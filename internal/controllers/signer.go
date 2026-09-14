/*
Copyright 2023 The cert-manager Authors.
Licensed under the Apache License, Version 2.0 (the "License");
*/

package controllers

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/go-kit/kit/log"
	api "github.com/hadesshade/cert-manager-scep-issuer/api/v1alpha1"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	pendingSecretSuffix = "-pending"
)

var (
	errConfigurationError   = errors.New("invalid issuer/clusterissuer configuration")
	errGetChallengeSecret   = errors.New("failed to get Secret containing Issuer credentials")
	errGetSignerSecret      = errors.New("failed to get Secret containing Delegating Signer TLS")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
	errSignerBuilder        = errors.New("failed to build the signer")
	errSignerSign           = errors.New("failed to sign")
	errStillPending         = errors.New("AWAITING APPROVAL: RA bootstrap enrollment is pending manual approval")

	OidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	OidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	OidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(*api.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(ctx context.Context, csr []byte) ([]byte, error)
}

type SignerBuilder func(*api.IssuerSpec, map[string][]byte) (Signer, error)

type Issuer struct {
	HealthCheckerBuilder     HealthCheckerBuilder
	SignerBuilder            SignerBuilder
	ClusterResourceNamespace string

	client client.Client
}

// +kubebuilder:rbac:groups=scep.hshade.io,resources=clusterissuers;issuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=scep.hshade.io,resources=clusterissuers/status;issuers/status,verbs=patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=clusterissuers.scep.hshade.io/*;issuers.scep.hshade.io/*

func (s *Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&api.Issuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&api.ClusterIssuer{}},

		FieldOwner:       "issuer.cert-manager.io",
		MaxRetryDuration: 168 * time.Hour,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorder("issuer.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

func (o *Issuer) GetIssuerDetails(issuerObject issuerapi.Issuer) (*api.IssuerSpec, string, error) {
	switch t := issuerObject.(type) {
	case *api.Issuer:
		return &t.Spec, issuerObject.GetNamespace(), nil
	case *api.ClusterIssuer:
		return &t.Spec, o.ClusterResourceNamespace, nil
	default:
		return nil, "", signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %T", issuerObject),
		}
	}
}

func delegatedSignerSecretName(issuerObject issuerapi.Issuer) string {
	return fmt.Sprintf("%s-delegated-signer", issuerObject.GetName())
}

func DelegatedSignerSecretName(issuerObject issuerapi.Issuer) string {
	return delegatedSignerSecretName(issuerObject)
}

func (o *Issuer) GetDelegatingSignerSecretData(ctx context.Context, secretNameStr string, namespace string, issuerSpec *api.IssuerSpec) (map[string][]byte, error) {
	secretName := types.NamespacedName{Namespace: namespace, Name: secretNameStr}

	var secret corev1.Secret
	if err := o.client.Get(ctx, secretName, &secret); err != nil {
		return nil, fmt.Errorf("%w, secret name: %s, reason: %v", errGetSignerSecret, secretName, err)
	}
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("%w, secret name: %s, reason: %v", errGetSignerSecret, secretName, "Delegating signer secret is not in TLS type")
	}

	checker, err := o.HealthCheckerBuilder(issuerSpec, secret.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHealthCheckerBuilder, err)
	}
	if err := checker.Check(); err != nil {
		return nil, fmt.Errorf("%w: %v", errHealthCheckerCheck, err)
	}
	return secret.Data, nil
}

func (o *Issuer) GetChallengePassword(ctx context.Context, issuerSpec *api.IssuerSpec, namespace string) (*string, error) {
	secretName := types.NamespacedName{Namespace: namespace, Name: issuerSpec.ChallengeSecretRef.Name}

	var secret corev1.Secret
	if err := o.client.Get(ctx, secretName, &secret); err != nil {
		return nil, fmt.Errorf("%w, secret name: %s, reason: %v", errGetChallengeSecret, secretName, err)
	}

	challengePassword, ok := secret.Data[issuerSpec.ChallengeSecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("%w, secret name: %s, reason: missing key %q", errGetChallengeSecret, secretName, issuerSpec.ChallengeSecretRef.Key)
	}
	if len(challengePassword) == 0 {
		return nil, fmt.Errorf("%w: secret %s: key %q is empty", errGetChallengeSecret, secretName, issuerSpec.ChallengeSecretRef.Key)
	}

	s := string(challengePassword)
	return &s, nil
}

func (o *Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	issuerSpec, namespace, err := o.GetIssuerDetails(issuerObject)
	if err != nil {
		return err
	}

	if issuerSpec.EnrollmentMode == api.Direct && issuerSpec.ChallengeSecretRef != nil {
		return signer.PermanentError{Err: fmt.Errorf("%w: challengeSecretRef has no effect in Direct enrollment mode - SCEP challenge passwords must be embedded in the CSR itself, which requires the CSR's private key; cert-manager never gives the issuer that key. Use Delegated mode if the SCEP server requires per-request authentication", errConfigurationError)}
	}

	if issuerSpec.ChallengeSecretRef != nil {
		if _, err := o.GetChallengePassword(ctx, issuerSpec, namespace); err != nil {
			return err
		}
	}

	switch issuerSpec.EnrollmentMode {
	case api.Direct:
		return nil
	case api.Delegated:
		switch {
		case issuerSpec.DelegatedSignerSecretName != nil && issuerSpec.DelegatedSignerConfiguration != nil:
			return signer.PermanentError{Err: fmt.Errorf("%w: only one of delegatedSignerSecretName or delegatedSignerConfiguration may be set", errConfigurationError)}

		case issuerSpec.DelegatedSignerSecretName != nil:
			_, err := o.GetDelegatingSignerSecretData(ctx, *issuerSpec.DelegatedSignerSecretName, namespace, issuerSpec)
			return err

		case issuerSpec.DelegatedSignerConfiguration != nil:
			secretName := delegatedSignerSecretName(issuerObject)
			if err := o.EnsureDelegatingSignerSecret(ctx, issuerSpec, issuerSpec.DelegatedSignerConfiguration, namespace, secretName); err != nil {
				return err
			}
			_, err := o.GetDelegatingSignerSecretData(ctx, secretName, namespace, issuerSpec)
			return err

		default:
			return signer.PermanentError{Err: fmt.Errorf("%w: enrollmentMode Delegated requires delegatedSignerSecretName or delegatedSignerConfiguration", errConfigurationError)}
		}
	default:
		return signer.PermanentError{Err: fmt.Errorf("%w: unknown enrollmentMode %q", errConfigurationError, issuerSpec.EnrollmentMode)}
	}
}

func (o *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, namespace, err := o.GetIssuerDetails(issuerObject)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	secretData, err := o.ResolveSignerSecretData(ctx, issuerSpec, issuerObject, namespace)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	certDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, err
	}

	signerObj, err := o.SignerBuilder(issuerSpec, secretData)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	signed, err := signerObj.Sign(ctx, certDetails.CSR)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}

	bundle, err := pki.ParseSingleCertificateChainPEM(signed)
	if err != nil {
		return signer.PEMBundle{}, err
	}

	return signer.PEMBundle(bundle), nil
}

func (o *Issuer) ResolveSignerSecretData(ctx context.Context, issuerSpec *api.IssuerSpec, issuerObject issuerapi.Issuer, namespace string) (map[string][]byte, error) {
	switch issuerSpec.EnrollmentMode {
	case api.Direct:
		return map[string][]byte{}, nil

	case api.Delegated:
		var secretName string
		switch {
		case issuerSpec.DelegatedSignerSecretName != nil:
			secretName = *issuerSpec.DelegatedSignerSecretName
		case issuerSpec.DelegatedSignerConfiguration != nil:
			secretName = delegatedSignerSecretName(issuerObject)
		default:
			return nil, fmt.Errorf("%w: enrollmentMode Delegated requires delegatedSignerSecretName or delegatedSignerConfiguration", errConfigurationError)
		}
		return o.GetDelegatingSignerSecretData(ctx, secretName, namespace, issuerSpec)

	default:
		return nil, fmt.Errorf("%w: unknown enrollmentMode %q", errConfigurationError, issuerSpec.EnrollmentMode)
	}
}

func (o *Issuer) EnsureDelegatingSignerSecret(ctx context.Context, issuerSpec *api.IssuerSpec, cfg *api.DelegatedSignerConfiguration, namespace, secretName string) error {
	nn := types.NamespacedName{Namespace: namespace, Name: secretName}
	needsUpdate := false

	var secret corev1.Secret
	err := o.client.Get(ctx, nn, &secret)
	if err == nil {
		cert, _, parseErr := ParseTLSPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
		if parseErr == nil {
			renewalThreshold := 720 * time.Hour // Default 30 days
			if cfg.RenewalWindow != nil {
				renewalThreshold = cfg.RenewalWindow.Duration
			}

			if time.Until(cert.NotAfter) > renewalThreshold {
				return nil
			}
		}
		needsUpdate = true
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to check for existing signer secret: %w", err)
	}

	var challengePassword string
	if issuerSpec.ChallengeSecretRef != nil {
		passwordPtr, err := o.GetChallengePassword(ctx, issuerSpec, namespace)
		if err != nil {
			return fmt.Errorf("failed to read bootstrap challenge password: %w", err)
		}
		challengePassword = *passwordPtr
	}

	// Updated call passing the entire cfg object
	cert, key, err := o.BootstrapDelegatingSignerIdentity(ctx, issuerSpec, namespace, secretName, cfg, challengePassword)
	if err != nil {
		return err
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       EncodeCertPEM(cert),
			corev1.TLSPrivateKeyKey: EncodeKeyPKCS8(key),
		},
	}

	if needsUpdate {
		newSecret.ResourceVersion = secret.ResourceVersion
		if err := o.client.Update(ctx, newSecret); err != nil {
			return fmt.Errorf("failed to update expiring signer secret: %w", err)
		}
	} else {
		if err := o.client.Create(ctx, newSecret); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return fmt.Errorf("failed to create signer secret: %w", err)
		}
	}

	return nil
}

// Signature updated to accept *api.DelegatedSignerConfiguration
func (o *Issuer) BootstrapDelegatingSignerIdentity(ctx context.Context, issuerSpec *api.IssuerSpec, namespace, secretName string, cfg *api.DelegatedSignerConfiguration, challengePassword string) (*x509.Certificate, *rsa.PrivateKey, error) {
	scepClient, caCerts, caCert, err := GetSCEPClient(ctx, issuerSpec)
	if err != nil {
		return nil, nil, err
	}

	pendingName := types.NamespacedName{Namespace: namespace, Name: secretName + pendingSecretSuffix}

	var pendingSecret corev1.Secret
	err = o.client.Get(ctx, pendingName, &pendingSecret)
	switch {
	case err == nil:
		bootstrapCert, raKey, txID, perr := ParsePendingSecret(pendingSecret)
		if perr != nil {
			return nil, nil, perr
		}
		return o.PollPendingRAEnrollment(ctx, scepClient, caCerts, caCert, bootstrapCert, raKey, txID, pendingName)

	case apierrors.IsNotFound(err):
		return o.StartNewRABootstrap(ctx, scepClient, caCerts, caCert, cfg, challengePassword, pendingName)

	default:
		return nil, nil, fmt.Errorf("failed to check for pending enrollment secret: %w", err)
	}
}

func GetSCEPClient(ctx context.Context, issuerSpec *api.IssuerSpec) (scepclient.Client, []*x509.Certificate, *x509.Certificate, error) {
	if issuerSpec.InsecureSkipVerify {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		http.DefaultClient.Transport = customTransport
	} else {
		http.DefaultClient.Transport = http.DefaultTransport
	}

	c, err := scepclient.New(issuerSpec.URL, log.NewNopLogger())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SCEP client: %w", err)
	}

	caCertBytes, _, err := c.GetCACert(ctx, "")
	if err != nil || len(caCertBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("failed to get CA certs: %w", err)
	}

	caCerts, err := scep.CACerts(caCertBytes)
	if err != nil {
		singleCert, perr := x509.ParseCertificate(caCertBytes)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse CA certs: %v (fallback: %v)", err, perr)
		}
		caCerts = []*x509.Certificate{singleCert}
	}
	return c, caCerts, caCerts[0], nil
}

// Signature updated to accept *api.DelegatedSignerConfiguration and map Subject/DNS fields
func (o *Issuer) StartNewRABootstrap(ctx context.Context, scepClient scepclient.Client, caCerts []*x509.Certificate, caCert *x509.Certificate, cfg *api.DelegatedSignerConfiguration, challengePassword string, pendingName types.NamespacedName) (*x509.Certificate, *rsa.PrivateKey, error) {
	raKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{CommonName: cfg.CommonName}
	if cfg.Subject != nil {
		subject.Organization = cfg.Subject.Organizations
		subject.Country = cfg.Subject.Countries
		subject.OrganizationalUnit = cfg.Subject.OrganizationalUnits
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: cfg.DNSNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, raKey)
	if err != nil {
		return nil, nil, err
	}
	raCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}

	bootstrapTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      csrTemplate.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	bootstrapCertDER, err := x509.CreateCertificate(rand.Reader, bootstrapTemplate, bootstrapTemplate, &raKey.PublicKey, raKey)
	if err != nil {
		return nil, nil, err
	}
	bootstrapCert, err := x509.ParseCertificate(bootstrapCertDER)
	if err != nil {
		return nil, nil, err
	}

	rawPKIMessage, transactionID, err := BuildSignedPKIMessage(raCSR.Raw, caCert, bootstrapCert, raKey)
	if err != nil {
		return nil, nil, err
	}

	scepResponseBytes, err := scepClient.PKIOperation(ctx, rawPKIMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("PKIOperation failed: %w", err)
	}
	scepResponseMessage, err := scep.ParsePKIMessage(scepResponseBytes, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SCEP response: %w", err)
	}

	switch scepResponseMessage.PKIStatus {
	case scep.FAILURE:
		return nil, nil, fmt.Errorf("RA bootstrap enrollment FAILED: %s", scepResponseMessage.FailInfo)
	case scep.PENDING:
		if err := o.SavePendingSecret(ctx, pendingName, bootstrapCert, raKey, transactionID); err != nil {
			return nil, nil, fmt.Errorf("failed to save pending enrollment state: %w", err)
		}
		return nil, nil, errStillPending
	}

	if err := scepResponseMessage.DecryptPKIEnvelope(bootstrapCert, raKey); err != nil {
		return nil, nil, err
	}
	return scepResponseMessage.Certificate, raKey, nil
}

func BuildSignedPKIMessage(csrRaw []byte, caCert, signerCert *x509.Certificate, signerKey *rsa.PrivateKey) ([]byte, scep.TransactionID, error) {
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse CSR: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, "", err
	}
	txSum := md5.Sum(pubKeyBytes)
	transactionID := scep.TransactionID(hex.EncodeToString(txSum[:]))

	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, "", err
	}

	envelopedData, err := pkcs7.Encrypt(csrRaw, []*x509.Certificate{caCert})
	if err != nil {
		return nil, "", fmt.Errorf("pkcs7 encrypt failed: %w", err)
	}
	signedData, err := pkcs7.NewSignedData(envelopedData)
	if err != nil {
		return nil, "", fmt.Errorf("pkcs7 new signed data failed: %w", err)
	}
	signerConfig := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: OidSCEPtransactionID, Value: transactionID},
			{Type: OidSCEPmessageType, Value: scep.PKCSReq},
			{Type: OidSCEPsenderNonce, Value: senderNonce},
		},
	}
	if err := signedData.AddSigner(signerCert, signerKey, signerConfig); err != nil {
		return nil, "", fmt.Errorf("pkcs7 add signer failed: %w", err)
	}

	msg, err := signedData.Finish()
	return msg, transactionID, err
}

func (o *Issuer) PollPendingRAEnrollment(ctx context.Context, scepClient scepclient.Client, caCerts []*x509.Certificate, caCert, bootstrapCert *x509.Certificate, raKey *rsa.PrivateKey, txID scep.TransactionID, pendingName types.NamespacedName) (*x509.Certificate, *rsa.PrivateKey, error) {
	rawPoll, err := BuildCertPollMessage(caCert, bootstrapCert, raKey, txID)
	if err != nil {
		return nil, nil, err
	}
	respBytes, err := scepClient.PKIOperation(ctx, rawPoll)
	if err != nil {
		return nil, nil, fmt.Errorf("PKIOperation (poll) failed: %w", err)
	}
	respMsg, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SCEP poll response: %w", err)
	}

	switch respMsg.PKIStatus {
	case scep.FAILURE:
		o.DeletePendingSecret(ctx, pendingName)
		return nil, nil, fmt.Errorf("RA bootstrap enrollment FAILED: %s", respMsg.FailInfo)
	case scep.PENDING:
		return nil, nil, errStillPending
	}

	if err := respMsg.DecryptPKIEnvelope(bootstrapCert, raKey); err != nil {
		return nil, nil, err
	}
	o.DeletePendingSecret(ctx, pendingName)
	return respMsg.Certificate, raKey, nil
}

func BuildCertPollMessage(caCert, signerCert *x509.Certificate, signerKey *rsa.PrivateKey, txID scep.TransactionID) ([]byte, error) {
	type issuerAndSubject struct {
		Issuer  asn1.RawValue
		Subject asn1.RawValue
	}
	ias := issuerAndSubject{
		Issuer:  asn1.RawValue{FullBytes: caCert.RawSubject},
		Subject: asn1.RawValue{FullBytes: signerCert.RawSubject},
	}
	iasDER, err := asn1.Marshal(ias)
	if err != nil {
		return nil, err
	}
	envelopedData, err := pkcs7.Encrypt(iasDER, []*x509.Certificate{caCert})
	if err != nil {
		return nil, err
	}
	signedData, err := pkcs7.NewSignedData(envelopedData)
	if err != nil {
		return nil, err
	}
	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, err
	}
	signerConfig := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: OidSCEPtransactionID, Value: txID},
			{Type: OidSCEPmessageType, Value: scep.CertPoll},
			{Type: OidSCEPsenderNonce, Value: senderNonce},
		},
	}
	if err := signedData.AddSigner(signerCert, signerKey, signerConfig); err != nil {
		return nil, err
	}
	return signedData.Finish()
}

func (o *Issuer) SavePendingSecret(ctx context.Context, name types.NamespacedName, bootstrapCert *x509.Certificate, raKey *rsa.PrivateKey, txID scep.TransactionID) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt":        EncodeCertPEM(bootstrapCert),
			"tls.key":        EncodeKeyPKCS8(raKey),
			"transaction-id": []byte(txID),
		},
	}
	if err := o.client.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func ParsePendingSecret(secret corev1.Secret) (*x509.Certificate, *rsa.PrivateKey, scep.TransactionID, error) {
	cert, key, err := ParseTLSPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid pending enrollment secret %s: %w", secret.Name, err)
	}
	return cert, key, scep.TransactionID(secret.Data["transaction-id"]), nil
}

func (o *Issuer) DeletePendingSecret(ctx context.Context, name types.NamespacedName) {
	_ = o.client.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace}})
}

func EncodeKeyPKCS8(key *rsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func ParseTLSPair(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("malformed TLS secret PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyParsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := keyParsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("signer key is not RSA")
	}
	return cert, key, nil
}
