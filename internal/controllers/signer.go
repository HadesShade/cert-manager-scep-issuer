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
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	httptransport "github.com/go-kit/kit/transport/http"
	api "github.com/hadesshade/cert-manager-scep-issuer/api/v1alpha1"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/micromdm/scep/v2/cryptoutil/x509util"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	pendingSecretSuffix = "-pending"

	// Secrets created by this controller carry this label. The controller only
	// renews (overwrites) a signer Secret that has it, so it never clobbers a
	// Secret it did not create.
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "scep-issuer"

	// raRenewalInterval is how often the background loop re-checks the RA signer
	// certificate of every Delegated issuer. raRenewalAttemptTimeout bounds a
	// single attempt so a hung SCEP server cannot stall the loop.
	raRenewalInterval       = 10 * time.Minute
	raRenewalAttemptTimeout = 2 * time.Minute

	// maxErrorMessageLen bounds error text stored in status conditions.
	maxErrorMessageLen = 512
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
	errSecretNotManaged     = errors.New("signer secret exists but was not created by this controller")

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

	// signerLocks serializes RA bootstrap/renewal per signer Secret: both Check()
	// and the background renewal loop can run it. Values are 1-slot channels so
	// waiting for the lock can honour context cancellation.
	signerLocks sync.Map
}

// +kubebuilder:rbac:groups=scep.hshade.io,resources=clusterissuers;issuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=scep.hshade.io,resources=clusterissuers/status;issuers/status,verbs=patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=clusterissuers.scep.hshade.io/*;issuers.scep.hshade.io/*

func (s *Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	// issuer-lib only calls Check() when an issuer's spec changes or after an
	// error, never periodically, so a Ready issuer would never renew its RA
	// certificate on its own. This loop does it (leader only).
	if err := mgr.Add(manager.RunnableFunc(s.renewDelegatedSigners)); err != nil {
		return err
	}

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
		return signer.PEMBundle{}, fmt.Errorf("%w: %s", errSignerSign, sanitizeError(err))
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

	unlock, lockErr := o.lockSigner(ctx, nn)
	if lockErr != nil {
		return fmt.Errorf("failed to lock signer secret %s: %w", nn, lockErr)
	}
	defer unlock()

	var existing corev1.Secret
	exists := true
	if err := o.client.Get(ctx, nn, &existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to check for existing signer secret: %w", err)
		}
		exists = false
	}

	// hasValidCert: the Secret holds an RA certificate that has not expired yet.
	// While it does, a failed or pending renewal is only logged (see
	// tolerateRenewalError) so the issuer keeps signing with the current one.
	hasValidCert := false
	if exists {
		if cert, _, parseErr := ParseTLSPair(existing.Data[corev1.TLSCertKey], existing.Data[corev1.TLSPrivateKeyKey]); parseErr == nil {
			renewalThreshold := 720 * time.Hour // Default 30 days
			if cfg.RenewalWindow != nil {
				renewalThreshold = cfg.RenewalWindow.Duration
			}

			remaining := time.Until(cert.NotAfter)
			if remaining > renewalThreshold {
				return nil
			}
			hasValidCert = remaining > 0
		}

		// Never overwrite a Secret this controller did not create.
		if !isManagedSecret(&existing) {
			return tolerateRenewalError(ctx, nn, hasValidCert, fmt.Errorf(
				"%w: %s (add the label %s=%s to allow renewal, or delete the Secret)",
				errSecretNotManaged, nn, managedByLabelKey, managedByLabelValue))
		}
	}

	var challengePassword string
	if issuerSpec.ChallengeSecretRef != nil {
		passwordPtr, err := o.GetChallengePassword(ctx, issuerSpec, namespace)
		if err != nil {
			return tolerateRenewalError(ctx, nn, hasValidCert, fmt.Errorf("failed to read bootstrap challenge password: %w", err))
		}
		challengePassword = *passwordPtr
	}

	// Updated call passing the entire cfg object
	cert, key, err := o.BootstrapDelegatingSignerIdentity(ctx, issuerSpec, namespace, secretName, cfg, challengePassword)
	if err != nil {
		return tolerateRenewalError(ctx, nn, hasValidCert, err)
	}

	certPEM, keyPEM := EncodeCertPEM(cert), EncodeKeyPKCS8(key)

	// Build tracking annotations dynamically
	resourceName := secretName
	resourceName = strings.TrimSuffix(resourceName, "-delegated-signer")

	isClusterIssuer := false
	if namespace == o.ClusterResourceNamespace || namespace == "" {
		var checkIssuer api.Issuer
		checkErr := o.client.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, &checkIssuer)
		if checkErr != nil && apierrors.IsNotFound(checkErr) {
			isClusterIssuer = true
		}
	}

	annotations := map[string]string{}
	if isClusterIssuer {
		annotations["scep.hshade.io/clusterissuer-name"] = resourceName
	} else {
		annotations["scep.hshade.io/issuer-name"] = resourceName
		annotations["scep.hshade.io/issuer-namespace"] = namespace
	}

	if exists {
		// The initial o.client.Get above can be stale by the time we get here: the SCEP
		// round trip in between can take seconds, during which another writer could
		// have updated this Secret's ResourceVersion. A plain Update would then fail
		// with a conflict and strand the RA certificate we just obtained from the CA
		// (it exists only in memory at that point). RetryOnConflict re-fetches and
		// retries so a freshly issued certificate is not lost to a stale write.
		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			latest := &corev1.Secret{}
			if getErr := o.client.Get(ctx, nn, latest); getErr != nil {
				return getErr
			}

			// Re-check ownership against the latest object: it may have been replaced
			// by something else while we were bootstrapping.
			if !isManagedSecret(latest) {
				return fmt.Errorf("%w: %s (add the label %s=%s to allow renewal, or delete the Secret)",
					errSecretNotManaged, nn, managedByLabelKey, managedByLabelValue)
			}

			// Update a copy of the latest Secret so its labels, annotations, owner
			// references, finalizers and any extra keys are preserved.
			updated := latest.DeepCopy()
			if updated.Labels == nil {
				updated.Labels = map[string]string{}
			}
			updated.Labels[managedByLabelKey] = managedByLabelValue

			if updated.Annotations == nil {
				updated.Annotations = map[string]string{}
			}
			for k, v := range annotations {
				updated.Annotations[k] = v
			}

			if updated.Data == nil {
				updated.Data = map[string][]byte{}
			}
			updated.Data[corev1.TLSCertKey] = certPEM
			updated.Data[corev1.TLSPrivateKeyKey] = keyPEM

			return o.client.Update(ctx, updated)
		})
		if err != nil {
			return tolerateRenewalError(ctx, nn, hasValidCert, fmt.Errorf("failed to update expiring signer secret: %w", err))
		}
		return nil
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   namespace,
			Labels:      map[string]string{managedByLabelKey: managedByLabelValue},
			Annotations: annotations,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	if err := o.client.Create(ctx, newSecret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another reconcile (or replica) created it first; discard this enrollment
			// and keep whichever landed first rather than fighting over it.
			ctrl.LoggerFrom(ctx).Info("signer secret was created concurrently; discarding this RA enrollment", "secret", nn.String())
			return nil
		}
		return fmt.Errorf("failed to create signer secret: %w", err)
	}

	return nil
}

// sanitizeError renders err as a short, printable string that is safe to store in a
// status condition. When a SCEP server rejects a request it can answer with a binary
// DER PKIMessage as the HTTP error body, and the SCEP client appends that body to the
// error text. Control characters make the Kubernetes API reject the status patch
// ("yaml: control characters are not allowed"), which hides the real error and makes
// the reconcile fail and retry in a tight loop.
func sanitizeError(err error) string {
	if err == nil {
		return "no data returned"
	}
	msg := err.Error()

	// The client formats HTTP failures as "<status>, msg: <body>". Drop a body that
	// is not text; the status line already carries the reason.
	const bodyMarker = ", msg: "
	if i := strings.Index(msg, bodyMarker); i >= 0 && !isPrintableText(msg[i+len(bodyMarker):]) {
		msg = msg[:i+len(bodyMarker)] + "(binary response body omitted)"
	}

	msg = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case r == utf8.RuneError || !unicode.IsPrint(r):
			return -1
		default:
			return r
		}
	}, msg)

	if runes := []rune(msg); len(runes) > maxErrorMessageLen {
		msg = string(runes[:maxErrorMessageLen]) + "…"
	}
	return msg
}

func isPrintableText(s string) bool {
	for _, r := range s {
		if r == utf8.RuneError || (!unicode.IsPrint(r) && r != '\n' && r != '\t') {
			return false
		}
	}
	return true
}

func isManagedSecret(secret *corev1.Secret) bool {
	return secret.Labels[managedByLabelKey] == managedByLabelValue
}

// tolerateRenewalError turns a failed or pending RA renewal into a log line when a
// still-valid RA certificate exists, so the issuer stays Ready and keeps signing
// with it. Without a valid certificate (initial enrollment, or already expired) the
// error is returned so the issuer reports NotReady as before.
func tolerateRenewalError(ctx context.Context, nn types.NamespacedName, hasValidCert bool, err error) error {
	if !hasValidCert {
		return err
	}

	log := ctrl.LoggerFrom(ctx).WithValues("secret", nn.String())
	if errors.Is(err, errStillPending) {
		log.Info("RA signer renewal is awaiting approval; continuing with the current RA certificate")
	} else {
		log.Error(err, "RA signer renewal failed; continuing with the current RA certificate, will retry")
	}
	return nil
}

// lockSigner takes the per-Secret bootstrap/renewal lock, or fails if ctx ends first.
func (o *Issuer) lockSigner(ctx context.Context, nn types.NamespacedName) (func(), error) {
	v, _ := o.signerLocks.LoadOrStore(nn.String(), make(chan struct{}, 1))
	sem := v.(chan struct{})

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// renewDelegatedSigners periodically retries RA signer renewal (including polling a
// pending renewal) for every Delegated issuer that manages its own signer Secret.
func (o *Issuer) renewDelegatedSigners(ctx context.Context) error {
	ticker := time.NewTicker(raRenewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			o.renewAllDelegatedSigners(ctx)
		}
	}
}

func (o *Issuer) renewAllDelegatedSigners(ctx context.Context) {
	log := ctrl.LoggerFrom(ctx).WithName("ra-renewal")

	var issuers api.IssuerList
	if err := o.client.List(ctx, &issuers); err != nil {
		log.Error(err, "failed to list Issuers")
	} else {
		for i := range issuers.Items {
			o.renewDelegatedSigner(ctx, &issuers.Items[i])
		}
	}

	var clusterIssuers api.ClusterIssuerList
	if err := o.client.List(ctx, &clusterIssuers); err != nil {
		log.Error(err, "failed to list ClusterIssuers")
	} else {
		for i := range clusterIssuers.Items {
			o.renewDelegatedSigner(ctx, &clusterIssuers.Items[i])
		}
	}
}

func (o *Issuer) renewDelegatedSigner(ctx context.Context, issuerObject issuerapi.Issuer) {
	spec, namespace, err := o.GetIssuerDetails(issuerObject)
	if err != nil ||
		spec.EnrollmentMode != api.Delegated ||
		spec.DelegatedSignerConfiguration == nil ||
		spec.DelegatedSignerSecretName != nil {
		return
	}

	log := ctrl.LoggerFrom(ctx).WithName("ra-renewal").WithValues("issuer", issuerObject.GetName(), "namespace", namespace)
	secretName := delegatedSignerSecretName(issuerObject)

	// Renewal only: the initial enrollment is driven by Check(), which has its own
	// retry/backoff and reports failures in the issuer status.
	var existing corev1.Secret
	if err := o.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &existing); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to look up RA signer secret")
		}
		return
	}

	attemptCtx, cancel := context.WithTimeout(ctx, raRenewalAttemptTimeout)
	defer cancel()

	if err := o.EnsureDelegatingSignerSecret(attemptCtx, spec, spec.DelegatedSignerConfiguration, namespace, secretName); err != nil {
		log.Error(err, "RA signer renewal failed")
	}
}

// Signature accept *api.DelegatedSignerConfiguration
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

// GetSCEPClient builds a SCEP client with its own *http.Client, rather than the
// package-level scepclient.New (which always uses http.DefaultClient). Mutating
// http.DefaultClient.Transport per-issuer, as this used to do, is a data race with
// concurrent reconciles, and one issuer with insecureSkipVerify would silently turn
// off TLS verification for every HTTP call in the whole process.
func GetSCEPClient(ctx context.Context, issuerSpec *api.IssuerSpec) (scepclient.Client, []*x509.Certificate, *x509.Certificate, error) {
	httpClient := &http.Client{Timeout: 60 * time.Second}
	if issuerSpec.InsecureSkipVerify {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = customTransport
	}

	instance := issuerSpec.URL
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	tgt, err := url.Parse(instance)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse SCEP URL: %w", err)
	}

	logger := level.Info(log.NewNopLogger())
	c := &scepserver.Endpoints{
		GetEndpoint: scepserver.EndpointLoggingMiddleware(logger)(
			httptransport.NewClient("GET", tgt, scepserver.EncodeSCEPRequest, scepserver.DecodeSCEPResponse,
				httptransport.SetClient(httpClient)).Endpoint()),
		PostEndpoint: scepserver.EndpointLoggingMiddleware(logger)(
			httptransport.NewClient("POST", tgt, scepserver.EncodeSCEPRequest, scepserver.DecodeSCEPResponse,
				httptransport.SetClient(httpClient)).Endpoint()),
	}

	caCertBytes, _, err := c.GetCACert(ctx, "")
	if err != nil || len(caCertBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("failed to get CA certs: %s", sanitizeError(err))
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

	// Unlike leaf CSRs (which cert-manager generates and signs itself), the RA
	// bootstrap CSR is created here, so we hold its private key and can embed the
	// PKCS#9 challengePassword attribute (RFC 2985, OID 1.2.840.113549.1.9.7)
	// before signing. The standard library's x509.CreateCertificateRequest cannot
	// emit this attribute, so x509util (which re-signs the CSR after adding it) is
	// used instead. An empty challengePassword yields a plain stdlib CSR.
	csrTemplate := &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:  subject,
			DNSNames: cfg.DNSNames,
		},
		ChallengePassword: challengePassword,
	}

	csrDER, err := x509util.CreateCertificateRequest(rand.Reader, csrTemplate, raKey)
	if err != nil {
		return nil, nil, err
	}
	raCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}

	bootstrapTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
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

	// Persist the RA bootstrap identity (key, self-signed cert, transaction ID) before
	// contacting the SCEP server, not only on a PENDING response as before. If the
	// PKIOperation call succeeds but the controller crashes or is killed before the
	// caller can write the signer Secret, the enrollment would otherwise be lost with
	// no way to recover it: the CA has already issued a certificate for a raKey that
	// no longer exists anywhere. With the pending Secret saved first, the next
	// reconcile finds it and calls PollPendingRAEnrollment, which can retrieve the
	// already-issued certificate from the CA using the same transaction ID, instead of
	// silently starting a brand new enrollment.
	if err := o.SavePendingSecret(ctx, pendingName, bootstrapCert, raKey, transactionID); err != nil {
		return nil, nil, fmt.Errorf("failed to save pending enrollment state: %w", err)
	}

	scepResponseBytes, err := scepClient.PKIOperation(ctx, rawPKIMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("PKIOperation failed: %s", sanitizeError(err))
	}
	scepResponseMessage, err := scep.ParsePKIMessage(scepResponseBytes, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SCEP response: %w", err)
	}

	switch scepResponseMessage.PKIStatus {
	case scep.FAILURE:
		o.DeletePendingSecret(ctx, pendingName)
		return nil, nil, fmt.Errorf("RA bootstrap enrollment FAILED: %s", scepResponseMessage.FailInfo)
	case scep.PENDING:
		// Already persisted above; nothing more to save.
		return nil, nil, errStillPending
	}

	if err := scepResponseMessage.DecryptPKIEnvelope(bootstrapCert, raKey); err != nil {
		return nil, nil, err
	}
	o.DeletePendingSecret(ctx, pendingName)
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
		return nil, nil, fmt.Errorf("PKIOperation (poll) failed: %s", sanitizeError(err))
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
	resourceName := name.Name
	resourceName = strings.TrimSuffix(resourceName, "-pending")
	resourceName = strings.TrimSuffix(resourceName, "-delegated-signer")

	isClusterIssuer := false
	if name.Namespace == o.ClusterResourceNamespace || name.Namespace == "" {
		var checkIssuer api.Issuer
		checkErr := o.client.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: name.Namespace}, &checkIssuer)
		if checkErr != nil && apierrors.IsNotFound(checkErr) {
			isClusterIssuer = true
		}
	}

	annotations := map[string]string{}
	if isClusterIssuer {
		annotations["scep.hshade.io/clusterissuer-name"] = resourceName
	} else {
		annotations["scep.hshade.io/issuer-name"] = resourceName
		annotations["scep.hshade.io/issuer-namespace"] = name.Namespace
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name.Name,
			Namespace:   name.Namespace,
			Labels:      map[string]string{managedByLabelKey: managedByLabelValue},
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
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
