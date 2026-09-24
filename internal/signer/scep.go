package signer

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	api "github.com/hadesshade/cert-manager-scep-issuer/api/v1alpha1"
	"github.com/hadesshade/cert-manager-scep-issuer/internal/controllers"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

type SCEPSigner struct {
	IssuerSpec *api.IssuerSpec
	SecretData map[string][]byte
}

func NewSCEPSignerBuilder() controllers.SignerBuilder {
	return func(issuerSpec *api.IssuerSpec, secretData map[string][]byte) (controllers.Signer, error) {
		return &SCEPSigner{IssuerSpec: issuerSpec, SecretData: secretData}, nil
	}
}

func (s *SCEPSigner) Sign(ctx context.Context, csr []byte) ([]byte, error) {
	// Decode the PEM-encoded CSR from cert-manager into raw DER bytes
	block, _ := pem.Decode(csr)
	if block != nil {
		csr = block.Bytes
	} else {
		return nil, fmt.Errorf("failed to decode PEM block from CertificateRequest")
	}

	// Proceed with standard SCEP signing using the raw bytes
	scepClient, caCerts, caCert, err := controllers.GetSCEPClient(ctx, s.IssuerSpec)
	if err != nil {
		return nil, err
	}

	if s.IssuerSpec.EnrollmentMode == api.Direct {
		return s.signDirect(ctx, scepClient, caCerts, caCert, csr)
	}
	return s.signDelegated(ctx, scepClient, caCerts, caCert, csr)
}

func (s *SCEPSigner) signDirect(ctx context.Context, scepClient scepclient.Client, caCerts []*x509.Certificate, caCert *x509.Certificate, csr []byte) ([]byte, error) {
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	ephemeralKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ephemeralTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      parsedCSR.Subject,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ephemeralCertDER, err := x509.CreateCertificate(rand.Reader, ephemeralTemplate, ephemeralTemplate, &ephemeralKey.PublicKey, ephemeralKey)
	if err != nil {
		return nil, err
	}
	ephemeralCert, err := x509.ParseCertificate(ephemeralCertDER)
	if err != nil {
		return nil, err
	}

	// Direct mode never carries a challenge password: SCEP validates it as a
	// PKCS#10 CSR attribute, which requires the CSR's private key to embed -
	// a key cert-manager never gives this issuer. Check() rejects
	// Direct + challengeSecretRef before Sign is ever reached.
	rawPKIMessage, err := buildDirectPKIMessage(csr, caCert, ephemeralCert, ephemeralKey)
	if err != nil {
		return nil, err
	}

	respBytes, err := scepClient.PKIOperation(ctx, rawPKIMessage)
	if err != nil {
		return nil, fmt.Errorf("PKIOperation failed: %w", err)
	}
	respMsg, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, err
	}

	switch respMsg.PKIStatus {
	case scep.FAILURE:
		// A CA-side rejection (e.g. "not in authorized signer list") will not
		// succeed on retry with the same request, and some SCEP servers reuse the
		// same failed enrollment state for repeat requests with the same
		// transaction ID. Report it as permanent so issuer-lib stops retrying this
		// CertificateRequest instead of backing off on it for up to
		// MaxRetryDuration.
		//
		// cert-manager's Certificate controller will retry roughly 1h, 2h, 4h...
		// capped at 32h. On first issuance (no existing Secret) that retry uses a
		// fresh private key, so it also gets a fresh SCEP transaction ID. On
		// renewal, with the default privateKey.rotationPolicy: Never, the key is
		// reused, so the retry keeps the same transaction ID and may hit the same
		// cached rejection again - use rotationPolicy: Always if that matters for
		// this issuer. Either way, this only controls how fast a doomed attempt
		// is recognized; the underlying CA rejection still needs a config fix.
		return nil, signer.PermanentError{Err: fmt.Errorf("CA rejected direct enrollment: %s", respMsg.FailInfo)}
	case scep.PENDING:
		return nil, fmt.Errorf("direct enrollment is PENDING. Polling direct ephemeral requests is currently unsupported")
	}

	if err := respMsg.DecryptPKIEnvelope(ephemeralCert, ephemeralKey); err != nil {
		return nil, fmt.Errorf("failed to decrypt CA response: %w", err)
	}

	return controllers.EncodeCertPEM(respMsg.Certificate), nil
}

func (s *SCEPSigner) signDelegated(ctx context.Context, scepClient scepclient.Client, caCerts []*x509.Certificate, caCert *x509.Certificate, csr []byte) ([]byte, error) {
	signerCert, signerKey, err := controllers.ParseTLSPair(s.SecretData["tls.crt"], s.SecretData["tls.key"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse delegating signer identity: %w", err)
	}

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(parsedCSR.PublicKey)
	if err != nil {
		return nil, err
	}
	txSum := md5.Sum(pubKeyBytes)
	txID := scep.TransactionID(hex.EncodeToString(txSum[:]))

	pollMsg, err := controllers.BuildCertPollMessage(caCert, signerCert, signerKey, txID)
	if err == nil {
		pollRespBytes, err := scepClient.PKIOperation(ctx, pollMsg)
		if err == nil {
			pollRespMsg, err := scep.ParsePKIMessage(pollRespBytes, scep.WithCACerts(caCerts))
			if err == nil {
				switch pollRespMsg.PKIStatus {
				case scep.SUCCESS:
					if err := pollRespMsg.DecryptPKIEnvelope(signerCert, signerKey); err != nil {
						return nil, fmt.Errorf("failed to decrypt polled CA response: %w", err)
					}
					return controllers.EncodeCertPEM(pollRespMsg.Certificate), nil
				case scep.PENDING:
					return nil, fmt.Errorf("enrollment still pending CA approval")
				}
			}
		}
	}

	rawPKIMessage, _, err := controllers.BuildSignedPKIMessage(csr, caCert, signerCert, signerKey)
	if err != nil {
		return nil, err
	}

	respBytes, err := scepClient.PKIOperation(ctx, rawPKIMessage)
	if err != nil {
		return nil, fmt.Errorf("PKIOperation failed: %w", err)
	}
	respMsg, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, err
	}

	switch respMsg.PKIStatus {
	case scep.FAILURE:
		// See the matching comment in signDirect: a CA-side rejection is permanent.
		return nil, signer.PermanentError{Err: fmt.Errorf("CA rejected delegated enrollment: %s", respMsg.FailInfo)}
	case scep.PENDING:
		return nil, fmt.Errorf("enrollment pending CA approval")
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, signerKey); err != nil {
		return nil, fmt.Errorf("failed to decrypt CA response: %w", err)
	}

	return controllers.EncodeCertPEM(respMsg.Certificate), nil
}

func buildDirectPKIMessage(csrRaw []byte, caCert, signerCert *x509.Certificate, signerKey *rsa.PrivateKey) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	txSum := md5.Sum(pubKeyBytes)
	transactionID := scep.TransactionID(hex.EncodeToString(txSum[:]))

	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		return nil, err
	}

	envelopedData, err := pkcs7.Encrypt(csrRaw, []*x509.Certificate{caCert})
	if err != nil {
		return nil, fmt.Errorf("pkcs7 encrypt failed: %w", err)
	}
	signedData, err := pkcs7.NewSignedData(envelopedData)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 new signed data failed: %w", err)
	}

	signerConfig := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: controllers.OidSCEPtransactionID, Value: transactionID},
			{Type: controllers.OidSCEPmessageType, Value: scep.PKCSReq},
			{Type: controllers.OidSCEPsenderNonce, Value: senderNonce},
		},
	}
	if err := signedData.AddSigner(signerCert, signerKey, signerConfig); err != nil {
		return nil, fmt.Errorf("pkcs7 add signer failed: %w", err)
	}
	return signedData.Finish()
}
