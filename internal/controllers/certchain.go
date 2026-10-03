package controllers

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// maxChainDepth bounds the issuer walk in EncodeCertChainPEM so that a pool
// containing a signing loop cannot spin forever.
const maxChainDepth = 10

// EncodeCertChainPEM PEM-encodes leaf followed by its issuer chain, built from pool.
//
// Only certificates that really issued the previous certificate in the chain
// (valid signature, and a CA according to their basic constraints) are added.
// Unrelated entries in pool, most notably an RA certificate, which SCEP servers
// often return from GetCACert next to the CA certificate, never end up in the
// result. That filter matters because cert-manager rejects a bundle that is not a
// single linear chain.
//
// If no issuer can be linked (for example because the CA chain is signed with
// SHA-1, which x509.Certificate.CheckSignatureFrom rejects) the result is just the
// leaf, which is what this issuer returned before chains were supported.
func EncodeCertChainPEM(leaf *x509.Certificate, pool []*x509.Certificate) []byte {
	out := EncodeCertPEM(leaf)

	seen := map[string]struct{}{string(leaf.Raw): {}}
	current := leaf
	for depth := 0; depth < maxChainDepth; depth++ {
		var issuer *x509.Certificate
		for _, candidate := range pool {
			if candidate == nil {
				continue
			}
			if _, dup := seen[string(candidate.Raw)]; dup {
				continue
			}
			if current.CheckSignatureFrom(candidate) == nil {
				issuer = candidate
				break
			}
		}
		if issuer == nil {
			break
		}
		seen[string(issuer.Raw)] = struct{}{}
		out = append(out, EncodeCertPEM(issuer)...)
		current = issuer
	}
	return out
}

// SCEP response helpers

// certRepCerts returns every certificate carried in a successful CertRep.
// scep.PKIMessage.DecryptPKIEnvelope keeps only the first one in msg.Certificate
// and discards the rest of the chain, so the envelope is decrypted again here.
// It returns nil on any error; callers then fall back to msg.Certificate alone.
func certRepCerts(msg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey) []*x509.Certificate {
	outer, err := pkcs7.Parse(msg.Raw)
	if err != nil {
		return nil
	}
	envelope, err := pkcs7.Parse(outer.Content)
	if err != nil {
		return nil
	}
	degenerate, err := envelope.Decrypt(cert, key)
	if err != nil {
		return nil
	}
	certs, err := scep.CACerts(degenerate)
	if err != nil {
		return nil
	}
	return certs
}

// CertRepPEM builds the PEM returned to cert-manager from a CertRep that was
// already decrypted with DecryptPKIEnvelope using cert and key. It contains the
// issued certificate followed by its issuer chain, assembled from the certificates
// in the response and the CA certificates from GetCACert (caCerts). This is what
// lets cert-manager fill in ca.crt and any intermediates.
func CertRepPEM(msg *scep.PKIMessage, cert *x509.Certificate, key *rsa.PrivateKey, caCerts []*x509.Certificate) []byte {
	pool := make([]*x509.Certificate, 0, len(caCerts))
	pool = append(pool, caCerts...)
	pool = append(pool, certRepCerts(msg, cert, key)...)
	return EncodeCertChainPEM(msg.Certificate, pool)
}
