package controllers

import (
	"crypto/x509"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// defaultRARenewalWindow is how long before expiry an RA certificate is renewed
// when delegatedSignerConfiguration.renewalWindow is not set.
const defaultRARenewalWindow = 720 * time.Hour // 30 days

// raRenewalThreshold returns how long before expiry the RA certificate should be
// renewed. The configured window (or the default) is capped at a third of the
// certificate's own lifetime.
//
// Without the cap, a CA that issues RA certificates valid for less than the window
// (for example 7 days against the 30-day default) puts every new certificate inside
// the renewal window immediately. The controller would then re-enroll, with a new
// key and a new CA request, on every renewal pass instead of once per lifetime.
func raRenewalThreshold(cert *x509.Certificate, window *metav1.Duration) time.Duration {
	threshold := defaultRARenewalWindow
	if window != nil {
		threshold = window.Duration
	}
	if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime > 0 {
		if limit := lifetime / 3; threshold > limit {
			threshold = limit
		}
	}
	return threshold
}
