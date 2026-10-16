package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	api "github.com/hadesshade/cert-manager-scep-issuer/api/v1alpha1"
)

const (
	// raRejectedForAnnotation is set on the pending-enrollment Secret when the CA
	// rejected the request. Its value fingerprints the RA configuration and the
	// challenge password the request was made with, so a rejected request is only
	// repeated once one of them has changed.
	raRejectedForAnnotation = "scep.hshade.io/ra-rejected-for"
	// raRejectedReasonAnnotation keeps what the CA answered, for the error message.
	raRejectedReasonAnnotation = "scep.hshade.io/ra-rejected-reason"

	// The SCEP client words a non-2xx answer as
	// "http request failed with status <status line>, msg: <body>".
	httpFailurePrefix = "http request failed with status "
	httpBodyMarker    = ", msg: "
)

// raRejection is returned when the CA answers an RA enrollment with FAILURE.
type raRejection struct{ reason string }

func (r raRejection) Error() string { return "RA bootstrap enrollment FAILED: " + r.reason }

// raRejectionFingerprint identifies what an enrollment was requested with: the RA
// identity configuration and the challenge password. It is a SHA-256 of both, so the
// password itself is not stored.
func raRejectionFingerprint(cfg *api.DelegatedSignerConfiguration, challengePassword string) string {
	sum := sha256.Sum256([]byte(raConfigHash(cfg) + "\x00" + challengePassword))
	return hex.EncodeToString(sum[:])
}

type raRejectedErr struct{ reason, hint string }

func (e raRejectedErr) Error() string {
	return fmt.Sprintf("RA bootstrap enrollment was rejected by the CA (%s). Not retried until the RA configuration or challenge password changes; after fixing, trigger a reconcile with: %s", e.reason, e.hint)
}

// reconcileHint returns the kubectl command that re-triggers this Issuer or
// ClusterIssuer, derived from the owner annotations SavePendingSecret sets.
func reconcileHint(pending *corev1.Secret) string {
	const tail = `scep.hshade.io/reconcile="$(date)" --overwrite`
	a := pending.Annotations
	if name := a["scep.hshade.io/clusterissuer-name"]; name != "" {
		return fmt.Sprintf("kubectl annotate clusterissuer.scep.hshade.io %s %s", name, tail)
	}
	if name := a["scep.hshade.io/issuer-name"]; name != "" {
		return fmt.Sprintf("kubectl annotate issuer.scep.hshade.io -n %s %s %s", a["scep.hshade.io/issuer-namespace"], name, tail)
	}
	return "kubectl annotate issuer.scep.hshade.io -n <namespace> <name> " + tail
}

func raRejectedError(pending *corev1.Secret, reason string) error {
	return raRejectedErr{reason: reason, hint: reconcileHint(pending)}
}

type raRejectionState int

const (
	// raNotRejected: the pending enrollment has not been rejected by the CA.
	raNotRejected raRejectionState = iota
	// raRejectedUnchanged: rejected, and neither the configuration nor the
	// challenge password changed since. The CA must not be contacted again.
	raRejectedUnchanged
	// raRejectedChanged: rejected, but the configuration or the challenge password
	// changed since, so a new enrollment is worth trying.
	raRejectedChanged
)

func raRejectionStateOf(pending *corev1.Secret, cfg *api.DelegatedSignerConfiguration, challengePassword string) raRejectionState {
	rejectedFor, ok := pending.Annotations[raRejectedForAnnotation]
	switch {
	case !ok:
		return raNotRejected
	case rejectedFor == raRejectionFingerprint(cfg, challengePassword):
		return raRejectedUnchanged
	default:
		return raRejectedChanged
	}
}

// rejectEnrollment records that the CA rejected the pending enrollment, by marking
// the pending Secret, and returns the permanent error to report. The Secret is kept
// instead of deleted: deleting it made the next attempt start over with a new key,
// transaction ID and CA request, on every retry. If the marker cannot be written the
// pending Secret is dropped as before.
func (o *Issuer) rejectEnrollment(ctx context.Context, pending *corev1.Secret, cfg *api.DelegatedSignerConfiguration, challengePassword, reason string) error {
	nn := types.NamespacedName{Namespace: pending.Namespace, Name: pending.Name}

	mark := func(secret *corev1.Secret) error {
		updated := secret.DeepCopy()
		if updated.Annotations == nil {
			updated.Annotations = map[string]string{}
		}
		updated.Annotations[raRejectedForAnnotation] = raRejectionFingerprint(cfg, challengePassword)
		updated.Annotations[raRejectedReasonAnnotation] = reason
		return o.client.Update(ctx, updated)
	}

	err := mark(pending)
	if apierrors.IsConflict(err) {
		// The Secret changed since it was read, or the read came from a stale cache.
		var latest corev1.Secret
		if err = o.client.Get(ctx, nn, &latest); err == nil {
			err = mark(&latest)
		}
	}
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to record the CA rejection; dropping the pending enrollment instead", "secret", nn.String())
		o.DeletePendingSecret(ctx, nn)
	} else {
		ctrl.LoggerFrom(ctx).Error(raRejection{reason: reason}, "the CA rejected the RA enrollment; it is not retried until the RA configuration or the challenge password changes", "secret", nn.String())
	}
	return raRejectedError(pending, reason)
}

// httpRejection reports whether err is the SCEP client's error for an HTTP 400, 401
// or 403 answer, which is how some CAs refuse a request. OpenXPKI answers a request
// without a valid challenge password this way, with HTTP 400 and no SCEP CertRep, so
// it never reaches the PKIStatus FAILURE handling. It returns the status line.
func httpRejection(err error) (string, bool) {
	msg := sanitizeError(err)
	i := strings.Index(msg, httpFailurePrefix)
	if i < 0 {
		return "", false
	}
	statusLine, _, _ := strings.Cut(msg[i+len(httpFailurePrefix):], httpBodyMarker)
	for _, code := range []string{"400", "401", "403"} {
		if strings.HasPrefix(statusLine, code) {
			return statusLine, true
		}
	}
	return "", false
}
