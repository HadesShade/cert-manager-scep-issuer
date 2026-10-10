package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"

	api "github.com/hadesshade/cert-manager-scep-issuer/api/v1alpha1"
)

// raConfigHashAnnotation records, on the RA signer Secret and on the pending
// enrollment Secret, a fingerprint of the delegatedSignerConfiguration fields the
// RA certificate was requested with. It is how the controller notices that the
// Issuer was edited after the RA certificate was issued.
const raConfigHashAnnotation = "scep.hshade.io/ra-config-hash"

// raConfigHash fingerprints the delegatedSignerConfiguration fields that end up in
// the RA certificate request: commonName, dnsNames and the subject lists.
//
// duration and renewalWindow are deliberately left out. duration is not used
// when requesting the certificate, and renewalWindow only decides when to renew,
// so changing either must not trigger a new enrollment. Lists are sorted so that
// reordering them is not a change.
func raConfigHash(cfg *api.DelegatedSignerConfiguration) string {
	sorted := func(in []string) []string {
		out := append([]string{}, in...)
		sort.Strings(out)
		return out
	}
	canonical := struct {
		Version             int
		CommonName          string
		DNSNames            []string
		Organizations       []string
		Countries           []string
		OrganizationalUnits []string
	}{Version: 1, CommonName: cfg.CommonName, DNSNames: sorted(cfg.DNSNames)}
	if cfg.Subject != nil {
		canonical.Organizations = sorted(cfg.Subject.Organizations)
		canonical.Countries = sorted(cfg.Subject.Countries)
		canonical.OrganizationalUnits = sorted(cfg.Subject.OrganizationalUnits)
	} else {
		canonical.Organizations, canonical.Countries, canonical.OrganizationalUnits = []string{}, []string{}, []string{}
	}
	// Marshalling this struct cannot fail.
	data, _ := json.Marshal(canonical)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type raConfigState int

const (
	// raConfigInSync: nothing to do. This includes a Secret this controller did
	// not create, which it must not re-enroll.
	raConfigInSync raConfigState = iota
	// raConfigUnknown: a managed Secret without the annotation, created by a
	// version that did not record it. What it was requested with is not known.
	raConfigUnknown
	// raConfigDrifted: the Issuer's RA configuration differs from what the
	// certificate was requested with.
	raConfigDrifted
)

func raConfigStateOf(secret *corev1.Secret, want string) raConfigState {
	if !isManagedSecret(secret) {
		return raConfigInSync
	}
	have, ok := secret.Annotations[raConfigHashAnnotation]
	switch {
	case !ok:
		return raConfigUnknown
	case have == want:
		return raConfigInSync
	default:
		return raConfigDrifted
	}
}

// stampRAConfigHash adopts a managed RA Secret that predates the annotation by
// recording the current configuration hash on it, so later edits are detected. It
// assumes the existing certificate matches the current configuration, because
// there is no way to tell: a CA may rewrite the subject or SANs, so comparing the
// issued certificate with the spec would give false positives. A failure is only
// logged, and the next renewal pass tries again.
func (o *Issuer) stampRAConfigHash(ctx context.Context, nn types.NamespacedName, hash string) {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		latest := &corev1.Secret{}
		if err := o.client.Get(ctx, nn, latest); err != nil {
			return err
		}
		if !isManagedSecret(latest) {
			return nil
		}
		if _, ok := latest.Annotations[raConfigHashAnnotation]; ok {
			return nil
		}
		updated := latest.DeepCopy()
		if updated.Annotations == nil {
			updated.Annotations = map[string]string{}
		}
		updated.Annotations[raConfigHashAnnotation] = hash
		return o.client.Update(ctx, updated)
	})
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to record the RA configuration hash on the signer secret", "secret", nn.String())
	}
}
