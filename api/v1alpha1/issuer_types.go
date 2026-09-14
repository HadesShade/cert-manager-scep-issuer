/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// cmapi "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Delegated;Direct
type EnrollmentMode string

const (
	ConditionTypeReady       string = "Ready"
	ReasonVerified           string = "Verified"
	ReasonRABootstrapPending string = "RABootstrapPending"
	ReasonConfigurationError string = "ConfigurationError"
	ReasonSecretNotFound     string = "SecretNotFound"
	ReasonSCEPClientError    string = "SCEPClientError"
	ReasonRAEnrollmentFailed string = "RAEnrollmentFailed"

	Delegated EnrollmentMode = "Delegated"
	Direct    EnrollmentMode = "Direct"
)

type ChallengeSecretRef struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// X509Subject defines the standard X.509 subject attributes.
type X509Subject struct {
	// +optional
	Organizations []string `json:"organizations,omitempty"`

	// +optional
	Countries []string `json:"countries,omitempty"`

	// +optional
	OrganizationalUnits []string `json:"organizationalUnits,omitempty"`
}

type DelegatedSignerConfiguration struct {
	// +kubebuilder:validation:Required
	CommonName string `json:"commonName"`

	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// +optional
	Subject *X509Subject `json:"subject,omitempty"`

	// +kubebuilder:default="1080h"
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// +optional
	RenewalWindow *metav1.Duration `json:"renewalWindow,omitempty"`
}

type IssuerStatus struct {
	v1alpha1.IssuerStatus `json:",inline"`

	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="string",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Issuer is the Schema for the issuers API.
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// URL is the base URL for the endpoint of the signing service,
	// for example: "https://sample-signer.example.com/api".
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// +kubebuilder:validation:Required
	EnrollmentMode EnrollmentMode `json:"enrollmentMode"`

	//+optional
	ChallengeSecretRef *ChallengeSecretRef `json:"challengeSecretRef,omitempty"`

	//+optional
	DelegatedSignerConfiguration *DelegatedSignerConfiguration `json:"delegatedSignerConfiguration,omitempty"`

	//+optional
	DelegatedSignerSecretName *string `json:"delegatedSignerSecretName,omitempty"`

	// A reference to a Secret in the same namespace as the referent. If the
	// referent is a ClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	// AuthSecretName string `json:"authSecretName"`
}

func (vi *Issuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

// GetIssuerTypeIdentifier returns a string that uniquely identifies the
// issuer type. This should be a constant across all instances of this
// issuer type. This string is used as a prefix when determining the
// issuer type for a Kubernetes CertificateSigningRequest resource based
// on the issuerName field. The value should be formatted as follows:
// "<issuer resource (plural)>.<issuer group>". For example, the value
// "simpleclusterissuers.issuer.cert-manager.io" will match all CSRs
// with an issuerName set to eg. "simpleclusterissuers.issuer.cert-manager.io/issuer1".
func (vi *Issuer) GetIssuerTypeIdentifier() string {
	// ACTION REQUIRED: Change this to a unique string that identifies your issuer
	return "issuers.scep.hshade.io"
}

// issuer-lib requires that we implement the Issuer interface
// so that it can interact with our Issuer resource.
var _ v1alpha1.Issuer = &Issuer{}

// +kubebuilder:object:root=true

// IssuerList contains a list of Issuer.
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}
