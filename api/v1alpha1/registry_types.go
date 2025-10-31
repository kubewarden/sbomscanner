package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// CatalogTypeNoCatalog is used for registries that don't
	// expose/implement the _catalog endpoint.
	CatalogTypeNoCatalog       = "NoCatalog"
	CatalogTypeOCIDistribution = "OCIDistribution"
)

// RegistrySpec defines the desired state of Registry
type RegistrySpec struct {
	// URI is the URI of the container registry
	URI string `json:"uri,omitempty"`
	// CatalogType is the type of catalog used to list the images within the registry.
	CatalogType string `json:"catalogType,omitempty"`
	// Repositories is the list of the repositories to be scanned
	// An empty list means all the repositories found in the registry are going to be scanned
	Repositories []string `json:"repositories,omitempty"`
	// AuthSecret is the name of the secret in the same namespace that contains the credentials to access the registry.
	AuthSecret string `json:"authSecret,omitempty"`
	// ScanInterval is the interval at which the registry is scanned.
	// If not set, automatic scanning is disabled.
	ScanInterval *metav1.Duration `json:"scanInterval,omitempty"`
	// CABundle is the CA bundle to use when connecting to the registry.
	CABundle string `json:"caBundle,omitempty"`
	// Insecure allows insecure connections to the registry when set to true.
	Insecure bool `json:"insecure,omitempty"`
	// Platforms allows to specify the list of platform to scan.
	// If not set, all the available platforms of a container image will be scanned.
	Platforms []Platform `json:"platforms,omitempty"`
}

// RegistryStatus defines the observed state of Registry
type RegistryStatus struct {
	// Represents the observations of a Registry's current state.
	// Registry.status.conditions.type are: "Discovering", "Scanning", and "UpToDate"
	// Registry.status.conditions.status are one of True, False, Unknown.
	// Registry.status.conditions.reason the value should be a CamelCase string and producers of specific
	// condition types may define expected values and meanings for this field, and whether the values
	// are considered a guaranteed API.
	// Registry.status.conditions.Message is a human readable message indicating details about the transition.
	// For further information see: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// Platform describes the platform which the image in the manifest runs on.
type Platform struct {
	// Architecture field specifies the CPU architecture, for example
	// `amd64` or `ppc64le`.
	Architecture string `json:"arch"`
	// OS specifies the operating system, for example `linux` or `windows`.
	OS string `json:"os"`
	// Variant is an optional field specifying a variant of the CPU, for
	// example `v7` to specify ARMv7 when architecture is `arm`.
	Variant string `json:"variant,omitempty"`
}

// String returns the expected platform string in the following format:
// <os>/<arch>[/<variant>]
func (p *Platform) String() string {
	platform := fmt.Sprintf("%s/%s", p.OS, p.Architecture)
	if p.Variant != "" {
		platform += fmt.Sprintf("/%s", p.Variant)
	}
	return platform
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Registry is the Schema for the registries API
type Registry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RegistrySpec   `json:"spec,omitempty"`
	Status RegistryStatus `json:"status,omitempty"`
}

// IsPrivate returns true when the registry requires authentication.
func (r *Registry) IsPrivate() bool {
	return r.Spec.AuthSecret != ""
}

// +kubebuilder:object:root=true

// RegistryList contains a list of Registry
type RegistryList struct {
	metav1.TypeMeta `           json:",inline"`
	metav1.ListMeta `           json:"metadata,omitempty"`
	Items           []Registry `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Registry{}, &RegistryList{})
}
