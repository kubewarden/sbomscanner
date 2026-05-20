package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VEXHubSpec defines the desired state of VEXHub
type VEXHubSpec struct {
	// URL is the URL of the VEXHub repository
	URL string `json:"url,omitempty"`
	// Enabled tells if the VEX Hub is enabled for processing
	Enabled bool `json:"enabled,omitempty"`
}

// VEXHubStatus defines the observed state of VEXHub.
type VEXHubStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// VEXHub is the Schema for the vexhubs API
type VEXHub struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of VEXHub
	// +required
	Spec VEXHubSpec `json:"spec"`

	// status defines the observed state of VEXHub
	// +optional
	Status VEXHubStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// VEXHubList contains a list of VEXHub
type VEXHubList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VEXHub `json:"items"`
}

func init() {
	register(&VEXHub{}, &VEXHubList{})
}
