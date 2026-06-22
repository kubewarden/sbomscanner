package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// NodeScanConfigurationName is the only allowed name for the singleton NodeScanConfiguration resource.
	NodeScanConfigurationName = "default"

	// AnnotationNodeRescanRequested triggers an immediate rescan of all matching nodes,
	// bypassing the scan interval timer. The annotation is removed after the scan jobs are created.
	AnnotationNodeRescanRequested = "sbomscanner.kubewarden.io/node-rescan-requested"
)

// NodeScanConfigurationSpec defines the desired configuration for node scanning.
type NodeScanConfigurationSpec struct {
	// Enabled controls whether node scanning is active.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
	// NodeSelector filters which nodes are scanned.
	// If not specified, all the nodes are scanned.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`

	// ScanInterval is the interval at which nodes are scanned.
	// +optional
	ScanInterval *metav1.Duration `json:"scanInterval,omitempty"`

	// SkipPatterns specifies gitignore-style patterns for directories and files to skip during node scanning.
	// Patterns ending with "/" are treated as directories.
	// All other patterns are treated as files.
	// Glob patterns like "**/vendor/" or "*.min.js" are supported.
	// +optional
	SkipPatterns []string `json:"skipPatterns,omitempty"`

	// Platforms allows to specify the list of platforms to scan.
	// If not set, all nodes are scanned regardless of their platform.
	// +optional
	Platforms []Platform `json:"platforms,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="NodeScanConfiguration name must be 'default'"

// NodeScanConfiguration is the Schema for the nodescanconfigurations API.
// This is a singleton resource - only one instance named "default" is allowed.
type NodeScanConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NodeScanConfigurationSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// NodeScanConfigurationList contains a list of NodeScanConfiguration.
type NodeScanConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NodeScanConfiguration `json:"items"`
}

func init() {
	register(&NodeScanConfiguration{}, &NodeScanConfigurationList{})
}
