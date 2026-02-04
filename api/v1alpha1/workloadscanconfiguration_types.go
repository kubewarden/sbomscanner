package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// WorkloadScanConfigurationName is the only allowed name for the singleton WorkloadScanConfiguration resource.
	WorkloadScanConfigurationName = "default"
)

// WorkloadScanConfigurationSpec defines the desired configuration for workload scanning.
type WorkloadScanConfigurationSpec struct {
	// NamespaceSelector filters which namespaces are scanned for workloads.
	// If not specified, workloads in all namespaces are scanned.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// TargetNamespace is the namespace where Registry, ScanJob, SBOM, and VulnerabilityReport resources will be created.
	// WorkloadScanReport resources will always be created in their respective workload namespaces.
	// If not specified, resources will be created in the workload's namespace.
	// This is useful in multi-tenant clusters to keep scan data isolated per namespace.
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// ScanInterval is the interval at which discovered registries are scanned.
	// +optional
	ScanInterval *metav1.Duration `json:"scanInterval,omitempty"`

	// ScanOnChange triggers a scan when a managed Registry resource is created or updated.
	// Defaults to true.
	// +kubebuilder:default=true
	// +optional
	ScanOnChange bool `json:"scanOnChange,omitempty"`

	// AuthSecret is the name of a secret in the installation namespace containing credentials to access registries.
	// The secret must be in dockerconfigjson format. See: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
	// +optional
	AuthSecret string `json:"authSecret,omitempty"`

	// CABundle is the CA bundle to use when connecting to registries.
	// +optional
	CABundle string `json:"caBundle,omitempty"`

	// Insecure allows insecure connections to registries when set to true.
	// +optional
	Insecure bool `json:"insecure,omitempty"`

	// Platforms specifies which platforms to scan for container images.
	// If not specified, all platforms available in the image manifest will be scanned.
	// +optional
	Platforms []Platform `json:"platforms,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="WorkloadScanConfiguration name must be 'default'"

// WorkloadScanConfiguration is the Schema for the workloadscanconfigurations API.
// This is a singleton resource - only one instance named "default" is allowed.
type WorkloadScanConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WorkloadScanConfigurationSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// WorkloadScanConfigurationList contains a list of WorkloadScanConfiguration.
type WorkloadScanConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WorkloadScanConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WorkloadScanConfiguration{}, &WorkloadScanConfigurationList{})
}
