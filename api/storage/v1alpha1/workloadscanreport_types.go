package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadScanReportList contains a list of WorkloadScanReport
type WorkloadScanReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []WorkloadScanReport `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadScanReport represents the vulnerability scan results for a workload's containers.
// The VulnerabilityReports field in each container is populated at read time by joining
// with the VulnerabilityReport table based on the VulnerabilityReportRef.
type WorkloadScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Containers contains the list of containers in the workload and their vulnerability reports.
	Containers []Container `json:"containers" protobuf:"bytes,2,rep,name=containers"`
}

// Container represents a container in a workload with its associated vulnerability reports.
type Container struct {
	// Name is the name of the container.
	Name string `json:"name" protobuf:"bytes,1,req,name=name"`

	// VulnerabilityReportRef identifies which VulnerabilityReports to associate with this container.
	VulnerabilityReportRef VulnerabilityReportRef `json:"vulnerabilityReportRef" protobuf:"bytes,2,req,name=vulnerabilityReportRef"`

	// VulnerabilityReports contains the vulnerability reports for this container's image.
	// This field is populated at read time and is not stored.
	// Multiple reports may exist for multi-arch images (one per platform).
	// +optional
	VulnerabilityReports []WorkloadScanVulnerabilityReport `json:"vulnerabilityReports,omitempty" protobuf:"bytes,3,rep,name=vulnerabilityReports"`
}

// VulnerabilityReportRef identifies a set of VulnerabilityReports by image reference.
// It matches VulnerabilityReports where:
// - imageMetadata.registry equals Registry
// - metadata.namespace equals Namespace
// - imageMetadata.repository equals Repository
// - imageMetadata.tag equals Tag
type VulnerabilityReportRef struct {
	// Registry is the name of the Registry custom resource.
	Registry string `json:"registry" protobuf:"bytes,1,req,name=registry"`

	// Namespace is the namespace where the VulnerabilityReports are stored.
	Namespace string `json:"namespace" protobuf:"bytes,2,req,name=namespace"`

	// Repository is the repository path of the image.
	Repository string `json:"repository" protobuf:"bytes,3,req,name=repository"`

	// Tag is the tag of the image.
	Tag string `json:"tag" protobuf:"bytes,4,req,name=tag"`
}

type WorkloadScanVulnerabilityReport struct {
	ImageMetadata ImageMetadata `json:"imageMetadata" protobuf:"bytes,1,req,name=imageMetadata"`
	Report        Report        `json:"report" protobuf:"bytes,2,req,name=report"`
}
