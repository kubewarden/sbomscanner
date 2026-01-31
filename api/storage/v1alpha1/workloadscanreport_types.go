package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScanStatus represents the status of a container's vulnerability scan.
type ScanStatus string

const (
	// ScanStatusWaitingForScan indicates no Image record exists for this container's image.
	ScanStatusWaitingForScan ScanStatus = "WaitingForScan"
	// ScanStatusScanInProgress indicates the Image exists but not all platforms have been scanned.
	ScanStatusScanInProgress ScanStatus = "ScanInProgress"
	// ScanStatusScanComplete indicates all platforms have vulnerability reports.
	ScanStatusScanComplete ScanStatus = "ScanComplete"
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
type WorkloadScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Spec contains the workload container references, written by the reconciler.
	Spec WorkloadScanReportSpec `json:"spec" protobuf:"bytes,2,req,name=spec"`

	// Status contains the scan status for each container.
	// Populated at read time.
	// +optional
	Status WorkloadScanReportStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`

	// Summary provides aggregated vulnerability counts across all containers.
	// Vulnerabilities are deduplicated per container (same CVE across platforms counts as 1),
	// then summed across all containers.
	// Populated at read time.
	// +optional
	Summary Summary `json:"summary,omitempty" protobuf:"bytes,4,opt,name=summary"`

	// Containers contains the vulnerability reports for each container.
	// Populated at read time by joining with VulnerabilityReport data.
	// +optional
	Containers []ContainerResult `json:"containers,omitempty" protobuf:"bytes,5,rep,name=containers"`
}

// WorkloadScanReportSpec defines the containers to scan.
type WorkloadScanReportSpec struct {
	// Containers contains the list of containers in the workload with their image references.
	Containers []ContainerRef `json:"containers" protobuf:"bytes,1,rep,name=containers"`
}

// WorkloadScanReportStatus contains the observed scan state for the workload.
type WorkloadScanReportStatus struct {
	// ContainerStatuses contains the scan status for each container.
	// +optional
	ContainerStatuses []ContainerStatus `json:"containerStatuses,omitempty" protobuf:"bytes,1,rep,name=containerStatuses"`
}

// ContainerRef identifies a container and its image reference for vulnerability lookup.
type ContainerRef struct {
	// Name is the name of the container.
	Name string `json:"name" protobuf:"bytes,1,req,name=name"`

	// ImageRef identifies which VulnerabilityReports to associate with this container.
	ImageRef ImageRef `json:"imageRef" protobuf:"bytes,2,req,name=imageRef"`
}

// ImageRef identifies a set of VulnerabilityReports by image reference.
type ImageRef struct {
	// Registry is the name of the Registry custom resource.
	Registry string `json:"registry" protobuf:"bytes,1,req,name=registry"`
	// Namespace is the namespace where the VulnerabilityReports are stored.
	Namespace string `json:"namespace" protobuf:"bytes,2,req,name=namespace"`
	// Repository is the repository path of the image.
	Repository string `json:"repository" protobuf:"bytes,3,req,name=repository"`
	// Tag is the tag of the image.
	Tag string `json:"tag" protobuf:"bytes,4,req,name=tag"`
}

// ContainerStatus contains the scan status for a single container.
type ContainerStatus struct {
	// Name is the name of the container (matches ContainerRef.Name).
	Name string `json:"name" protobuf:"bytes,1,req,name=name"`

	// ScanStatus indicates the scan status for this container.
	ScanStatus ScanStatus `json:"scanStatus" protobuf:"bytes,2,req,name=scanStatus"`
}

// ContainerResult contains the vulnerability scan results for a single container.
type ContainerResult struct {
	// Name is the name of the container (matches ContainerRef.Name).
	Name string `json:"name" protobuf:"bytes,1,req,name=name"`

	// VulnerabilityReports contains the vulnerability reports for this container's image.
	// Multiple reports may exist for multi-arch images (one per platform).
	// +optional
	VulnerabilityReports []WorkloadScanVulnerabilityReport `json:"vulnerabilityReports,omitempty" protobuf:"bytes,2,rep,name=vulnerabilityReports"`
}

// WorkloadScanVulnerabilityReport contains vulnerability report data for a specific platform.
type WorkloadScanVulnerabilityReport struct {
	ImageMetadata ImageMetadata `json:"imageMetadata" protobuf:"bytes,1,req,name=imageMetadata"`
	Report        Report        `json:"report" protobuf:"bytes,2,req,name=report"`
}
