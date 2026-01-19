package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SBOMList contains a list of Software Bill of Materials
type SBOMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []SBOM `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.registry`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.registryURI`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.repository`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.tag`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.platform`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.digest`

// SBOM represents a Software Bill of Materials of an OCI artifact
type SBOM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	ImageMetadata     ImageMetadata `json:"imageMetadata" protobuf:"bytes,2,req,name=imageMetadata"`
	// SPDX contains the SPDX document of the SBOM in JSON format
	SPDX runtime.RawExtension `json:"spdx" protobuf:"bytes,3,req,name=spdx"`
}

func (s *SBOM) GetImageMetadata() ImageMetadata {
	return s.ImageMetadata
}

func (s *SBOM) SetImageMetadata(imageMetadata ImageMetadata) {
	s.ImageMetadata = imageMetadata
}
