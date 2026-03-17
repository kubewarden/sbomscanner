package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeSBOMList contains a list of Software Bill of Materials for nodes
type NodeSBOMList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []NodeSBOM `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:selectablefield:JSONPath=`.nodeMetadata.name`
// +kubebuilder:selectablefield:JSONPath=`.nodeMetadata.namespace`
// +kubebuilder:selectablefield:JSONPath=`.nodeMetadata.uid`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.indexDigest`

// NodeSBOM represents a Software Bill of Materials of a node
type NodeSBOM struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	NodeMetadata      NodeMetadata `json:"nodeMetadata" protobuf:"bytes,2,req,name=nodeMetadata"`
	// SPDX contains the SPDX document of the SBOM in JSON format
	SPDX runtime.RawExtension `json:"spdx" protobuf:"bytes,3,req,name=spdx"`
}

func (s *NodeSBOM) GetNodeMetadata() NodeMetadata {
	return s.NodeMetadata
}
