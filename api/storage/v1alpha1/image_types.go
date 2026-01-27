package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageList contains a list of Image
type ImageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []Image `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.registry`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.registryURI`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.repository`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.tag`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.platform`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.digest`
// +kubebuilder:selectablefield:JSONPath=`.imageMetadata.indexDigest`

// Image is the Schema for the images API
type Image struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Metadata of the image
	ImageMetadata `json:"imageMetadata" protobuf:"bytes,2,req,name=imageMetadata"`
	// List of the layers that make the image
	Layers []ImageLayer `json:"layers,omitempty" protobuf:"bytes,3,rep,name=layers"`
}

// ImageLayer define a layer part of an OCI Image
type ImageLayer struct {
	// command is the command that led to the creation
	// of the layer. The contents are base64 encoded
	Command string `json:"command" protobuf:"bytes,1,req,name=command"`
	// digest is the Hash of the compressed layer
	Digest string `json:"digest" protobuf:"bytes,2,req,name=digest"`
	// diffID is the Hash of the uncompressed layer
	DiffID string `json:"diffID" protobuf:"bytes,3,req,name=diffID"`
}

func (i *Image) GetImageMetadata() ImageMetadata {
	return i.ImageMetadata
}
