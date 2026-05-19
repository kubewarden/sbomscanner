package v1alpha1

// IndexNodeMetadataDigest is the field index for the digest of a node.
const (
	IndexNodeMetadataName = "nodeMetadata.name"
)

// NodeMetadata contains the metadata details of a node.
type NodeMetadata struct {
	// Name specifies the name of the node.
	Name string `json:"name" protobuf:"bytes,1,req,name=name"`
	// Platform specifies the platform of the image. Example "linux/amd64".
	Platform string `json:"platform" protobuf:"bytes,2,req,name=platform"`
}

type NodeMetadataAccessor interface {
	GetNodeMetadata() NodeMetadata
}
