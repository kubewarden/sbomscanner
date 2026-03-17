package v1alpha1

// IndexNodeMetadataDigest is the field index for the digest of a node.
const (
	IndexNodeMetadataMachineID = "nodeMetadata.machineID"
)

// NodeMetadata contains the metadata details of a node.
type NodeMetadata struct {
	// MachineID specifies the machine ID of the node.
	MachineID string `json:"machineID" protobuf:"bytes,1,req,name=machineID"`
	// Platform specifies the platform of the image. Example "linux/amd64".
	Platform string `json:"platform" protobuf:"bytes,2,req,name=platform"`
}

type NodeMetadataAccessor interface {
	GetNodeMetadata() NodeMetadata
}
