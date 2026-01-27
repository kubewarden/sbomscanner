package v1alpha1

// IndexImageMetadataRegistry is the field index for the registry of an image.
const (
	IndexImageMetadataRegistry = "imageMetadata.registry"
	IndexImageMetadataDigest   = "imageMetadata.digest"
)

// ImageMetadata contains the metadata details of an image.
type ImageMetadata struct {
	// Registry specifies the name of the Registry object in the same namespace where the image is stored.
	Registry string `json:"registry" protobuf:"bytes,1,req,name=registry"`
	// RegistryURI specifies the URI of the registry where the image is stored. Example: "registry-1.docker.io:5000".`
	RegistryURI string `json:"registryURI" protobuf:"bytes,2,req,name=registryURI"`
	// Repository specifies the repository path of the image. Example: "kubewarden/sbomscanner".
	Repository string `json:"repository" protobuf:"bytes,3,req,name=repository"`
	// Tag specifies the tag of the image. Example: "latest".
	Tag string `json:"tag" protobuf:"bytes,4,req,name=tag"`
	// Platform specifies the platform of the image. Example "linux/amd64".
	Platform string `json:"platform" protobuf:"bytes,5,req,name=platform"`
	// Digest specifies the image manifest digest.
	Digest string `json:"digest" protobuf:"bytes,6,req,name=digest"`
	// IndexDigest specifies the image index digest that referenced this manifest. Set only for multi-arch images.
	IndexDigest string `json:"indexDigest,omitempty" protobuf:"bytes,7,opt,name=indexDigest"`
}

type ImageMetadataAccessor interface {
	GetImageMetadata() ImageMetadata
}
