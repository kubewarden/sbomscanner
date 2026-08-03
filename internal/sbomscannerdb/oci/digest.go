package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// descriptorFromFile computes the size and sha256 digest of the file at path
// and returns a descriptor with the given media type.
func descriptorFromFile(path, mediaType string) (ocispec.Descriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("hash %s: %w", path, err)
	}
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(hasher.Sum(nil))),
		Size:      size,
	}, nil
}
