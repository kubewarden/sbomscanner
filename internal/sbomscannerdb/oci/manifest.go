package oci

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ManifestView is a source-agnostic snapshot of a DB artifact's manifest,
// suitable for rendering by the CLI. It is produced by both Remote.Inspect
// (registry) and Store.Inspect (local store).
type ManifestView struct {
	// Ref is the reference the artifact was inspected by.
	Ref string `json:"ref"`
	// Digest is the manifest digest.
	Digest string `json:"digest"`
	// MediaType is the manifest media type.
	MediaType string `json:"mediaType"`
	// ArtifactType identifies the DB artifact on the manifest.
	ArtifactType string `json:"artifactType,omitempty"`
	// Size is the manifest size in bytes.
	Size int64 `json:"size"`
	// Annotations are the manifest annotations (created, lastUpdate, nextUpdate, …).
	Annotations map[string]string `json:"annotations,omitempty"`
	// Layers describes each layer in manifest order.
	Layers []LayerView `json:"layers"`
}

// LayerView describes one layer of an inspected artifact.
type LayerView struct {
	// Digest is the layer blob digest.
	Digest string `json:"digest"`
	// MediaType identifies the feed carried by the layer.
	MediaType string `json:"mediaType"`
	// Size is the layer blob size in bytes.
	Size int64 `json:"size"`
	// Annotations are the layer annotations (title, lastUpdate, nextUpdate, …).
	Annotations map[string]string `json:"annotations,omitempty"`
}

// newManifestView maps an OCI manifest and its descriptor into a ManifestView.
func newManifestView(ref string, desc ocispec.Descriptor, manifest ocispec.Manifest) ManifestView {
	layers := make([]LayerView, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		layers = append(layers, LayerView{
			Digest:      layer.Digest.String(),
			MediaType:   layer.MediaType,
			Size:        layer.Size,
			Annotations: layer.Annotations,
		})
	}
	return ManifestView{
		Ref:          ref,
		Digest:       desc.Digest.String(),
		MediaType:    manifest.MediaType,
		ArtifactType: manifest.ArtifactType,
		Size:         desc.Size,
		Annotations:  manifest.Annotations,
		Layers:       layers,
	}
}
