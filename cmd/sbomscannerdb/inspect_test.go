package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

func TestRenderInspectJSON_EncodesView(t *testing.T) {
	view := oci.ManifestView{
		Ref:          "registry.example.com/db:latest",
		Digest:       "sha256:abc",
		MediaType:    "application/vnd.oci.image.manifest.v1+json",
		ArtifactType: oci.ArtifactType,
		Size:         123,
		Annotations: map[string]string{
			oci.AnnotationLastUpdate: "2026-07-16T00:00:00Z",
			oci.AnnotationNextUpdate: "2026-07-17T00:00:00Z",
		},
		Layers: []oci.LayerView{
			{Digest: "sha256:kev", MediaType: oci.DataLayerMediaType("kev", "json"), Size: 10},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, renderInspectJSON(&buf, view))

	var got oci.ManifestView
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, view, got)
	// Indented for humans.
	assert.Contains(t, buf.String(), "\n  ")
}

func TestCLI_InspectRequiresReference(t *testing.T) {
	_, err := runCLI(t, "inspect")
	require.Error(t, err)
}

func TestCLI_InspectLocalUnknownRefErrors(t *testing.T) {
	// A missing artifact in the (empty default) local store surfaces an error,
	// exercising the --local path without a registry.
	_, err := runCLI(t, "inspect", "--local", "registry.example.com/kubewarden/sbomscanner/does-not-exist:latest")
	require.Error(t, err)
}
