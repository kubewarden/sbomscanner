package registry

import (
	"testing"

	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
)

const (
	mediaTypeCosignSimpleSigning types.MediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
	mediaTypeDSSEEnvelope        types.MediaType = "application/vnd.dsse.envelope.v1+json"
	mediaTypeHelmConfig          types.MediaType = "application/vnd.cncf.helm.config.v1+json"
	mediaTypeHelmChartContent    types.MediaType = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	mediaTypeWasmConfig          types.MediaType = "application/vnd.wasm.config.v1+json"
	mediaTypeWasmContent         types.MediaType = "application/vnd.wasm.content.layer.v1+wasm"
	mediaTypeOCIEmpty            types.MediaType = "application/vnd.oci.empty.v1+json"
	mediaTypeInToto              types.MediaType = "application/vnd.in-toto+json"
)

func TestIsContainerImageManifest(t *testing.T) {
	tests := []struct {
		name      string
		mediaType types.MediaType
		manifest  *cranev1.Manifest
		want      bool
	}{
		{
			name:      "OCI image with gzip layers",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.OCILayer},
					{MediaType: types.OCILayer},
				},
			},
			want: true,
		},
		{
			name:      "OCI image with zstd layers",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.OCILayerZStd},
				},
			},
			want: true,
		},
		{
			name:      "OCI image with uncompressed layers",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.OCIUncompressedLayer},
				},
			},
			want: true,
		},
		{
			name:      "OCI image with non-distributable layers",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.OCIRestrictedLayer},
					{MediaType: types.OCILayer},
				},
			},
			want: true,
		},
		{
			name:      "Docker v2 image",
			mediaType: types.DockerManifestSchema2,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.DockerConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.DockerLayer},
					{MediaType: types.DockerForeignLayer},
				},
			},
			want: true,
		},
		{
			name:      "nil manifest",
			mediaType: types.OCIManifestSchema1,
			manifest:  nil,
			want:      false,
		},
		{
			name:      "image index media type",
			mediaType: types.OCIImageIndex,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{{MediaType: types.OCILayer}},
			},
			want: false,
		},
		{
			name:      "Docker schema 1 media type",
			mediaType: types.DockerManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.DockerConfigJSON},
				Layers: []cranev1.Descriptor{{MediaType: types.DockerLayer}},
			},
			want: false,
		},
		{
			name:      "manifest with artifactType",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				ArtifactType: "application/vnd.example.artifact.v1",
				Config:       cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers:       []cranev1.Descriptor{{MediaType: types.OCILayer}},
			},
			want: false,
		},
		{
			name:      "image without layers",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{},
			},
			want: true,
		},
		{
			name:      "cosign signature",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{{MediaType: mediaTypeCosignSimpleSigning}},
			},
			want: false,
		},
		{
			name:      "cosign attestation",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{{MediaType: mediaTypeDSSEEnvelope}},
			},
			want: false,
		},
		{
			name:      "cosign bundle referrer",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				Config:       cranev1.Descriptor{MediaType: mediaTypeOCIEmpty},
				Layers:       []cranev1.Descriptor{{MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"}},
			},
			want: false,
		},
		{
			name:      "in-toto attestation referrer",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				ArtifactType: string(mediaTypeInToto),
				Config:       cranev1.Descriptor{MediaType: mediaTypeOCIEmpty},
				Layers:       []cranev1.Descriptor{{MediaType: mediaTypeDSSEEnvelope}},
			},
			want: false,
		},
		{
			name:      "Helm chart",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: mediaTypeHelmConfig},
				Layers: []cranev1.Descriptor{{MediaType: mediaTypeHelmChartContent}},
			},
			want: false,
		},
		{
			name:      "Wasm module",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: mediaTypeWasmConfig},
				Layers: []cranev1.Descriptor{{MediaType: mediaTypeWasmContent}},
			},
			want: false,
		},
		{
			name:      "image with one unknown layer",
			mediaType: types.OCIManifestSchema1,
			manifest: &cranev1.Manifest{
				Config: cranev1.Descriptor{MediaType: types.OCIConfigJSON},
				Layers: []cranev1.Descriptor{
					{MediaType: types.OCILayer},
					{MediaType: mediaTypeCosignSimpleSigning},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsContainerImageManifest(tt.mediaType, tt.manifest)
			assert.Equal(t, tt.want, got)
		})
	}
}
