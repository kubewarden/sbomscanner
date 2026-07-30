package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRef = "registry.example.com/kubewarden/sbomscanner/sbomscannerdb:latest"

// writeTestData creates a data dir with one small file per feed and returns
// its path along with the layer descriptions.
func writeTestData(t *testing.T) (string, []Layer) {
	t.Helper()
	dataDir := t.TempDir()
	layers := []Layer{
		{Name: "kev", FileName: "kev.json", MediaType: LayerMediaTypeKEV},
		{Name: "epss", FileName: "epss.csv", MediaType: LayerMediaTypeEPSS},
	}
	for _, layer := range layers {
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, layer.FileName), []byte("data for "+layer.FileName), 0o600))
	}
	return dataDir, layers
}

func TestBuild_TagsArtifactInStore(t *testing.T) {
	dataDir, layers := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")

	built, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, layers)
	require.NoError(t, err)
	assert.Equal(t, testRef, built.Ref)

	artifacts, err := NewStore(storeDir, slog.New(slog.DiscardHandler)).List()
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, testRef, artifacts[0].Ref)
	assert.Equal(t, built.Digest, artifacts[0].Digest)
}

func TestBuild_OneLayerPerFile(t *testing.T) {
	dataDir, layers := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")

	built, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, layers)
	require.NoError(t, err)

	manifest := readManifest(t, storeDir, built.Digest)
	require.Len(t, manifest.Layers, len(layers))
	for i, layer := range layers {
		assert.Equal(t, layer.MediaType, manifest.Layers[i].MediaType)
		assert.Equal(t, layer.Name+".tar.gz", manifest.Layers[i].Annotations[ocispec.AnnotationTitle])
	}
}

func TestBuild_IsReproducible(t *testing.T) {
	dataDir, layers := writeTestData(t)

	first, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "a"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, layers)
	require.NoError(t, err)
	second, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "b"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, layers)
	require.NoError(t, err)

	assert.Equal(t, first.Digest, second.Digest)
}

func TestBuild_RetagsExistingContent(t *testing.T) {
	dataDir, layers := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")
	ctx := context.Background()

	store := NewStore(storeDir, slog.New(slog.DiscardHandler))
	builder := NewBuilder(store, slog.New(slog.DiscardHandler))
	_, err := builder.Build(ctx, testRef, dataDir, layers)
	require.NoError(t, err)
	otherRef := "registry.example.com/kubewarden/sbomscanner/sbomscannerdb:v2"
	_, err = builder.Build(ctx, otherRef, dataDir, layers)
	require.NoError(t, err)

	artifacts, err := store.List()
	require.NoError(t, err)
	refs := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		refs = append(refs, a.Ref)
	}
	assert.Contains(t, refs, testRef)
	assert.Contains(t, refs, otherRef)
}

func TestBuild_FailsOnMissingDataFile(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "store")
	layers := []Layer{{Name: "epss", FileName: "missing.csv", MediaType: LayerMediaTypeEPSS}}
	_, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, t.TempDir(), layers)
	require.Error(t, err)
}

func TestBuild_FailsOnEmptyDataFile(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "empty.csv"), nil, 0o600))

	layers := []Layer{{Name: "epss", FileName: "empty.csv", MediaType: LayerMediaTypeEPSS}}
	_, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, layers)
	require.Error(t, err)
}

func TestList_EmptyOnMissingStore(t *testing.T) {
	artifacts, err := NewStore(filepath.Join(t.TempDir(), "does-not-exist"), slog.New(slog.DiscardHandler)).List()
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestWriteTarGz_ContainsFile(t *testing.T) {
	srcDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "data.csv"), []byte("hello tar.gz"), 0o600))
	archivePath := filepath.Join(t.TempDir(), "data.tar.gz")

	require.NoError(t, writeTarGz(archivePath, srcDir, []string{"data.csv"}))

	entries := readTarGz(t, archivePath)
	require.Len(t, entries, 1)
	assert.Equal(t, "hello tar.gz", entries["data.csv"])
}

// readManifest reads the manifest blob for digest from the OCI layout at storeDir.
func readManifest(t *testing.T, storeDir, digest string) ocispec.Manifest {
	t.Helper()
	encoded, ok := strings.CutPrefix(digest, "sha256:")
	require.True(t, ok, "unexpected digest format: %s", digest)

	data, err := os.ReadFile(filepath.Join(storeDir, "blobs", "sha256", encoded))
	require.NoError(t, err)
	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	return manifest
}

// readTarGz returns the name -> content map of a tar.gz file.
func readTarGz(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gzr)

	entries := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		entries[hdr.Name] = string(data)
	}
	return entries
}
