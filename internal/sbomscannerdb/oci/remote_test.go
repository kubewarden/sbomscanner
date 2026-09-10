package oci

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startRegistry runs a registry:2 container and returns its host:port
// address. The container is terminated when the test finishes.
func startRegistry(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp"),
		Started:      true,
	})
	if err != nil {
		t.Skipf("cannot start registry container (docker not available?): %v", err)
	}
	t.Cleanup(func() {
		_ = testcontainers.TerminateContainer(container)
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5000/tcp")
	require.NoError(t, err)
	return fmt.Sprintf("%s:%s", host, port.Port())
}

// useTempDockerConfig points DOCKER_CONFIG at an empty config.json,
// so the tests never read the developer's real credentials.
func useTempDockerConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600))
	t.Setenv("DOCKER_CONFIG", dir)
}

func TestPushPull_RoundTrip(t *testing.T) {
	registry := startRegistry(t)
	useTempDockerConfig(t)
	ctx := context.Background()
	remote := NewRemote(Config{PlainHTTP: true}, slog.New(slog.DiscardHandler))

	dataDir, layers := writeTestData(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))
	ref := registry + "/kubewarden/sbomscanner/sbomscannerdb:latest"

	built, err := NewBuilder(store, slog.New(slog.DiscardHandler), "").build(ctx, ref, dataDir, layers, testWindow())
	require.NoError(t, err)
	pushed, err := remote.Push(ctx, store, ref)
	require.NoError(t, err)
	assert.Equal(t, built.Digest, pushed.Digest)

	// Pull into a second, empty store. The digest round-trips.
	pulledStore := NewStore(filepath.Join(t.TempDir(), "pulled"), slog.New(slog.DiscardHandler))
	pulled, err := remote.Pull(ctx, pulledStore, ref)
	require.NoError(t, err)
	assert.Equal(t, built.Digest, pulled.Digest)

	// Each feed exports as its own decompressed file, named by its layer title.
	outDir := t.TempDir()
	paths, err := pulledStore.Export(ctx, ref, outDir)
	require.NoError(t, err)
	require.Len(t, paths, len(layers))
	for i, layer := range layers {
		assert.Equal(t, layer.FileName, filepath.Base(paths[i]))
		data, err := os.ReadFile(paths[i])
		require.NoError(t, err)
		assert.Equal(t, "data for "+layer.FileName, string(data))
	}

	// A second pull finds everything in the store and returns the same artifact.
	pulled2, err := remote.Pull(ctx, pulledStore, ref)
	require.NoError(t, err)
	assert.Equal(t, pulled, pulled2)

	// Re-push is idempotent: all content is already present remotely.
	_, err = remote.Push(ctx, store, ref)
	require.NoError(t, err)
}

func TestPush_FailsForUnbuiltRef(t *testing.T) {
	useTempDockerConfig(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))

	_, err := NewRemote(Config{PlainHTTP: true}, slog.New(slog.DiscardHandler)).Push(context.Background(), store, "registry.example.com/nope:missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run `build` or `pull` first")
}

func TestPush_RejectsDigestReference(t *testing.T) {
	useTempDockerConfig(t)
	ref := "registry.example.com/repo@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

	store := NewStore(t.TempDir(), slog.New(slog.DiscardHandler))
	_, err := NewRemote(Config{}, slog.New(slog.DiscardHandler)).Push(context.Background(), store, ref)
	require.Error(t, err)
}

func TestRemoteInspect_RoundTrip(t *testing.T) {
	registry := startRegistry(t)
	useTempDockerConfig(t)
	ctx := context.Background()
	remote := NewRemote(Config{PlainHTTP: true}, slog.New(slog.DiscardHandler))

	dataDir, layers := writeTestData(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))
	ref := registry + "/kubewarden/sbomscanner/sbomscannerdb:latest"

	built, err := NewBuilder(store, slog.New(slog.DiscardHandler), "").build(ctx, ref, dataDir, layers, testWindow())
	require.NoError(t, err)
	_, err = remote.Push(ctx, store, ref)
	require.NoError(t, err)

	view, err := remote.Inspect(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, ref, view.Ref)
	assert.Equal(t, built.Digest, view.Digest)
	assert.Equal(t, ArtifactType, view.ArtifactType)
	require.Len(t, view.Layers, len(layers))
	window := testWindow().annotations()
	assert.Equal(t, window[AnnotationNextUpdate], view.Annotations[AnnotationNextUpdate])
}

func TestRemoteInspect_RejectsDigestReference(t *testing.T) {
	useTempDockerConfig(t)
	ref := "registry.example.com/repo@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

	_, err := NewRemote(Config{}, slog.New(slog.DiscardHandler)).Inspect(context.Background(), ref)
	require.Error(t, err)
}
