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
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "registry:2",
			ExposedPorts: []string{"5000/tcp"},
			WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp"),
		},
		Started: true,
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

// useTempDockerConfig points DOCKER_CONFIG at a temp dir with an empty
// config.json so push/pull pass the docker-config pre-flight check.
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

	built, err := NewBuilder(store, slog.New(slog.DiscardHandler)).Build(ctx, ref, dataDir, layers)
	require.NoError(t, err)
	pushed, err := remote.Push(ctx, store, ref)
	require.NoError(t, err)
	assert.Equal(t, built.Digest, pushed.Digest)

	outDir := t.TempDir()
	paths, err := remote.Pull(ctx, ref, outDir)
	require.NoError(t, err)
	require.Len(t, paths, len(layers))

	// Each feed comes back as its own decompressed file, named by its layer title.
	for i, layer := range layers {
		assert.Equal(t, layer.FileName, filepath.Base(paths[i]))
		data, err := os.ReadFile(paths[i])
		require.NoError(t, err)
		assert.Equal(t, "data for "+layer.FileName, string(data))
	}

	// Re-push is idempotent: all content is already present remotely.
	_, err = remote.Push(ctx, store, ref)
	require.NoError(t, err)
}

func TestPush_FailsForUnbuiltRef(t *testing.T) {
	useTempDockerConfig(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))

	_, err := NewRemote(Config{PlainHTTP: true}, slog.New(slog.DiscardHandler)).Push(context.Background(), store, "registry.example.com/nope:missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run `build` first")
}

func TestPush_FailsWithoutDockerConfig(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", filepath.Join(t.TempDir(), "does-not-exist"))

	dataDir, layers := writeTestData(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))
	ctx := context.Background()

	_, err := NewBuilder(store, slog.New(slog.DiscardHandler)).Build(ctx, testRef, dataDir, layers)
	require.NoError(t, err)

	_, err = NewRemote(Config{PlainHTTP: true}, slog.New(slog.DiscardHandler)).Push(ctx, store, testRef)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker config not found")
}

func TestPush_RejectsDigestReference(t *testing.T) {
	useTempDockerConfig(t)
	ref := "registry.example.com/repo@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

	store := NewStore(t.TempDir(), slog.New(slog.DiscardHandler))
	_, err := NewRemote(Config{}, slog.New(slog.DiscardHandler)).Push(context.Background(), store, ref)
	require.Error(t, err)
}
