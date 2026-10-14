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
	"oras.land/oras-go/v2/errdef"
)

// testDigest is a well-formed digest that matches no content the tests build.
const testDigest = "sha256:8bd15b4817faa0f34829aa505edc90aab0dcb98e3d86b93625d2aeecdc3ab125"

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

	// Pulling by the pinned digest lands the same artifact under the same tag.
	pinned, err := PinDigest(ref, built.Digest)
	require.NoError(t, err)
	pulledByDigest, err := remote.PullByDigest(ctx, pulledStore, pinned, ref)
	require.NoError(t, err)
	assert.Equal(t, pulled, pulledByDigest)

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

	// A digest the repository does not hold fails with ErrNotFound.
	unknown, err := PinDigest(ref, testDigest)
	require.NoError(t, err)
	_, err = remote.PullByDigest(ctx, NewStore(filepath.Join(t.TempDir(), "unknown"), slog.New(slog.DiscardHandler)), unknown, ref)
	require.ErrorIs(t, err, errdef.ErrNotFound)
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
	ref := "registry.example.com/repo@" + testDigest

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
	ref := "registry.example.com/repo@" + testDigest

	_, err := NewRemote(Config{}, slog.New(slog.DiscardHandler)).Inspect(context.Background(), ref)
	require.Error(t, err)
}

func TestPinDigest(t *testing.T) {
	const repo = "registry.example.com/kubewarden/sbomscannerdb"
	tests := []struct {
		name    string
		ref     string
		digest  string
		want    string
		wantErr bool
	}{
		{name: "tag reference", ref: repo + ":1", digest: testDigest, want: repo + "@" + testDigest},
		{name: "digest reference is rejected", ref: repo + "@" + testDigest, digest: testDigest, wantErr: true},
		{name: "tag instead of digest is rejected", ref: repo + ":1", digest: "latest", wantErr: true},
		{name: "truncated digest is rejected", ref: repo + ":1", digest: "sha256:abcd", wantErr: true},
		{name: "empty digest is rejected", ref: repo + ":1", digest: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := PinDigest(test.ref, test.digest)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestPullByDigest_RejectsInvalidReferences(t *testing.T) {
	const repo = "registry.invalid/repo"
	tests := []struct {
		name      string
		digestRef string
		localTag  string
		wantErr   string
	}{
		{name: "tag as digest reference", digestRef: repo + ":latest", localTag: repo + ":1", wantErr: "must be a digest"},
		{name: "malformed digest", digestRef: repo + "@sha256:abcd", localTag: repo + ":1", wantErr: "invalid digest"},
		{name: "digest as local tag", digestRef: repo + "@" + testDigest, localTag: repo + "@" + testDigest, wantErr: "local tag"},
		{name: "repository without tag as local tag", digestRef: repo + "@" + testDigest, localTag: repo, wantErr: "local tag"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useTempDockerConfig(t)
			store := NewStore(t.TempDir(), slog.New(slog.DiscardHandler))
			remote := NewRemote(Config{}, slog.New(slog.DiscardHandler))

			_, err := remote.PullByDigest(context.Background(), store, test.digestRef, test.localTag)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantErr)
		})
	}
}

func TestPullByDigest_PinsWhenTagMoves(t *testing.T) {
	registry := startRegistry(t)
	useTempDockerConfig(t)
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	remote := NewRemote(Config{PlainHTTP: true}, logger)
	ref := registry + "/kubewarden/sbomscanner/sbomscannerdb:1"

	// Publish artifact A under the tag.
	dataDir, layers := writeTestData(t)
	storeA := NewStore(filepath.Join(t.TempDir(), "a"), logger)
	builtA, err := NewBuilder(storeA, logger, "").build(ctx, ref, dataDir, layers, testWindow())
	require.NoError(t, err)
	_, err = remote.Push(ctx, storeA, ref)
	require.NoError(t, err)

	// Move the tag to a different artifact B.
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, layers[0].FileName), []byte("other data"), 0o600))
	storeB := NewStore(filepath.Join(t.TempDir(), "b"), logger)
	builtB, err := NewBuilder(storeB, logger, "").build(ctx, ref, dataDir, layers, testWindow())
	require.NoError(t, err)
	require.NotEqual(t, builtA.Digest, builtB.Digest)
	_, err = remote.Push(ctx, storeB, ref)
	require.NoError(t, err)

	// Pulling by A's digest returns A, even though the tag now points to B.
	pinned, err := PinDigest(ref, builtA.Digest)
	require.NoError(t, err)
	local := NewStore(filepath.Join(t.TempDir(), "local"), logger)
	pulled, err := remote.PullByDigest(ctx, local, pinned, ref)
	require.NoError(t, err)
	assert.Equal(t, builtA.Digest, pulled.Digest)
	assert.Equal(t, ref, pulled.Ref)

	view, err := local.Inspect(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, builtA.Digest, view.Digest)
}
