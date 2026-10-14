package oci

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerify_UnsignedArtifactFails pushes an artifact without any cosign
// signature and asserts that verification rejects it. An attacker with registry
// write access but no trusted signing identity lands exactly here.
func TestVerify_UnsignedArtifactFails(t *testing.T) {
	registry := startRegistry(t)
	useTempDockerConfig(t)
	ctx := context.Background()

	dataDir, layers := writeTestData(t)
	store := NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler))
	ref := registry + "/kubewarden/sbomscanner/sbomscannerdb:1"

	cfg := Config{PlainHTTP: true}
	built, err := NewBuilder(store, slog.New(slog.DiscardHandler), "").build(ctx, ref, dataDir, layers, testWindow())
	require.NoError(t, err)
	pushed, err := NewRemote(cfg, slog.New(slog.DiscardHandler)).Push(ctx, store, ref)
	require.NoError(t, err)
	require.Equal(t, built.Digest, pushed.Digest)

	pinned, err := PinDigest(ref, pushed.Digest)
	require.NoError(t, err)
	err = NewVerifier(cfg, slog.New(slog.DiscardHandler)).Verify(ctx, pinned)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVerification)
}

// TestVerifier_TUFOptions checks that a writable TUFCacheDir enables the local
// cache at the given path, while an empty one disables it so verification works
// on a read-only filesystem.
func TestVerifier_TUFOptions(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "tuf")
	withCache := NewVerifier(Config{TUFCacheDir: cacheDir}, slog.New(slog.DiscardHandler)).tufOptions()
	assert.False(t, withCache.DisableLocalCache)
	assert.Equal(t, cacheDir, withCache.CachePath)

	withoutCache := NewVerifier(Config{}, slog.New(slog.DiscardHandler)).tufOptions()
	assert.True(t, withoutCache.DisableLocalCache)
}

// TestVerify_RejectsTagReference guards the digest-only contract: Verify parses
// its argument as a digest reference, so a tag is rejected before any registry call.
func TestVerify_RejectsTagReference(t *testing.T) {
	err := NewVerifier(Config{}, slog.New(slog.DiscardHandler)).Verify(
		context.Background(),
		"registry.example.com/kubewarden/sbomscannerdb:1",
	)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVerification, "should fail while parsing the reference, not during verification")
}
