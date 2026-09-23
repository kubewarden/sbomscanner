package oci

import (
	"context"
	"errors"
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

	err = NewVerifier(cfg, slog.New(slog.DiscardHandler)).Verify(ctx, ref, pushed.Digest)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVerification)
}

// TestVerify_RejectsDigestReference guards the tag-only contract: Verify parses
// its ref as a tag, so a digest reference is rejected before any registry call.
func TestVerify_RejectsDigestReference(t *testing.T) {
	err := NewVerifier(Config{}, slog.New(slog.DiscardHandler)).Verify(
		context.Background(),
		"registry.example.com/kubewarden/sbomscannerdb@sha256:"+
			"0000000000000000000000000000000000000000000000000000000000000000",
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
	)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrVerification), "should fail while parsing the reference, not during verification")
}
