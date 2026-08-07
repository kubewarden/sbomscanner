package oci

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildWithWindow builds the standard test data with the given window and
// returns the parsed manifest.
func buildWithWindow(t *testing.T, window UpdateWindow) ocispec.Manifest {
	t.Helper()
	dataDir, layers := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")

	built, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler), "").
		build(context.Background(), testRef, dataDir, layers, window)
	require.NoError(t, err)
	return readManifest(t, storeDir, built.Digest)
}

func TestBuild_SetsUpdateWindowAnnotationsOnManifest(t *testing.T) {
	last := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
	window := UpdateWindow{LastUpdate: last, NextUpdate: last.Add(24 * time.Hour)}

	manifest := buildWithWindow(t, window)

	assert.Equal(t, "2026-07-16T00:00:00Z", manifest.Annotations[AnnotationLastUpdate])
	assert.Equal(t, "2026-07-17T00:00:00Z", manifest.Annotations[AnnotationNextUpdate])
}

func TestBuild_DerivesCreatedFromLastUpdate(t *testing.T) {
	last := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
	window := UpdateWindow{LastUpdate: last, NextUpdate: last.Add(24 * time.Hour)}

	manifest := buildWithWindow(t, window)

	assert.Equal(t, "2026-07-16T00:00:00Z", manifest.Annotations[ocispec.AnnotationCreated])
	assert.Equal(t, manifest.Annotations[AnnotationLastUpdate], manifest.Annotations[ocispec.AnnotationCreated])
}

func TestBuild_MirrorsUpdateWindowAnnotationsOnEveryLayer(t *testing.T) {
	last := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
	window := UpdateWindow{LastUpdate: last, NextUpdate: last.Add(24 * time.Hour)}

	manifest := buildWithWindow(t, window)

	require.NotEmpty(t, manifest.Layers)
	for _, layer := range manifest.Layers {
		assert.Equal(t, manifest.Annotations[AnnotationLastUpdate], layer.Annotations[AnnotationLastUpdate])
		assert.Equal(t, manifest.Annotations[AnnotationNextUpdate], layer.Annotations[AnnotationNextUpdate])
		// The title annotation must still be present alongside the window annotations.
		assert.NotEmpty(t, layer.Annotations[ocispec.AnnotationTitle])
	}
}

func TestBuild_NormalizesUpdateWindowToRFC3339UTC(t *testing.T) {
	// A non-UTC input must be rendered as RFC3339 in UTC (Z suffix).
	loc := time.FixedZone("CEST", 2*60*60)
	last := time.Date(2026, time.July, 16, 2, 0, 0, 0, loc) // 00:00Z
	window := UpdateWindow{LastUpdate: last, NextUpdate: last.Add(24 * time.Hour)}

	manifest := buildWithWindow(t, window)

	lastValue := manifest.Annotations[AnnotationLastUpdate]
	nextValue := manifest.Annotations[AnnotationNextUpdate]
	assert.Equal(t, "2026-07-16T00:00:00Z", lastValue)
	assert.Equal(t, "2026-07-17T00:00:00Z", nextValue)

	parsedLast, err := time.Parse(time.RFC3339, lastValue)
	require.NoError(t, err)
	parsedNext, err := time.Parse(time.RFC3339, nextValue)
	require.NoError(t, err)
	assert.True(t, parsedLast.Before(parsedNext), "lastUpdate must be strictly before nextUpdate")
}

func TestBuild_RejectsInvalidUpdateWindow(t *testing.T) {
	last := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
	testCases := []struct {
		name   string
		window UpdateWindow
	}{
		{
			name:   "lastUpdate equals nextUpdate",
			window: UpdateWindow{LastUpdate: last, NextUpdate: last},
		},
		{
			name:   "lastUpdate after nextUpdate",
			window: UpdateWindow{LastUpdate: last, NextUpdate: last.Add(-time.Hour)},
		},
		{
			name:   "lastUpdate unset",
			window: UpdateWindow{NextUpdate: last},
		},
		{
			name:   "nextUpdate unset",
			window: UpdateWindow{LastUpdate: last},
		},
		{
			name:   "both unset",
			window: UpdateWindow{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir, layers := writeTestData(t)
			storeDir := filepath.Join(t.TempDir(), "store")

			_, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler), "").
				build(context.Background(), testRef, dataDir, layers, tc.window)
			require.Error(t, err)
		})
	}
}

func TestUpdateWindowValidate(t *testing.T) {
	last := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)

	require.NoError(t, UpdateWindow{LastUpdate: last, NextUpdate: last.Add(time.Nanosecond)}.validate())
	require.Error(t, UpdateWindow{LastUpdate: last, NextUpdate: last}.validate())
	require.Error(t, UpdateWindow{LastUpdate: last, NextUpdate: last.Add(-time.Nanosecond)}.validate())
	require.Error(t, UpdateWindow{}.validate())
}
