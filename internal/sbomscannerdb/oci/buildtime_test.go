package oci

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTime_DefaultsToNow(t *testing.T) {
	before := time.Now().UTC()
	got, err := buildTime("")
	require.NoError(t, err)
	after := time.Now().UTC()

	assert.Equal(t, time.UTC, got.Location())
	assert.False(t, got.Before(before))
	assert.False(t, got.After(after))
}

func TestBuildTime_HonorsSourceDateEpoch(t *testing.T) {
	// 2026-07-16T00:00:00Z
	got, err := buildTime("1784160000")
	require.NoError(t, err)
	assert.Equal(t, "2026-07-16T00:00:00Z", got.Format(time.RFC3339))
	assert.Equal(t, time.UTC, got.Location())
}

func TestBuildTime_RejectsInvalidSourceDateEpoch(t *testing.T) {
	_, err := buildTime("not-a-number")
	require.Error(t, err)
}

func TestBuildTime_IsReproducibleForSameEpoch(t *testing.T) {
	first, err := buildTime("1784160000")
	require.NoError(t, err)
	second, err := buildTime("1784160000")
	require.NoError(t, err)
	assert.Equal(t, first, second)
}
