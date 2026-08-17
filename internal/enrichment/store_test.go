package enrichment

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKEV = `{
  "title": "CISA KEV",
  "catalogVersion": "2026.07.16",
  "count": 2,
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228"},
    {"cveID": "CVE-2019-0708"}
  ]
}`
	testEPSS = `#model_version:v2026.07.16,score_date:2026-07-16T00:00:00Z
cve,epss,percentile
CVE-2021-44228,0.97,0.999
CVE-2020-1234,0.01,0.5
`
)

// seedCache writes the KEV and EPSS feed files into dir.
func seedCache(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVFileName), []byte(testKEV), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.EPSSFileName), []byte(testEPSS), 0o600))
}

func newTestStore(cacheDir string) *Store {
	return New("registry.example.com/db:latest", cacheDir, oci.Config{}, slog.New(slog.DiscardHandler))
}

func TestLookup_AfterLoad(t *testing.T) {
	dir := t.TempDir()
	seedCache(t, dir)
	store := newTestStore(dir)
	require.NoError(t, store.load(context.Background()))

	tests := []struct {
		name string
		cve  string
		want Enrichment
	}{
		{
			name: "KEV and EPSS",
			cve:  "CVE-2021-44228",
			want: Enrichment{KnownExploited: true, EPSSScore: 0.97, EPSSPercentile: 0.999, EPSSFound: true},
		},
		{
			name: "KEV only",
			cve:  "CVE-2019-0708",
			want: Enrichment{KnownExploited: true},
		},
		{
			name: "EPSS only",
			cve:  "CVE-2020-1234",
			want: Enrichment{EPSSScore: 0.01, EPSSPercentile: 0.5, EPSSFound: true},
		},
		{
			name: "unknown CVE",
			cve:  "CVE-0000-0000",
			want: Enrichment{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, store.Lookup(tc.cve))
		})
	}
}

func TestLookup_NilStoreIsNoOp(t *testing.T) {
	var store *Store
	assert.Equal(t, Enrichment{}, store.Lookup("CVE-2021-44228"))
	store.Update(context.Background()) // must not panic
}

func TestRefresh_BootstrapsFromDiskAndStaysFreshWhileWithinHorizon(t *testing.T) {
	dir := t.TempDir()
	seedCache(t, dir)
	// Persist a nextUpdate far in the future so Refresh serves the disk cache
	// without ever contacting the (unreachable) registry.
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	require.NoError(t, os.WriteFile(filepath.Join(dir, nextUpdateFileName), []byte(future), 0o600))

	store := newTestStore(dir)
	store.Update(context.Background())

	// Loaded from disk, and lookups work despite the registry being unreachable.
	assert.True(t, store.Lookup("CVE-2021-44228").KnownExploited)
	assert.True(t, store.loaded)
}

func TestRefresh_RegistryFailureDegradesGracefully(t *testing.T) {
	dir := t.TempDir() // empty: no cache, no persisted horizon
	store := newTestStore(dir)

	// Horizon is zero, so Refresh will try the (unreachable) registry and fail,
	// but it must not panic and must leave the store usable-but-empty.
	store.Update(context.Background())

	assert.Equal(t, Enrichment{}, store.Lookup("CVE-2021-44228"))
}

func TestLoad_ToleratesSingleMissingFeed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVFileName), []byte(testKEV), 0o600))
	// No EPSS file.
	store := newTestStore(dir)
	require.NoError(t, store.load(context.Background()))

	assert.True(t, store.Lookup("CVE-2021-44228").KnownExploited)
	assert.False(t, store.Lookup("CVE-2021-44228").EPSSFound)
}

func TestLoad_FailsWhenNoFeeds(t *testing.T) {
	store := newTestStore(t.TempDir())
	require.Error(t, store.load(context.Background()))
}

func TestCleanCache_RemovesStaleCache(t *testing.T) {
	runDir := t.TempDir()
	cacheDir := DefaultCacheDir(runDir)
	require.NoError(t, os.MkdirAll(cacheDir, 0o700))
	// A leftover nextUpdate is exactly what makes a restarted store skip the pull.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, nextUpdateFileName), []byte("2999-01-01T00:00:00Z"), 0o600))

	CleanCache(runDir, slog.New(slog.DiscardHandler))

	_, err := os.Stat(cacheDir)
	assert.True(t, os.IsNotExist(err), "enrichment cache dir must be removed")
}

func TestCleanCache_NoDirIsNoOp(t *testing.T) {
	runDir := t.TempDir() // no enrichment subdir exists
	// Must not panic or fail when there is nothing to clean.
	CleanCache(runDir, slog.New(slog.DiscardHandler))
	_, err := os.Stat(DefaultCacheDir(runDir))
	assert.True(t, os.IsNotExist(err))
}
