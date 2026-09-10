package sbomscannerdb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// testRepository uses a reserved host, so every registry contact fails fast.
const testRepository = "registry.invalid/kubewarden/sbomscannerdb"

// testRef is the reference that Open builds from testRepository.
const testRef = testRepository + ":1"

// seedFeeds writes the KEV and EPSS databases into dir, converted from upstream
// feeds the same way build does.
// CVE-2021-44228 is in both, CVE-2019-0708 only in KEV, CVE-2020-1234 only in EPSS.
func seedFeeds(t *testing.T, dir string) {
	t.Helper()
	kev, err := json.Marshal(datafeed.KEVCatalog{
		Title:          "CISA KEV",
		CatalogVersion: "2026.07.16",
		Count:          2,
		Vulnerabilities: []datafeed.KEVVulnerability{
			{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareCampaignUse: "Known"},
			{CVEID: "CVE-2019-0708", DateAdded: "2021-11-03", DueDate: "2022-05-03", KnownRansomwareCampaignUse: "Unknown"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVSourceFileName), kev, 0o600))

	var epss strings.Builder
	fmt.Fprintf(&epss, "#model_version:v2026.07.16,score_date:%s\n", scoreDate().Format(time.RFC3339))
	epss.WriteString("cve,epss,percentile\n")
	for _, score := range []datafeed.EPSSScore{
		{CVE: "CVE-2021-44228", EPSS: 0.97, Percentile: 0.999},
		{CVE: "CVE-2020-1234", EPSS: 0.01, Percentile: 0.5},
	} {
		fmt.Fprintf(&epss, "%s,%g,%g\n", score.CVE, score.EPSS, score.Percentile)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.EPSSSourceFileName), []byte(epss.String()), 0o600))

	logger := slog.New(slog.DiscardHandler)
	for _, source := range datafeed.AllSources(datafeed.NewHTTPDownloader(), logger) {
		_, err := source.BuildSQLite(context.Background(), dir, dir)
		require.NoError(t, err)
	}
}

// scoreDate is the score_date of the seeded EPSS feed.
func scoreDate() time.Time {
	return time.Date(2026, time.July, 16, 12, 1, 37, 0, time.UTC)
}

// log4jKEV is the expected KEV record of CVE-2021-44228 in the seeded feeds.
func log4jKEV() *storagev1alpha1.KEV {
	return &storagev1alpha1.KEV{DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUseKnown}
}

// buildArtifact builds the test feeds into the local store under runDir,
// as a previous pull would have left them. nextUpdate is the build time plus interval.
func buildArtifact(t *testing.T, runDir string, interval time.Duration) oci.Artifact {
	t.Helper()
	dataDir := t.TempDir()
	seedFeeds(t, dataDir)
	layers := []oci.Layer{
		{Name: "kev", FileName: datafeed.KEVDBFileName, MediaType: oci.DataLayerMediaType("kev")},
		{Name: "epss", FileName: datafeed.EPSSDBFileName, MediaType: oci.DataLayerMediaType("epss")},
	}
	logger := slog.New(slog.DiscardHandler)
	store := oci.NewStore(filepath.Join(runDir, cacheDirName, ociDirName), logger)
	built, err := oci.NewBuilder(store, logger, "").Build(context.Background(), testRef, dataDir, layers, interval)
	require.NoError(t, err)
	return built
}

// lookupRecord runs Lookup and fails the test on an error.
func lookupRecord(t *testing.T, db *DB, cve string) Record {
	t.Helper()
	record, err := db.Lookup(context.Background(), cve)
	require.NoError(t, err)
	return record
}

func newTestDB(runDir string) *DB {
	return Open(testRepository, runDir, oci.Config{}, slog.New(slog.DiscardHandler))
}

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	buildArtifact(t, dir, 24*time.Hour)
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	tests := []struct {
		name string
		db   *DB
		cve  string
		want Record
	}{
		{
			name: "KEV and EPSS",
			db:   db,
			cve:  "CVE-2021-44228",
			want: Record{
				KEV:  log4jKEV(),
				EPSS: &storagev1alpha1.EPSS{Score: "0.97", Percentile: "0.999", Date: metav1.NewTime(scoreDate())},
			},
		},
		{
			name: "KEV only",
			db:   db,
			cve:  "CVE-2019-0708",
			want: Record{KEV: &storagev1alpha1.KEV{DateAdded: "2021-11-03", DueDate: "2022-05-03", KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUseUnknown}},
		},
		{
			name: "EPSS only",
			db:   db,
			cve:  "CVE-2020-1234",
			want: Record{EPSS: &storagev1alpha1.EPSS{Score: "0.01", Percentile: "0.5", Date: metav1.NewTime(scoreDate())}},
		},
		{
			name: "unknown CVE",
			db:   db,
			cve:  "CVE-0000-0000",
			want: Record{},
		},
		{
			name: "nil DB",
			db:   nil,
			cve:  "CVE-2021-44228",
			want: Record{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, lookupRecord(t, test.db, test.cve))
		})
	}
}

func TestNilDB(t *testing.T) {
	var db *DB
	assert.NoError(t, db.Update(context.Background()))
	assert.NoError(t, db.Close())
}

func TestUpdate_LoadsFromLocalStoreWhileFresh(t *testing.T) {
	dir := t.TempDir()
	built := buildArtifact(t, dir, 24*time.Hour)

	// The artifact is fresh for a day, so Update never contacts the registry.
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	assert.Equal(t, built.Digest, db.digest)
	assert.Equal(t, log4jKEV(), lookupRecord(t, db, "CVE-2021-44228").KEV)
	assert.FileExists(t, filepath.Join(dir, cacheDirName, datafeed.KEVDBFileName))
	assert.FileExists(t, filepath.Join(dir, cacheDirName, datafeed.EPSSDBFileName))
}

func TestUpdate_StaleLocalStoreIsNotUsedWhenRegistryUnreachable(t *testing.T) {
	dir := t.TempDir()
	buildArtifact(t, dir, time.Nanosecond)

	// The artifact is stale, so Update contacts the registry and fails
	// before it loads anything from the stale copy.
	db := newTestDB(dir)
	require.Error(t, db.Update(context.Background()))

	assert.Empty(t, db.digest)
	assert.Equal(t, Record{}, lookupRecord(t, db, "CVE-2021-44228"))
}

func TestUpdate_StaleBrokenLocalCopyIsPulledAgain(t *testing.T) {
	dir := t.TempDir()
	buildArtifact(t, dir, time.Nanosecond)
	cacheDir := filepath.Join(dir, cacheDirName)
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, datafeed.KEVDBFileName), []byte("not sqlite"), 0o600))

	// The local copy is stale and broken. Update must reach the pull
	// instead of failing on the local parse.
	db := newTestDB(dir)
	err := db.Update(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pull sbomscanner DB")
}

func TestUpdate_FailsWithoutLocalStore(t *testing.T) {
	dir := t.TempDir() // empty: no local store
	db := newTestDB(dir)

	// Nothing is loaded, so Update contacts the registry and fails.
	require.Error(t, db.Update(context.Background()))

	assert.Empty(t, db.digest)
	assert.Equal(t, Record{}, lookupRecord(t, db, "CVE-2021-44228"))
}

func TestReload_FailsWhenOneFeedIsMissing(t *testing.T) {
	dir := t.TempDir()
	built := buildArtifact(t, dir, 24*time.Hour)
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	// A broken artifact must not replace the databases that are open.
	broken := buildBrokenArtifact(t, dir)
	require.Error(t, db.reload(context.Background(), broken))
	assert.Equal(t, built.Digest, db.digest)
	assert.Equal(t, log4jKEV(), lookupRecord(t, db, "CVE-2021-44228").KEV)
}

func TestClose_ReleasesTheDatabases(t *testing.T) {
	dir := t.TempDir()
	buildArtifact(t, dir, 24*time.Hour)
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	require.NoError(t, db.Close())
	assert.Nil(t, db.kev)
	assert.Nil(t, db.epss)
	assert.Equal(t, Record{}, lookupRecord(t, db, "CVE-2021-44228"))
}

// buildBrokenArtifact overwrites the local store with an artifact whose EPSS layer
// is not a database and returns its manifest view.
func buildBrokenArtifact(t *testing.T, runDir string) oci.ManifestView {
	t.Helper()
	dataDir := t.TempDir()
	seedFeeds(t, dataDir)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, datafeed.EPSSDBFileName), []byte("not sqlite"), 0o600))
	layers := []oci.Layer{
		{Name: "kev", FileName: datafeed.KEVDBFileName, MediaType: oci.DataLayerMediaType("kev")},
		{Name: "epss", FileName: datafeed.EPSSDBFileName, MediaType: oci.DataLayerMediaType("epss")},
	}
	logger := slog.New(slog.DiscardHandler)
	store := oci.NewStore(filepath.Join(runDir, cacheDirName, ociDirName), logger)
	_, err := oci.NewBuilder(store, logger, "").Build(context.Background(), testRef, dataDir, layers, 24*time.Hour)
	require.NoError(t, err)
	view, err := store.Inspect(context.Background(), testRef)
	require.NoError(t, err)
	return view
}

func TestNextHorizon(t *testing.T) {
	next := time.Date(2026, time.July, 17, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		nextUpdate string
		want       time.Time
	}{
		{name: "valid nextUpdate is used as is", nextUpdate: next.Format(time.RFC3339), want: next},
		{name: "missing nextUpdate counts as stale", nextUpdate: "", want: time.Time{}},
		{name: "malformed nextUpdate counts as stale", nextUpdate: "soon", want: time.Time{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := oci.ManifestView{Annotations: map[string]string{oci.AnnotationNextUpdate: test.nextUpdate}}
			assert.Equal(t, test.want, nextHorizon(view))
		})
	}
}
