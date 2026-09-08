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

// testRef uses a reserved host, so every registry contact fails fast.
const testRef = "registry.invalid/kubewarden/sbomscannerdb:latest"

// seedFeeds writes a KEV catalog and an EPSS feed into dir.
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
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVFileName), kev, 0o600))

	var epss strings.Builder
	fmt.Fprintf(&epss, "#model_version:v2026.07.16,score_date:%s\n", scoreDate().Format(time.RFC3339))
	epss.WriteString("cve,epss,percentile\n")
	for _, score := range []datafeed.EPSSScore{
		{CVE: "CVE-2021-44228", EPSS: 0.97, Percentile: 0.999},
		{CVE: "CVE-2020-1234", EPSS: 0.01, Percentile: 0.5},
	} {
		fmt.Fprintf(&epss, "%s,%g,%g\n", score.CVE, score.EPSS, score.Percentile)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.EPSSFileName), []byte(epss.String()), 0o600))
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
		{Name: "kev", FileName: datafeed.KEVFileName, MediaType: oci.DataLayerMediaType("kev", "json")},
		{Name: "epss", FileName: datafeed.EPSSFileName, MediaType: oci.DataLayerMediaType("epss", "csv")},
	}
	logger := slog.New(slog.DiscardHandler)
	store := oci.NewStore(filepath.Join(runDir, cacheDirName, ociDirName), logger)
	built, err := oci.NewBuilder(store, logger, "").Build(context.Background(), testRef, dataDir, layers, interval)
	require.NoError(t, err)
	return built
}

func newTestDB(runDir string) *DB {
	return New(testRef, runDir, oci.Config{}, slog.New(slog.DiscardHandler))
}

func TestLookup_AfterUpdate(t *testing.T) {
	dir := t.TempDir()
	buildArtifact(t, dir, 24*time.Hour)
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	tests := []struct {
		name string
		cve  string
		want Record
	}{
		{
			name: "KEV and EPSS",
			cve:  "CVE-2021-44228",
			want: Record{
				KEV:  log4jKEV(),
				EPSS: &storagev1alpha1.EPSS{Score: "0.97", Percentile: "0.999", Date: metav1.NewTime(scoreDate())},
			},
		},
		{
			name: "KEV only",
			cve:  "CVE-2019-0708",
			want: Record{KEV: &storagev1alpha1.KEV{DateAdded: "2021-11-03", DueDate: "2022-05-03", KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUseUnknown}},
		},
		{
			name: "EPSS only",
			cve:  "CVE-2020-1234",
			want: Record{EPSS: &storagev1alpha1.EPSS{Score: "0.01", Percentile: "0.5", Date: metav1.NewTime(scoreDate())}},
		},
		{
			name: "unknown CVE",
			cve:  "CVE-0000-0000",
			want: Record{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, db.Lookup(test.cve))
		})
	}
}

func TestLookup_NilStoreIsNoOp(t *testing.T) {
	var db *DB
	assert.Equal(t, Record{}, db.Lookup("CVE-2021-44228"))
	assert.NoError(t, db.Update(context.Background()))
}

func TestUpdate_LoadsFromLocalStoreWhileFresh(t *testing.T) {
	dir := t.TempDir()
	built := buildArtifact(t, dir, 24*time.Hour)

	// The artifact is fresh for a day, so Update never contacts the registry.
	db := newTestDB(dir)
	require.NoError(t, db.Update(context.Background()))

	assert.Equal(t, built.Digest, db.loadedDigest())
	assert.Equal(t, log4jKEV(), db.Lookup("CVE-2021-44228").KEV)
	assert.FileExists(t, filepath.Join(dir, cacheDirName, datafeed.KEVFileName))
	assert.FileExists(t, filepath.Join(dir, cacheDirName, datafeed.EPSSFileName))
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), db.freshUntil(), time.Minute)
}

func TestUpdate_StaleLocalStoreFailsWhenRegistryUnreachable(t *testing.T) {
	dir := t.TempDir()
	built := buildArtifact(t, dir, time.Nanosecond)

	// The artifact is stale, so Update contacts the registry and fails.
	// The stale data stays loaded, and the horizon stays in the past.
	db := newTestDB(dir)
	require.Error(t, db.Update(context.Background()))

	assert.Equal(t, built.Digest, db.loadedDigest())
	assert.Equal(t, log4jKEV(), db.Lookup("CVE-2021-44228").KEV)
	assert.True(t, db.freshUntil().Before(time.Now()))
}

func TestUpdate_FailsWithoutLocalStore(t *testing.T) {
	dir := t.TempDir() // empty: no local store
	db := newTestDB(dir)

	// Nothing is loaded, so Update contacts the registry and fails.
	require.Error(t, db.Update(context.Background()))

	assert.Empty(t, db.loadedDigest())
	assert.Equal(t, Record{}, db.Lookup("CVE-2021-44228"))
}

func TestLoad_ToleratesSingleMissingFeed(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, cacheDirName)
	require.NoError(t, os.MkdirAll(cacheDir, 0o700))
	seedFeeds(t, cacheDir)
	require.NoError(t, os.Remove(filepath.Join(cacheDir, datafeed.EPSSFileName)))
	db := newTestDB(dir)
	require.NoError(t, db.load(context.Background()))

	assert.Equal(t, log4jKEV(), db.Lookup("CVE-2021-44228").KEV)
	assert.Nil(t, db.Lookup("CVE-2021-44228").EPSS)
}

func TestLoad_FailsWhenNoFeeds(t *testing.T) {
	db := newTestDB(t.TempDir())
	require.Error(t, db.load(context.Background()))
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
