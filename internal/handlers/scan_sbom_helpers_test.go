package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testDBRepository uses a reserved host, so every registry contact fails fast.
const testDBRepository = "registry.invalid/kubewarden/sbomscannerdb"

// testDBRef is the reference that sbomscannerdb.Open builds from testDBRepository.
const testDBRef = testDBRepository + ":1"

// seedFeeds writes the KEV and EPSS databases with CVE-2021-44228 into dir,
// converted from upstream feeds the same way build does.
func seedFeeds(t *testing.T, dir string) {
	t.Helper()
	kev, err := json.Marshal(datafeed.KEVCatalog{
		Title: "CISA KEV",
		Count: 1,
		Vulnerabilities: []datafeed.KEVVulnerability{
			{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareCampaignUse: "Known"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVSourceFileName), kev, 0o600))

	score := datafeed.EPSSScore{CVE: "CVE-2021-44228", EPSS: 0.97, Percentile: 0.999}
	epss := "#model_version:v1,score_date:" + scoreDate().Format(time.RFC3339) + "\n" +
		"cve,epss,percentile\n" +
		fmt.Sprintf("%s,%g,%g\n", score.CVE, score.EPSS, score.Percentile)
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.EPSSSourceFileName), []byte(epss), 0o600))

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

// seededDB returns a DB whose local store holds a fresh artifact,
// so Update never contacts the registry.
func seededDB(t *testing.T) *sbomscannerdb.DB {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	dataDir := t.TempDir()
	seedFeeds(t, dataDir)
	layers := []oci.Layer{
		{Name: "kev", FileName: datafeed.KEVDBFileName, MediaType: oci.DataLayerMediaType("kev")},
		{Name: "epss", FileName: datafeed.EPSSDBFileName, MediaType: oci.DataLayerMediaType("epss")},
	}

	runDir := t.TempDir()
	localStore := oci.NewStore(filepath.Join(runDir, "sbomscannerdb", "oci"), logger)
	_, err := oci.NewBuilder(localStore, logger, "").Build(context.Background(), testDBRef, dataDir, layers, 24*time.Hour)
	require.NoError(t, err)
	return sbomscannerdb.Open(testDBRepository, runDir, oci.Config{}, logger)
}

func TestEnrichResults_PopulatesKEVAndEPSS(t *testing.T) {
	base := &scanSBOMBase{
		sbomscannerDB: seededDB(t),
		logger:        slog.New(slog.DiscardHandler),
	}
	results := []storagev1alpha1.Result{
		{Vulnerabilities: []storagev1alpha1.Vulnerability{
			{CVE: "CVE-2021-44228"},
			{CVE: "CVE-0000-0000"},
		}},
	}

	require.NoError(t, base.enrichResults(context.Background(), results))

	exploited := results[0].Vulnerabilities[0]
	assert.Equal(t, &storagev1alpha1.KEV{DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareCampaignUse: storagev1alpha1.RansomwareCampaignUseKnown}, exploited.KEV)
	assert.Equal(t, &storagev1alpha1.EPSS{Score: "0.97", Percentile: "0.999", Date: metav1.NewTime(scoreDate())}, exploited.EPSS)

	unknown := results[0].Vulnerabilities[1]
	assert.Nil(t, unknown.KEV)
	assert.Nil(t, unknown.EPSS)
}

func TestEnrichResults_NilStoreLeavesResultsUnchanged(t *testing.T) {
	base := &scanSBOMBase{logger: slog.New(slog.DiscardHandler)}
	results := []storagev1alpha1.Result{
		{Vulnerabilities: []storagev1alpha1.Vulnerability{{CVE: "CVE-2021-44228"}}},
	}

	require.NoError(t, base.enrichResults(context.Background(), results))

	assert.Nil(t, results[0].Vulnerabilities[0].KEV)
	assert.Nil(t, results[0].Vulnerabilities[0].EPSS)
}

func TestEnrichResults_FailsWhenDBCannotUpdate(t *testing.T) {
	// An empty run dir and an unreachable registry, so the DB cannot be updated.
	base := &scanSBOMBase{
		sbomscannerDB: sbomscannerdb.Open(testDBRepository, t.TempDir(), oci.Config{}, slog.New(slog.DiscardHandler)),
		logger:        slog.New(slog.DiscardHandler),
	}
	results := []storagev1alpha1.Result{
		{Vulnerabilities: []storagev1alpha1.Vulnerability{{CVE: "CVE-2021-44228"}}},
	}

	require.Error(t, base.enrichResults(context.Background(), results))

	assert.Nil(t, results[0].Vulnerabilities[0].KEV)
	assert.Nil(t, results[0].Vulnerabilities[0].EPSS)
}
