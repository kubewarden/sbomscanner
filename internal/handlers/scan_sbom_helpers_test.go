package handlers

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/enrichment"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	enrichTestKEV = `{"title":"KEV","count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`
	//nolint:lll // csv fixture
	enrichTestEPSS = "#model_version:v1,score_date:2026-07-16T00:00:00Z\ncve,epss,percentile\nCVE-2021-44228,0.97,0.999\n"
)

func seededEnrichmentStore(t *testing.T) *enrichment.Store {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.KEVFileName), []byte(enrichTestKEV), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, datafeed.EPSSFileName), []byte(enrichTestEPSS), 0o600))
	// A far-future persisted horizon keeps Refresh from contacting any registry.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nextUpdate"), []byte("2999-01-01T00:00:00Z"), 0o600))
	return enrichment.New("registry.example.com/db:latest", dir, oci.Config{}, slog.New(slog.DiscardHandler))
}

func TestEnrichResults_PopulatesKEVAndEPSS(t *testing.T) {
	base := &scanSBOMBase{
		enrichmentStore: seededEnrichmentStore(t),
		logger:          slog.New(slog.DiscardHandler),
	}
	results := []storagev1alpha1.Result{
		{Vulnerabilities: []storagev1alpha1.Vulnerability{
			{CVE: "CVE-2021-44228"},
			{CVE: "CVE-0000-0000"},
		}},
	}

	base.enrichResults(context.Background(), results)

	exploited := results[0].Vulnerabilities[0]
	assert.True(t, exploited.KnownExploited)
	assert.Equal(t, "0.97", exploited.EPSSScore)
	assert.Equal(t, "0.999", exploited.EPSSPercentile)

	unknown := results[0].Vulnerabilities[1]
	assert.False(t, unknown.KnownExploited)
	assert.Empty(t, unknown.EPSSScore)
	assert.Empty(t, unknown.EPSSPercentile)
}

func TestEnrichResults_NilStoreLeavesResultsUnchanged(t *testing.T) {
	base := &scanSBOMBase{logger: slog.New(slog.DiscardHandler)}
	results := []storagev1alpha1.Result{
		{Vulnerabilities: []storagev1alpha1.Vulnerability{{CVE: "CVE-2021-44228"}}},
	}

	base.enrichResults(context.Background(), results)

	assert.False(t, results[0].Vulnerabilities[0].KnownExploited)
	assert.Empty(t, results[0].Vulnerabilities[0].EPSSScore)
}
