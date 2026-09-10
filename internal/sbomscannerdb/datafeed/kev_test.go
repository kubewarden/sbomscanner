package datafeed

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKEVDownloader_Download(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir("../../../test/fixtures")))
	t.Cleanup(srv.Close)
	dir := t.TempDir()

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/known_exploited_vulnerabilities.json"
	require.NoError(t, d.Download(context.Background(), dir))

	// Download fetches the JSON; BuildSQLite turns it into the database,
	// storing each entry as CISA published it.
	dbDir := t.TempDir()
	_, err := d.BuildSQLite(context.Background(), dir, dbDir)
	require.NoError(t, err)

	var entry KEVVulnerability
	lookupJSON(t, filepath.Join(dbDir, KEVDBFileName), "CVE-2021-44228", &entry)
	assert.Equal(t, "Apache", entry.VendorProject)
	assert.Equal(t, "Known", entry.KnownRansomwareCampaignUse)
}

func TestKEVDownloader_DownloadFailsOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir("../../../test/fixtures")))
	t.Cleanup(srv.Close)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/does-not-exist.json"
	require.Error(t, d.Download(context.Background(), t.TempDir()))
}

func TestKEVDownloader_BuildSQLiteFailsOnInvalidPayload(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, KEVSourceFileName), []byte("<html>error</html>"), 0o600))

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	_, err := d.BuildSQLite(context.Background(), dir, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate KEV")
}

func TestParseKEVCatalog_Failures(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"not JSON", "<html>error</html>"},
		{"empty vulnerabilities", `{"title":"KEV","count":0,"vulnerabilities":[]}`},
		{"missing cveID", `{"count":1,"vulnerabilities":[{"vendorProject":"Apache"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKEVCatalog(strings.NewReader(tt.input))
			require.Error(t, err)
		})
	}
}
