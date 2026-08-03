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

	file, err := os.Open(filepath.Join(dir, KEVFileName))
	require.NoError(t, err)
	defer file.Close()

	catalog, err := ParseKEVCatalog(file)
	require.NoError(t, err)
	assert.Equal(t, 1, catalog.Count)
	require.Len(t, catalog.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2021-44228", catalog.Vulnerabilities[0].CVEID)
}

func TestKEVDownloader_DownloadFailsOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir("../../../test/fixtures")))
	t.Cleanup(srv.Close)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/does-not-exist.json"
	require.Error(t, d.Download(context.Background(), t.TempDir()))
}

func TestKEVDownloader_DownloadFailsOnInvalidPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Service temporarily unavailable</body></html>"))
	}))
	t.Cleanup(srv.Close)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/known_exploited_vulnerabilities.json"
	err := d.Download(context.Background(), t.TempDir())
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
