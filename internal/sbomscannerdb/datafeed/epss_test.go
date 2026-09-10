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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEPSSDownloader_Download(t *testing.T) {
	srv := httptest.NewServer(http.FileServer(http.Dir("../../../test/fixtures")))
	t.Cleanup(srv.Close)
	dir := t.TempDir()

	d := NewEPSSDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/epss_scores.csv.gz"
	require.NoError(t, d.Download(context.Background(), dir))

	// The gzipped fixture must land decompressed under the plain CSV name.
	file, err := os.Open(filepath.Join(dir, EPSSFileName))
	require.NoError(t, err)
	defer file.Close()

	scores, err := ParseEPSSScores(file)
	require.NoError(t, err)
	assert.Equal(t, "v2026.06.15", scores.ModelVersion)
	assert.Equal(t, time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC), scores.ScoreDate)
	require.Len(t, scores.Scores, 1)
	assert.Equal(t, EPSSScore{CVE: "CVE-2021-44228", EPSS: 0.97565, Percentile: 0.99992}, scores.Scores[0])
}

func TestEPSSDownloader_DownloadFailsOnInvalidPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Service temporarily unavailable</body></html>"))
	}))
	t.Cleanup(srv.Close)

	d := NewEPSSDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/epss_scores-current.csv.gz"
	err := d.Download(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate EPSS")
}

func TestParseEPSSScores(t *testing.T) {
	const header = "#model_version:v1,score_date:2026-07-12T12:00:00Z\n"
	tests := []struct {
		name    string
		input   string
		want    *EPSSScores
		wantErr bool
	}{
		{
			name:  "valid feed",
			input: header + "cve,epss,percentile\nCVE-2021-44228,0.97565,0.99992\n",
			want: &EPSSScores{
				ModelVersion: "v1",
				ScoreDate:    time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
				Scores:       []EPSSScore{{CVE: "CVE-2021-44228", EPSS: 0.97565, Percentile: 0.99992}},
			},
		},
		{name: "not CSV", input: "<html>error</html>", wantErr: true},
		{name: "no metadata line", input: "cve,epss,percentile\nCVE-2021-44228,0.9,0.9\n", wantErr: true},
		{name: "no score_date", input: "#model_version:v1\ncve,epss,percentile\nCVE-2021-44228,0.9,0.9\n", wantErr: true},
		{name: "wrong header", input: header + "id,score,rank\nCVE-2021-44228,0.9,0.9\n", wantErr: true},
		{name: "no rows", input: header + "cve,epss,percentile\n", wantErr: true},
		{name: "empty cve", input: header + "cve,epss,percentile\n,0.9,0.9\n", wantErr: true},
		{name: "wrong field count", input: header + "cve,epss,percentile\nCVE-2021-44228,0.9\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseEPSSScores(strings.NewReader(test.input))
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
