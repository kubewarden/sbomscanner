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

	// Download decompresses the CSV; BuildSQLite turns it into the database.
	dbDir := t.TempDir()
	_, err := d.BuildSQLite(context.Background(), dir, dbDir)
	require.NoError(t, err)

	var entry EPSSEntry
	lookupJSON(t, filepath.Join(dbDir, EPSSDBFileName), "CVE-2021-44228", &entry)
	assert.Equal(t, EPSSEntry{EPSS: 0.97565, Percentile: 0.99992, Date: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)}, entry)
}

func TestEPSSDownloader_BuildSQLiteFailsOnInvalidPayload(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, EPSSSourceFileName), []byte("<html>error</html>"), 0o600))

	d := NewEPSSDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	_, err := d.BuildSQLite(context.Background(), dir, t.TempDir())
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
