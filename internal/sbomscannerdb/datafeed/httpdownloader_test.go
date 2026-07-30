package datafeed

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPDownloader_DownloadPlain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,epss\nCVE-1,0.5\n"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "plain.csv")
	size, err := NewHTTPDownloader().Download(context.Background(), srv.URL, dst)
	require.NoError(t, err)

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "cve,epss\nCVE-1,0.5\n", string(data))
	assert.Equal(t, int64(len(data)), size)

	st, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}

func TestHTTPDownloader_DownloadGzipAutoDetected(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("decompressed content"))
	_ = gz.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "data.csv")
	size, err := NewHTTPDownloader().Download(context.Background(), srv.URL, dst)
	require.NoError(t, err)

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "decompressed content", string(data))
	assert.Equal(t, int64(len("decompressed content")), size)
}

func TestHTTPDownloader_DownloadHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "data.csv")
	_, err := NewHTTPDownloader().Download(context.Background(), srv.URL, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")

	// Neither the destination nor a temp sibling may be left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestHTTPDownloader_DownloadUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "x")
	_, err := NewHTTPDownloader().Download(context.Background(), srv.URL, dst)
	require.NoError(t, err)
	assert.Equal(t, userAgent, got)
}

func TestHTTPDownloader_DownloadContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "x")
	_, err := NewHTTPDownloader().Download(ctx, srv.URL, dst)
	require.Error(t, err)
}
