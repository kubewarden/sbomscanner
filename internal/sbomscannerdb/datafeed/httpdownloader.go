package datafeed

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	userAgent = "sbomscannerdb"

	// fileMode is applied to every downloaded file regardless of umask.
	fileMode os.FileMode = 0o600

	// 30s applies to dial + response-header wait.
	// Body reads stream freely and only unblock on ctx cancellation (Ctrl+C) or network error.
	dialTimeout           = 30 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// HTTPDownloader downloads files over HTTP with atomic on-disk writes
// and optional on-the-fly gzip decompression.
type HTTPDownloader struct {
	client *http.Client
}

// NewHTTPDownloader returns a downloader with 30s dial and response-header timeouts
// and unbounded body reads (interruptible via request context).
// The Transport is built explicitly rather than mutating [http.DefaultTransport].
func NewHTTPDownloader() *HTTPDownloader {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	// No client-level Timeout: we don't want to cap total request duration,
	// only dial + response-header.
	// Body reads are bounded by ctx.
	return &HTTPDownloader{client: &http.Client{Transport: transport}}
}

// Download streams url into dst atomically: bytes go to a per-pid ".tmp.<pid>" sibling
// that is renamed into place on success and removed on any failure.
// Gzipped payloads are detected by their magic bytes and decompressed on the fly.
//
// It returns the final on-disk size (post-decompression for gzipped payloads).
func (d *HTTPDownloader) Download(ctx context.Context, url, dst string) (int64, error) {
	tmp := tmpPath(dst)

	// Best-effort cleanup: if we return without a successful rename, drop the partial.
	// This also fires on Ctrl+C via the ctx path below.
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()

	resp, err := d.doRequest(ctx, url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	written, err := writeStream(resp.Body, tmp)
	if err != nil {
		return 0, err
	}

	// Ensure exact 0600 regardless of umask.
	if err := os.Chmod(tmp, fileMode); err != nil {
		return 0, fmt.Errorf("chmod %s: %w", tmp, err)
	}

	// Atomic rename lands the file in its final place.
	if err := os.Rename(tmp, dst); err != nil {
		return 0, fmt.Errorf("rename %s -> %s: %w", tmp, dst, err)
	}
	renamed = true
	return written, nil
}

// doRequest issues the GET and validates the response status.
func (d *HTTPDownloader) doRequest(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include a snippet of the body to make CDN errors debuggable.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %s: %s", resp.Status, string(snippet))
	}
	return resp, nil
}

// writeStream copies src into tmp,
// transparently decompressing gzipped payloads
// (detected by the 0x1f 0x8b magic bytes at the stream start).
func writeStream(src io.Reader, tmp string) (int64, error) {
	tmpFile, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return 0, fmt.Errorf("open temp %s: %w", tmp, err)
	}

	reader, gzipReader, err := maybeGunzip(src)
	if err != nil {
		_ = tmpFile.Close()
		return 0, err
	}

	written, copyErr := io.Copy(tmpFile, reader)
	if gzipReader != nil {
		_ = gzipReader.Close()
	}
	if closeErr := tmpFile.Close(); closeErr != nil && copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return 0, fmt.Errorf("write %s: %w", tmp, copyErr)
	}
	return written, nil
}

// maybeGunzip peeks at the first two bytes of src;
// if they match the gzip magic it returns a decompressing reader (and the [gzip.Reader] to close),
// otherwise the buffered stream is returned as is.
func maybeGunzip(src io.Reader) (io.Reader, *gzip.Reader, error) {
	buffered := bufio.NewReader(src)
	magic, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("peek stream: %w", err)
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, nil, fmt.Errorf("open gzip: %w", err)
		}
		return gzipReader, gzipReader, nil
	}
	return buffered, nil, nil
}

// tmpPath returns the per-pid tmp sibling for dst.
// The per-pid suffix prevents two concurrent runs from racing on the same partial file.
func tmpPath(dst string) string {
	return dst + ".tmp." + strconv.Itoa(os.Getpid())
}
