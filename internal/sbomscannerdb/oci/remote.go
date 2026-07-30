package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	orasremote "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const userAgent = "sbomscannerdb"

// Config controls how a Remote contacts registries.
type Config struct {
	// SkipTLSVerify disables TLS certificate verification.
	SkipTLSVerify bool
	// PlainHTTP uses HTTP instead of HTTPS.
	PlainHTTP bool
}

// Remote performs push and pull operations against OCI registries.
type Remote struct {
	config Config
	logger *slog.Logger
}

// NewRemote returns a Remote using the given configuration.
func NewRemote(config Config, logger *slog.Logger) *Remote {
	return &Remote{config: config, logger: logger}
}

// Push publishes the artifact tagged as ref in the given store
// to the remote registry identified by the same reference.
func (r *Remote) Push(ctx context.Context, store *Store, ref string) (Artifact, error) {
	dstRef, err := parseTagReference(ref)
	if err != nil {
		return Artifact{}, err
	}

	layout, err := store.open()
	if err != nil {
		return Artifact{}, err
	}
	if _, err := layout.Resolve(ctx, ref); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return Artifact{}, fmt.Errorf("%s not found in local store (run `build` first)", ref)
		}
		return Artifact{}, fmt.Errorf("resolve %s in local store: %w", ref, err)
	}

	repo, err := r.newRepository(dstRef)
	if err != nil {
		return Artifact{}, err
	}

	// oras.Copy resolves the tag in the source, walks the graph,
	// and pushes missing blobs/manifests to the destination.
	// Progress hooks log each blob/manifest as it lands.
	copyOpts := oras.DefaultCopyOptions
	copyOpts.PreCopy = func(_ context.Context, desc ocispec.Descriptor) error {
		r.logger.InfoContext(ctx, "pushing blob", "mediaType", desc.MediaType, "digest", desc.Digest, "bytes", desc.Size)
		return nil
	}
	copyOpts.OnCopySkipped = func(_ context.Context, desc ocispec.Descriptor) error {
		r.logger.DebugContext(ctx, "skipped blob, already present", "mediaType", desc.MediaType, "digest", desc.Digest)
		return nil
	}

	pushedDesc, err := oras.Copy(ctx, layout, ref, repo, dstRef.Reference, copyOpts)
	if err != nil {
		return Artifact{}, fmt.Errorf("copy to remote: %w", err)
	}
	r.logger.InfoContext(ctx, "pushed artifact", "ref", dstRef.String(), "digest", pushedDesc.Digest)

	return Artifact{
		Ref:    ref,
		Digest: pushedDesc.Digest.String(),
		Size:   pushedDesc.Size,
	}, nil
}

// Pull fetches the DB artifact at the given tag reference,
// extracts each data layer (a tar.gz), and writes the contained files
// (e.g. known_exploited_vulnerabilities.json, epss_scores.csv) into outDir.
// It returns the written file paths in manifest layer order.
func (r *Remote) Pull(ctx context.Context, ref, outDir string) ([]string, error) {
	srcRef, err := parseTagReference(ref)
	if err != nil {
		return nil, err
	}

	repo, err := r.newRepository(srcRef)
	if err != nil {
		return nil, err
	}

	layerDescs, err := r.resolveDataLayers(ctx, repo, srcRef.Reference)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, layerDesc := range layerDescs {
		r.logger.InfoContext(ctx, "pulling data layer", "ref", srcRef.String(), "layer", layerDesc.Annotations[ocispec.AnnotationTitle], "digest", layerDesc.Digest, "bytes", layerDesc.Size)
		extracted, err := fetchAndExtractLayer(ctx, repo, layerDesc, outDir)
		if err != nil {
			return nil, err
		}
		paths = append(paths, extracted...)
	}
	return paths, nil
}

// resolveDataLayers fetches the manifest at tag
// and returns the descriptors of the DB data layers, located by media type.
func (r *Remote) resolveDataLayers(ctx context.Context, repo *orasremote.Repository, tag string) ([]ocispec.Descriptor, error) {
	manifestDesc, manifestBytes, err := oras.FetchBytes(ctx, repo, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", manifestDesc.Digest, err)
	}

	var layers []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if isDataLayerMediaType(layer.MediaType) {
			layers = append(layers, layer)
		}
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("no DB data layers in manifest %s", manifestDesc.Digest)
	}
	return layers, nil
}

// newRepository builds an authenticated remote repository client for ref.
func (r *Remote) newRepository(ref registry.Reference) (*orasremote.Repository, error) {
	if err := requireDockerConfig(); err != nil {
		return nil, err
	}
	credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("load docker config: %w", err)
	}

	repo, err := orasremote.NewRepository(ref.String())
	if err != nil {
		return nil, fmt.Errorf("build remote client: %w", err)
	}
	repo.PlainHTTP = r.config.PlainHTTP
	repo.Client = buildAuthClient(credStore, r.config.SkipTLSVerify)
	return repo, nil
}

// maxDecompressedLayerSize bounds how much a data layer may decompress to (1 GiB).
// The real feeds are tens of MB; the cap only guards against a
// decompression bomb served by a hostile registry.
const maxDecompressedLayerSize = 1 << 30

// fetchAndExtractLayer streams the tar.gz blob described by desc
// and writes each regular file it contains into outDir under its base name.
// It returns the written file paths.
func fetchAndExtractLayer(ctx context.Context, repo *orasremote.Repository, desc ocispec.Descriptor, outDir string) ([]string, error) {
	readCloser, err := repo.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch blob %s: %w", desc.Digest, err)
	}
	defer readCloser.Close()

	gzipReader, err := gzip.NewReader(io.LimitReader(readCloser, desc.Size))
	if err != nil {
		return nil, fmt.Errorf("decompress blob %s: %w", desc.Digest, err)
	}
	tarReader := tar.NewReader(gzipReader)

	var paths []string
	remaining := int64(maxDecompressedLayerSize)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar in blob %s: %w", desc.Digest, err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Base strips any path components a hostile archive could smuggle in.
		dst := filepath.Join(outDir, filepath.Base(header.Name))
		written, err := writeFileCapped(dst, tarReader, remaining)
		if err != nil {
			return nil, fmt.Errorf("extract %s from blob %s: %w", header.Name, desc.Digest, err)
		}
		remaining -= written
		paths = append(paths, dst)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no files in layer %s", desc.Digest)
	}
	return paths, nil
}

// writeFileCapped writes at most limit bytes from reader into dst,
// failing (and removing dst) if reader holds more.
func writeFileCapped(dst string, reader io.Reader, limit int64) (int64, error) {
	outFile, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", dst, err)
	}
	defer outFile.Close()

	written, err := io.Copy(outFile, io.LimitReader(reader, limit+1))
	if err != nil {
		_ = os.Remove(dst)
		return 0, fmt.Errorf("write %s: %w", dst, err)
	}
	if written > limit {
		_ = os.Remove(dst)
		return 0, fmt.Errorf("decompresses beyond %d bytes", maxDecompressedLayerSize)
	}
	if err := outFile.Close(); err != nil {
		return 0, fmt.Errorf("close %s: %w", dst, err)
	}
	return written, nil
}

// parseTagReference parses ref and requires it to be a tag (not digest) reference.
func parseTagReference(ref string) (registry.Reference, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	if err := parsed.ValidateReferenceAsTag(); err != nil {
		return registry.Reference{}, fmt.Errorf("reference must be a tag (not a digest): %w", err)
	}
	return parsed, nil
}

// requireDockerConfig checks that a docker config.json exists
// at either $DOCKER_CONFIG/config.json or ~/.docker/config.json.
// We don't want the operation to proceed anonymously if the file is absent.
func requireDockerConfig() error {
	// Mirror the resolution NewStoreFromDocker does internally.
	if dc := os.Getenv("DOCKER_CONFIG"); dc != "" {
		p := filepath.Clean(filepath.Join(dc, "config.json"))
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("docker config not found at %s: %w", p, err)
		}
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	p := filepath.Join(home, ".docker", "config.json")
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("docker config not found at %s: %w", p, err)
	}
	return nil
}

// buildAuthClient wires the credentials store
// into an auth.Client backed by a retry-capable transport.
// TLS verification is toggled by skipTLS.
func buildAuthClient(credStore credentials.Store, skipTLS bool) *auth.Client {
	// Transport: reuse retry.Transport (which wraps http.DefaultTransport)
	// so that we inherit the sensible retry/backoff defaults.
	// When skipTLS is set we build our own base transport with InsecureSkipVerify.
	baseTransport := http.DefaultTransport
	if skipTLS {
		baseTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in by --skip-tls-verify
		}
	}

	client := &auth.Client{
		Client:     &http.Client{Transport: retry.NewTransport(baseTransport)},
		Credential: credentials.Credential(credStore),
	}
	client.SetUserAgent(userAgent)
	return client
}
