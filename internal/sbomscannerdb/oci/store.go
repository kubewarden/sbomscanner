package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
)

// Store is the local artifact store, backed by an OCI image layout on disk.
type Store struct {
	dir    string
	logger *slog.Logger
}

// NewStore returns a Store rooted at dir. The layout is created lazily on first use.
func NewStore(dir string, logger *slog.Logger) *Store {
	return &Store{dir: dir, logger: logger}
}

// NewDefaultStore returns a Store rooted at the default location under the user cache directory
// ($XDG_CACHE_HOME/sbomscannerdb on Linux, ~/Library/Caches/sbomscannerdb on macOS).
func NewDefaultStore(logger *slog.Logger) (*Store, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user cache directory: %w", err)
	}
	return NewStore(filepath.Join(base, "sbomscannerdb"), logger), nil
}

// List returns the tagged artifacts in the store, in index order.
// A missing store yields an empty list.
func (s *Store) List() ([]Artifact, error) {
	indexPath := filepath.Join(s.dir, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read store index %s: %w", indexPath, err)
	}

	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse store index %s: %w", indexPath, err)
	}

	var artifacts []Artifact
	for _, manifest := range index.Manifests {
		ref := manifest.Annotations[ocispec.AnnotationRefName]
		if ref == "" {
			// Untagged (e.g. dangling) manifest entries are not listed.
			continue
		}
		artifacts = append(artifacts, Artifact{
			Ref:    ref,
			Digest: manifest.Digest.String(),
			Size:   manifest.Size,
		})
	}
	return artifacts, nil
}

// Inspect resolves ref in the local store and returns a view of its manifest.
func (s *Store) Inspect(ctx context.Context, ref string) (ManifestView, error) {
	layout, err := s.open()
	if err != nil {
		return ManifestView{}, err
	}
	if err := resolveLocal(ctx, layout, ref); err != nil {
		return ManifestView{}, err
	}

	desc, manifest, err := fetchManifest(ctx, layout, ref)
	if err != nil {
		return ManifestView{}, err
	}
	return newManifestView(ref, desc, manifest), nil
}

// Export writes the data files of the artifact at ref into outDir.
// It returns the written paths in layer order.
func (s *Store) Export(ctx context.Context, ref, outDir string) ([]string, error) {
	layout, err := s.open()
	if err != nil {
		return nil, err
	}
	if err := resolveLocal(ctx, layout, ref); err != nil {
		return nil, err
	}

	layerDescs, err := resolveDataLayers(ctx, layout, ref)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, layerDesc := range layerDescs {
		s.logger.InfoContext(ctx, "extracting data layer", "ref", ref, "layer", layerDesc.Annotations[ocispec.AnnotationTitle], "digest", layerDesc.Digest, "bytes", layerDesc.Size)
		extracted, err := fetchAndExtractLayer(ctx, layout, layerDesc, outDir)
		if err != nil {
			return nil, err
		}
		paths = append(paths, extracted...)
	}
	return paths, nil
}

// open opens (creating if needed) the OCI image layout backing the store.
func (s *Store) open() (*orasoci.Store, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory %s: %w", s.dir, err)
	}
	layout, err := orasoci.New(s.dir)
	if err != nil {
		return nil, fmt.Errorf("open store %s: %w", s.dir, err)
	}
	return layout, nil
}

// resolveLocal checks that ref exists in layout.
func resolveLocal(ctx context.Context, layout *orasoci.Store, ref string) error {
	if _, err := layout.Resolve(ctx, ref); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("%s not found in local store (run `build` or `pull` first)", ref)
		}
		return fmt.Errorf("resolve %s in local store: %w", ref, err)
	}
	return nil
}

// maxDecompressedLayerSize bounds how much a data layer may decompress to (256 MiB).
// The real feeds are about 10 MiB; the cap only guards against a
// decompression bomb served by a hostile registry.
const maxDecompressedLayerSize = 256 << 20

// fetchAndExtractLayer streams the tar.gz blob described by desc
// and writes each regular file it contains into outDir under its base name.
// It returns the written file paths.
func fetchAndExtractLayer(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor, outDir string) ([]string, error) {
	readCloser, err := fetcher.Fetch(ctx, desc)
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

// writeFileCapped writes at most limit bytes from reader into dst through a temp file
// in the same directory, so an existing dst is replaced and never followed.
// It fails if reader holds more than limit bytes.
func writeFileCapped(dst string, reader io.Reader, limit int64) (int64, error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".*")
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", dst, err)
	}
	tmp := tmpFile.Name()
	defer os.Remove(tmp)
	defer tmpFile.Close()

	written, err := io.Copy(tmpFile, io.LimitReader(reader, limit+1))
	if err != nil {
		return 0, fmt.Errorf("write %s: %w", dst, err)
	}
	if written > limit {
		return 0, fmt.Errorf("decompresses beyond %d bytes", maxDecompressedLayerSize)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("close %s: %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return 0, fmt.Errorf("rename %s: %w", dst, err)
	}
	return written, nil
}
