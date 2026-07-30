package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	orasoci "oras.land/oras-go/v2/content/oci"
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
