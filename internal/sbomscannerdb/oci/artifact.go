package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
)

// Media types used by the DB artifact.
const (
	// ArtifactType identifies the sbomscanner DB artifact on the manifest.
	ArtifactType = "application/vnd.sbomscanner.db.v1+json"
	// LayerMediaTypeKEV is the media type of the KEV catalog tar.gz layer.
	LayerMediaTypeKEV = "application/vnd.sbomscanner.db.kev.layer.v1.tar+gzip"
	// LayerMediaTypeEPSS is the media type of the EPSS scores tar.gz layer.
	LayerMediaTypeEPSS = "application/vnd.sbomscanner.db.epss.layer.v1.tar+gzip"

	// epochCreated pins the manifest's created annotation to the Unix epoch
	// so that identical input files yield a byte-identical manifest (SOURCE_DATE_EPOCH convention).
	// A wall-clock time here would change the manifest digest on every run.
	epochCreated = "1970-01-01T00:00:00Z"
)

// isDataLayerMediaType reports whether mediaType is one of the DB data layers.
func isDataLayerMediaType(mediaType string) bool {
	return mediaType == LayerMediaTypeKEV || mediaType == LayerMediaTypeEPSS
}

// Layer describes one data file to pack as its own tar.gz layer.
// The tar envelope leaves room to add metadata entries alongside the data
// file in a future layer version.
type Layer struct {
	// Name is the short feed name (e.g. "kev");
	// the layer archive is titled Name+".tar.gz".
	Name string
	// FileName is the file's name within the data directory,
	// kept as its entry name inside the layer archive.
	FileName string
	// MediaType identifies the feed carried by the layer.
	MediaType string
}

// Artifact describes one DB artifact by reference.
type Artifact struct {
	Ref    string
	Digest string
	Size   int64
}

// Builder assembles DB artifacts into a local store.
type Builder struct {
	store  *Store
	logger *slog.Logger
}

// NewBuilder returns a Builder writing into the given store.
func NewBuilder(store *Store, logger *slog.Logger) *Builder {
	return &Builder{store: store, logger: logger}
}

// Build packs each data file from dataDir as its own tar.gz layer
// and tags the resulting DB artifact as ref in the store.
// Keeping one layer per feed means an unchanged feed keeps its blob digest
// across builds, so registries deduplicate it and consumers can fetch feeds
// selectively by media type.
func (b *Builder) Build(ctx context.Context, ref, dataDir string, layers []Layer) (Artifact, error) {
	layout, err := b.store.open()
	if err != nil {
		return Artifact{}, err
	}

	b.logger.InfoContext(ctx, "packing artifact", "ref", ref, "layers", len(layers))

	// Archive each data file into a temp dir before pushing;
	// descriptors need the final size and digest up front.
	tempDir, err := os.MkdirTemp("", "sbomscannerdb-layers-*")
	if err != nil {
		return Artifact{}, fmt.Errorf("create temp layer dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	layerDescs := make([]ocispec.Descriptor, 0, len(layers))
	for _, layer := range layers {
		archiveName := layer.Name + ".tar.gz"
		archivePath := filepath.Join(tempDir, archiveName)
		if err := writeTarGz(archivePath, dataDir, []string{layer.FileName}); err != nil {
			return Artifact{}, fmt.Errorf("archive %s: %w", layer.FileName, err)
		}
		desc, err := pushFileAsLayer(ctx, layout, archivePath, layer.MediaType, archiveName)
		if err != nil {
			return Artifact{}, fmt.Errorf("push layer %s: %w", archiveName, err)
		}
		b.logger.InfoContext(ctx, "packed layer", "file", layer.FileName, "mediaType", layer.MediaType, "digest", desc.Digest, "bytes", desc.Size)
		layerDescs = append(layerDescs, desc)
	}

	// Empty config blob — the DB artifactType lives on the manifest itself (OCI 1.1 style),
	// not on the config media type.
	emptyDesc, err := pushEmptyConfig(ctx, layout)
	if err != nil {
		return Artifact{}, fmt.Errorf("push empty config: %w", err)
	}

	manifestDesc, err := oras.PackManifest(
		ctx,
		layout,
		oras.PackManifestVersion1_1,
		ArtifactType,
		oras.PackManifestOptions{
			Layers:           layerDescs,
			ConfigDescriptor: &emptyDesc,
			ManifestAnnotations: map[string]string{
				// Pinned (not time.Now) so the manifest is reproducible;
				// oras honors a caller-provided created annotation.
				ocispec.AnnotationCreated: epochCreated,
			},
		},
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("pack manifest: %w", err)
	}

	if err := layout.Tag(ctx, manifestDesc, ref); err != nil {
		return Artifact{}, fmt.Errorf("tag %s: %w", ref, err)
	}
	b.logger.InfoContext(ctx, "tagged artifact", "ref", ref, "digest", manifestDesc.Digest)

	return Artifact{
		Ref:    ref,
		Digest: manifestDesc.Digest.String(),
		Size:   manifestDesc.Size,
	}, nil
}

// writeTarGz creates a tar.gz at archivePath containing the given files
// (read from dataDir, stored under their base names).
// Tar and gzip headers are normalized (zero mtime, fixed mode, no file name
// in the gzip header) so that identical input bytes always produce identical
// layer bytes.
func writeTarGz(archivePath, dataDir string, files []string) error {
	outFile, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("create %s: %w", archivePath, err)
	}
	defer outFile.Close()

	gzipWriter := gzip.NewWriter(outFile)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, name := range files {
		if err := addFileToTar(tarWriter, filepath.Join(dataDir, name), name); err != nil {
			return err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", archivePath, err)
	}
	return nil
}

// addFileToTar appends the regular, non-empty file at path to tarWriter
// under name with normalized metadata.
func addFileToTar(tarWriter *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if fileInfo.Size() == 0 {
		return fmt.Errorf("%s: empty file", path)
	}

	// Normalized header: fixed mode, zero timestamps, no owner info.
	header := &tar.Header{
		Name: name,
		Mode: 0o644,
		Size: fileInfo.Size(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}
	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("write tar entry %s: %w", name, err)
	}
	return nil
}

// pushFileAsLayer streams the file at path into the layout as a blob with the given media type.
// The title annotation records the layer archive name (e.g. kev.tar.gz),
// so that generic tools like `oras pull` write it under an honest file name.
func pushFileAsLayer(ctx context.Context, layout *orasoci.Store, path, mediaType, title string) (ocispec.Descriptor, error) {
	desc, err := descriptorFromFile(path, mediaType)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc.Annotations = map[string]string{
		ocispec.AnnotationTitle: title,
	}

	file, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	if err := layout.Push(ctx, desc, file); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", path, err)
	}
	return desc, nil
}

// pushEmptyConfig pushes the standard empty JSON config blob
// referenced by OCI 1.1 image manifests when there is no real config payload.
func pushEmptyConfig(ctx context.Context, layout *orasoci.Store) (ocispec.Descriptor, error) {
	desc := ocispec.DescriptorEmptyJSON
	if err := layout.Push(ctx, desc, bytes.NewReader(ocispec.DescriptorEmptyJSON.Data)); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, fmt.Errorf("push empty config blob: %w", err)
	}
	return desc, nil
}

// isAlreadyExists returns true when err (or any wrapped cause) is oras' "blob already exists" sentinel.
// Pushing a duplicate is not a real failure —
// content-addressed stores are idempotent on identical bytes.
func isAlreadyExists(err error) bool {
	return errors.Is(err, errdef.ErrAlreadyExists)
}
