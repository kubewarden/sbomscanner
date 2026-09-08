package oci

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
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
	if err := resolveLocal(ctx, layout, ref); err != nil {
		return Artifact{}, err
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

// Pull copies the artifact at ref from the registry into store, under the same reference.
// Blobs that the store already holds are not downloaded again.
func (r *Remote) Pull(ctx context.Context, store *Store, ref string) (Artifact, error) {
	srcRef, err := parseTagReference(ref)
	if err != nil {
		return Artifact{}, err
	}

	repo, err := r.newRepository(srcRef)
	if err != nil {
		return Artifact{}, err
	}

	layout, err := store.open()
	if err != nil {
		return Artifact{}, err
	}

	// PreCopy and OnCopySkipped run concurrently, so the counters must be atomic.
	var fetched, skipped atomic.Int64
	copyOpts := oras.DefaultCopyOptions
	copyOpts.PreCopy = func(_ context.Context, desc ocispec.Descriptor) error {
		fetched.Add(1)
		r.logger.InfoContext(ctx, "fetching blob", "mediaType", desc.MediaType, "digest", desc.Digest, "bytes", desc.Size)
		return nil
	}
	copyOpts.OnCopySkipped = func(_ context.Context, desc ocispec.Descriptor) error {
		skipped.Add(1)
		r.logger.DebugContext(ctx, "skipped blob, already in local store", "mediaType", desc.MediaType, "digest", desc.Digest)
		return nil
	}
	pulledDesc, err := oras.Copy(ctx, repo, srcRef.Reference, layout, ref, copyOpts)
	if err != nil {
		return Artifact{}, fmt.Errorf("copy from remote: %w", err)
	}
	if fetched.Load() == 0 {
		r.logger.InfoContext(ctx, "artifact unchanged, already in local store", "ref", srcRef.String(), "digest", pulledDesc.Digest, "cachedBlobs", skipped.Load())
	} else {
		r.logger.InfoContext(ctx, "pulled artifact", "ref", srcRef.String(), "digest", pulledDesc.Digest, "fetchedBlobs", fetched.Load(), "cachedBlobs", skipped.Load())
	}

	return Artifact{
		Ref:    ref,
		Digest: pulledDesc.Digest.String(),
		Size:   pulledDesc.Size,
	}, nil
}

// resolveDataLayers fetches the manifest at tag from target
// and returns the descriptors of the DB data layers, located by media type.
func resolveDataLayers(ctx context.Context, target oras.ReadOnlyTarget, tag string) ([]ocispec.Descriptor, error) {
	_, manifest, err := fetchManifest(ctx, target, tag)
	if err != nil {
		return nil, err
	}

	var layers []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if isDataLayerMediaType(layer.MediaType) {
			layers = append(layers, layer)
		}
	}
	if len(layers) == 0 {
		return nil, errors.New("no DB data layers in manifest")
	}
	return layers, nil
}

// Inspect fetches the manifest at the given tag reference from the remote
// registry and returns a view of its metadata (media types, layers, annotations).
func (r *Remote) Inspect(ctx context.Context, ref string) (ManifestView, error) {
	srcRef, err := parseTagReference(ref)
	if err != nil {
		return ManifestView{}, err
	}

	repo, err := r.newRepository(srcRef)
	if err != nil {
		return ManifestView{}, err
	}

	desc, manifest, err := fetchManifest(ctx, repo, srcRef.Reference)
	if err != nil {
		return ManifestView{}, err
	}
	return newManifestView(ref, desc, manifest), nil
}

// fetchManifest resolves tag against fetcher and returns the manifest descriptor
// and its parsed content.
func fetchManifest(ctx context.Context, target oras.ReadOnlyTarget, tag string) (ocispec.Descriptor, ocispec.Manifest, error) {
	manifestDesc, manifestBytes, err := oras.FetchBytes(ctx, target, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, ocispec.Manifest{}, fmt.Errorf("parse manifest %s: %w", manifestDesc.Digest, err)
	}
	return manifestDesc, manifest, nil
}

// newRepository builds a registry client for ref.
// It uses the docker config.json when one exists, otherwise requests are anonymous.
func (r *Remote) newRepository(ref registry.Reference) (*orasremote.Repository, error) {
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
