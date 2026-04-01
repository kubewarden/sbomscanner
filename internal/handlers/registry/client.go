package registry

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type ImageDetails struct {
	Digest   cranev1.Hash
	Layers   []cranev1.Layer
	History  []cranev1.History
	Platform cranev1.Platform
}

type ClientFactory func(http.RoundTripper) *Client

type Client struct {
	transport http.RoundTripper
	logger    *slog.Logger
}

func NewClient(transport http.RoundTripper, logger *slog.Logger) *Client {
	return &Client{
		transport: transport,
		logger:    logger.With("component", "registry_client"),
	}
}

func (c *Client) Catalog(ctx context.Context, registry name.Registry) ([]string, error) {
	c.logger.DebugContext(ctx, "Catalog called", "registry", registry)

	puller, err := remote.NewPuller(
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		return []string{}, fmt.Errorf("cannot create puller: %w", err)
	}

	catalogger, err := puller.Catalogger(ctx, registry)
	if err != nil {
		return []string{}, fmt.Errorf("cannot create catalogger for %s: %w", registry.Name(), err)
	}

	repositories := []string{}

	for catalogger.HasNext() {
		var repos *remote.Catalogs
		repos, err = catalogger.Next(ctx)
		if err != nil {
			return []string{}, fmt.Errorf("cannot iterate over repository %s contents: %w", registry.Name(), err)
		}
		for _, repo := range repos.Repos {
			repositories = append(repositories, path.Join(registry.Name(), repo))
		}
	}

	c.logger.DebugContext(ctx, "Repositories found",
		"registry", registry.Name(),
		"number", len(repositories),
		"repositories", repositories)

	return repositories, nil
}

func (c *Client) ListRepositoryContents(ctx context.Context, repo name.Repository) ([]string, error) {
	c.logger.DebugContext(ctx, "List repository contents", "repository", repo)

	puller, err := remote.NewPuller(
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		return []string{}, fmt.Errorf("cannot create puller: %w", err)
	}

	lister, err := puller.Lister(ctx, repo)
	if err != nil {
		return []string{}, fmt.Errorf("cannot create lister for repository %s: %w", repo, err)
	}

	images := []string{}
	for lister.HasNext() {
		var tags *remote.Tags
		tags, err = lister.Next(ctx)
		if err != nil {
			return []string{}, fmt.Errorf("cannot iterate over repository contents: %w", err)
		}
		for _, tag := range tags.Tags {
			images = append(images, repo.Tag(tag).String())
		}
	}

	c.logger.DebugContext(ctx, "Images found",
		"repository", repo.Name(),
		"number", len(images),
		"images", images)

	return images, nil
}

// GetDescriptor fetches the descriptor for a given reference.
func (c *Client) GetDescriptor(ctx context.Context, ref name.Reference) (*remote.Descriptor, error) {
	c.logger.DebugContext(ctx, "GetDescriptor called", "ref", ref.Name())

	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch descriptor for %q: %w", ref, err)
	}

	return desc, nil
}

// IsContainerImage checks if the descriptor represents an actual container image
// (as opposed to other OCI artifacts like Helm charts, signatures, attestations, etc.)
//
// Image indexes are considered container images. For single manifests, this method
// parses the manifest and checks if the config media type is a container image config.
func (c *Client) IsContainerImage(ctx context.Context, desc *remote.Descriptor) (bool, error) {
	// Image indexes are considered container images.
	// Individual manifests within the index will be validated when processing platforms.
	if desc.MediaType.IsIndex() {
		return true, nil
	}

	// Not a recognized manifest type
	if !desc.MediaType.IsImage() {
		c.logger.DebugContext(ctx, "Unknown manifest type", "mediaType", desc.MediaType)
		return false, nil
	}

	// For single manifests, we need to check the config media type.
	// OCI artifacts (Helm charts, signatures, etc.) use the same manifest schema
	// but have different config media types.
	manifest, err := cranev1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return false, fmt.Errorf("cannot parse manifest: %w", err)
	}

	return manifest.Config.MediaType.IsConfig(), nil
}

// imageDetails extracts config, digest, platform, and layers from a cranev1.Image.
// If platform is nil, it falls back to the platform from the image config file.
func imageDetails(img cranev1.Image, platform *cranev1.Platform, label string) (ImageDetails, error) {
	cfgFile, err := img.ConfigFile()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read config for %s: %w", label, err)
	}

	imageDigest, err := img.Digest()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot compute image digest for %s: %w", label, err)
	}

	// When no platform is provided (single-arch images or index entries without
	// an explicit platform), fall back to the platform from the config file.
	// Note: the config file does not contain the Variant field.
	if platform == nil {
		platform = cfgFile.Platform()
		if platform == nil {
			return ImageDetails{}, fmt.Errorf("cannot get platform for %s", label)
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read layers for %s: %w", label, err)
	}

	return ImageDetails{
		History:  cfgFile.History,
		Layers:   layers,
		Platform: *platform,
		Digest:   imageDigest,
	}, nil
}

// GetImageDetailsFromIndex fetches details for a specific image within a multi-arch index,
// identified by its digest.
func (c *Client) GetImageDetailsFromIndex(ctx context.Context, imageIndex cranev1.ImageIndex, digest cranev1.Hash, platform *cranev1.Platform) (ImageDetails, error) {
	c.logger.DebugContext(ctx, "GetImageDetailsFromIndex called", "digest", digest, "platform", platform)

	img, err := imageIndex.Image(digest)
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot get image by digest %s: %w", digest, err)
	}

	return imageDetails(img, platform, digest.String())
}

func (c *Client) GetImageDetails(ctx context.Context, ref name.Reference, multiArchPlatform *cranev1.Platform) (ImageDetails, error) {
	c.logger.DebugContext(ctx, "GetImageDetails called", "image", ref.Name(), "multiArchPlatform", multiArchPlatform)

	options := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	}
	if multiArchPlatform != nil {
		options = append(options, remote.WithPlatform(*multiArchPlatform))
	}

	img, err := remote.Image(ref, options...)
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot fetch image %q: %w", ref, err)
	}

	return imageDetails(img, multiArchPlatform, ref.Name())
}
