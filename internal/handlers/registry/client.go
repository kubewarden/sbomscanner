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
	Digest      cranev1.Hash
	IndexDigest cranev1.Hash
	Layers      []cranev1.Layer
	History     []cranev1.History
	Platform    cranev1.Platform
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

func (c *Client) GetImageIndex(ctx context.Context, ref name.Reference) (cranev1.ImageIndex, error) {
	c.logger.DebugContext(ctx, "GetImageIndex called", "image", ref.Name())

	index, err := remote.Index(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch image index %q: %w", ref, err)
	}
	return index, nil
}

func (c *Client) GetImageDetails(ctx context.Context, ref name.Reference, platform *cranev1.Platform) (ImageDetails, error) {
	c.logger.DebugContext(ctx, "GetImageDetails called", "image", ref.Name(), "platform", platform)

	options := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	}
	if platform != nil {
		options = append(options, remote.WithPlatform(*platform))
	}

	img, err := remote.Image(ref, options...)
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot fetch image %q: %w", ref, err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read config for %s: %w", ref, err)
	}

	imageDigest, err := img.Digest()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot compute image digest %q: %w", ref, err)
	}

	var indexDigest cranev1.Hash
	// Single-arch images do not have a platform associated with them.
	// In that case, we get the platform from the config file.
	// Platform obtained from the config file does not have the Variant field set,
	// as the config file does not contain that information.
	if platform == nil {
		platform = cfgFile.Platform()
		if platform == nil {
			return ImageDetails{}, fmt.Errorf("cannot get platform for %s", ref)
		}
	} else {
		imageIndex, err := c.GetImageIndex(ref)
		if err != nil {
			return ImageDetails{}, fmt.Errorf("cannot get index for %s: %w", ref, err)
		}

		indexDigest, err = imageIndex.Digest()
		if err != nil {
			return ImageDetails{}, fmt.Errorf("cannot compute index digest %q: %w", ref, err)
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read layers for %s: %w", ref, err)
	}

	return ImageDetails{
		History:     cfgFile.History,
		Layers:      layers,
		Platform:    *platform,
		Digest:      imageDigest,
		IndexDigest: indexDigest,
	}, nil
}
