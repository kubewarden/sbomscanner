package registry

import (
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

func (c *Client) GetImageIndex(ref name.Reference) (cranev1.ImageIndex, error) {
	c.logger.Debug("GetImageIndex called", "image", ref.Name())

	index, err := remote.Index(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(c.transport),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch image index %q: %w", ref, err)
	}
	return index, nil
}

func (c *Client) GetImageDetails(ref name.Reference, platform *cranev1.Platform) (ImageDetails, error) {
	c.logger.Debug("GetImageDetails called", "image", ref.Name(), "platform", platform)

	options := []remote.Option{
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

	imageDigest, err := img.Digest()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot compute image digest %q: %w", ref, err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read config for %s: %w", ref, err)
	}

	// Single-arch images do not have a platform associated with them.
	// In that case, we get the platform from the config file.
	// Platform obtained from the config file does not have the Variant field set,
	// as the config file does not contain that information.
	if platform == nil {
		platform = cfgFile.Platform()
		if platform == nil {
			return ImageDetails{}, fmt.Errorf("cannot get platform for %s", ref)
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot read layers for %s: %w", ref, err)
	}

	return ImageDetails{
		History:  cfgFile.History,
		Layers:   layers,
		Platform: *platform,
		Digest:   imageDigest,
	}, nil
}
