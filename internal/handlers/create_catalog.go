package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"

	"github.com/google/go-containerregistry/pkg/name"
	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	storagev1alpha1 "github.com/rancher/sbombastic/api/storage/v1alpha1"
	"github.com/rancher/sbombastic/api/v1alpha1"
	registryclient "github.com/rancher/sbombastic/internal/handlers/registry"
	"github.com/rancher/sbombastic/internal/messaging"
)

// CreateCatalogHandler is a handler for creating a catalog of images in a registry.
type CreateCatalogHandler struct {
	registryClientFactory registryclient.ClientFactory
	k8sClient             client.Client
	scheme                *runtime.Scheme
	logger                *slog.Logger
}

func NewCreateCatalogHandler(registryClientFactory registryclient.ClientFactory, k8sClient client.Client, scheme *runtime.Scheme, logger *slog.Logger) *CreateCatalogHandler {
	return &CreateCatalogHandler{
		registryClientFactory: registryClientFactory,
		k8sClient:             k8sClient,
		scheme:                scheme,
		logger:                logger.With("handler", "create_catalog_handler"),
	}
}

func (h *CreateCatalogHandler) Handle(message messaging.Message) error {
	createCatalogMessage, ok := message.(*messaging.CreateCatalog)
	if !ok {
		return fmt.Errorf("unexpected message type: %T", message)
	}

	h.logger.Debug("Catalog creation requested",
		"registry", createCatalogMessage.RegistryName,
		"namespace", createCatalogMessage.RegistryNamespace,
	)

	ctx := context.Background()

	registry := &v1alpha1.Registry{}
	err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      createCatalogMessage.RegistryName,
		Namespace: createCatalogMessage.RegistryNamespace,
	}, registry)
	if err != nil {
		return fmt.Errorf("cannot get registry %s/%s: %w", createCatalogMessage.RegistryNamespace, createCatalogMessage.RegistryName, err)
	}

	h.logger.Debug("Registry found", "registry", registry)

	transport, err := h.transportFromRegistry(registry)
	if err != nil {
		return fmt.Errorf("cannot create transport for registry %s: %w", registry.Name, err)
	}
	registryClient := h.registryClientFactory(transport)

	repositories, err := h.discoverRepositories(ctx, registryClient, registry)
	if err != nil {
		return fmt.Errorf("cannot discover repositories: %w", err)
	}

	discoveredImageNames := sets.Set[string]{}
	for _, repository := range repositories {
		repoImages, err := h.discoverImages(ctx, registryClient, repository)
		if err != nil {
			return fmt.Errorf("cannot discover images in registry %s: %w", registry.Name, err)
		}
		discoveredImageNames.Insert(repoImages...)
	}

	existingImageList := &storagev1alpha1.ImageList{}
	if err := h.k8sClient.List(ctx, existingImageList, client.InNamespace(registry.Namespace), client.MatchingLabels{"registry": registry.Name}); err != nil {
		return fmt.Errorf("cannot list existing images in registry %s: %w", registry.Name, err)
	}
	existingImageNames := sets.Set[string]{}
	for _, existingImage := range existingImageList.Items {
		existingImageNames.Insert(existingImage.Name)
	}

	for newImageName := range discoveredImageNames {
		ref, err := name.ParseReference(newImageName)
		if err != nil {
			return fmt.Errorf("cannot parse reference %s: %w", newImageName, err)
		}

		images, err := h.refToImages(registryClient, ref, registry)
		if err != nil {
			h.logger.Error("Error cannot get images for ref", "ref", ref, "error", err)
			// Avoid blocking other images to be cataloged
			continue
		}

		for _, image := range images {
			if existingImageNames.Has(image.Name) {
				continue
			}

			if err := h.k8sClient.Create(ctx, &image); err != nil {
				return fmt.Errorf("cannot create image %s: %w", image.Name, err)
			}
		}
	}

	if err := h.deleteObsoleteImages(ctx, existingImageNames, discoveredImageNames, registry.Namespace); err != nil {
		return fmt.Errorf("cannot delete obsolete images in registry %s: %w", registry.Name, err)
	}

	return nil
}

func (h *CreateCatalogHandler) NewMessage() messaging.Message {
	return &messaging.CreateCatalog{}
}

// discoverRepositories discovers all the repositories in a registry.
// Returns the list of fully qualified repository names (e.g. registryclientexample.com/repo)
func (h *CreateCatalogHandler) discoverRepositories(ctx context.Context, registryClient registryclient.Client, registry *v1alpha1.Registry) ([]string, error) {
	reg, err := name.NewRegistry(registry.Spec.URI)
	if err != nil {
		return nil, fmt.Errorf("cannot parse registry %s %s: %w", registry.Name, registry.Namespace, err)
	}

	// If the registry doesn't have any repositories defined, it means we need to catalog all of them.
	// In this case, we need to discover all the repositories in the registry.
	if len(registry.Spec.Repositories) == 0 {
		allRepositories, err := registryClient.Catalog(ctx, reg)
		if err != nil {
			return []string{}, fmt.Errorf("cannot discover repositories: %w", err)
		}

		return allRepositories, nil
	}

	repositories := []string{}
	for _, repository := range registry.Spec.Repositories {
		repositories = append(repositories, path.Join(reg.Name(), repository))
	}

	return repositories, nil
}

// discoverImages discovers all the images defined inside of a repository.
// Returns the list of fully qualified image names (e.g. registryclientexample.com/repo:tag)
func (h *CreateCatalogHandler) discoverImages(ctx context.Context, registryClient registryclient.Client, repository string) ([]string, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return []string{}, fmt.Errorf("cannot parse repository name %q: %w", repository, err)
	}

	contents, err := registryClient.ListRepositoryContents(ctx, repo)
	if err != nil {
		return []string{}, fmt.Errorf("cannot list repository contents: %w", err)
	}

	return contents, nil
}

func (h *CreateCatalogHandler) refToImages(registryClient registryclient.Client, ref name.Reference, registry *v1alpha1.Registry) ([]storagev1alpha1.Image, error) {
	platforms, err := h.refToPlatforms(registryClient, ref)
	if err != nil {
		return []storagev1alpha1.Image{}, fmt.Errorf("cannot get platforms for %s: %w", ref, err)
	}
	if platforms == nil {
		// add a `nil` platform to the list of platforms, this will be used to get the default platform
		platforms = append(platforms, nil)
	}

	images := []storagev1alpha1.Image{}

	for _, platform := range platforms {
		imageDetails, err := registryClient.GetImageDetails(ref, platform)
		if err != nil {
			platformStr := "default"
			if platform != nil {
				platformStr = platform.String()
			}

			return nil, fmt.Errorf("cannot get image details for %s %s: %w", ref, platformStr, err)
		}

		image, err := imageDetailsToImage(ref, imageDetails, registry)
		if err != nil {
			return nil, fmt.Errorf("cannot convert image details to image: %w", err)
		}

		if err := controllerutil.SetControllerReference(registry, &image, h.scheme); err != nil {
			return nil, fmt.Errorf("cannot set owner reference: %w", err)
		}

		images = append(images, image)
	}

	return images, nil
}

// refToPlatforms returns the list of platforms for the given image reference.
// If the image is not multi-architecture, it returns an empty list.
func (h *CreateCatalogHandler) refToPlatforms(registryClient registryclient.Client, ref name.Reference) ([]*cranev1.Platform, error) {
	imgIndex, err := registryClient.GetImageIndex(ref)
	if err != nil {
		h.logger.Debug(
			"image doesn't seem to be multi-architecture",
			"image", ref.Name(),
			"error", err)
		return []*cranev1.Platform(nil), nil
	}

	manifest, err := imgIndex.IndexManifest()
	if err != nil {
		return []*cranev1.Platform(nil), fmt.Errorf("cannot read index manifest of %s: %w", ref, err)
	}

	platforms := make([]*cranev1.Platform, len(manifest.Manifests))
	for i, manifest := range manifest.Manifests {
		platforms[i] = manifest.Platform
	}

	return platforms, nil
}

// transportFromRegistry creates a new http.RoundTripper from the options specified in the Registry spec.
func (h *CreateCatalogHandler) transportFromRegistry(registry *v1alpha1.Registry) (http.RoundTripper, error) {
	transport, ok := remote.DefaultTransport.(*http.Transport)
	if !ok {
		// should not happen
		return nil, errors.New("remote.DefaultTransport is not an *http.Transport")
	}
	transport = transport.Clone()

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: registry.Spec.Insecure, //nolint:gosec // this a user provided option
	}

	if len(registry.Spec.CABundle) > 0 {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			h.logger.Error("cannot load system cert pool, using empty pool", "error", err)
			rootCAs = x509.NewCertPool()
		}

		ok := rootCAs.AppendCertsFromPEM([]byte(registry.Spec.CABundle))
		if ok {
			transport.TLSClientConfig.RootCAs = rootCAs
		} else {
			h.logger.Info("cannot load the given CA bundle",
				"registry", registry.Name,
				"namespace", registry.Namespace)
		}
	}

	return transport, nil
}

// deleteObsoleteImages deletes images that are not present in the discovered registry anymore.
func (h *CreateCatalogHandler) deleteObsoleteImages(ctx context.Context, existingImageNames sets.Set[string], discoveredImageNames sets.Set[string], namespace string) error {
	for existingImageName := range existingImageNames {
		if discoveredImageNames.Has(existingImageName) {
			continue
		}

		existingImage := storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      existingImageName,
				Namespace: namespace,
			},
		}

		if err := h.k8sClient.Delete(ctx, &existingImage); err != nil {
			return fmt.Errorf("cannot delete image %s: %w", existingImageName, err)
		}
	}

	return nil
}

func imageDetailsToImage(ref name.Reference, details registryclient.ImageDetails, registry *v1alpha1.Registry) (storagev1alpha1.Image, error) {
	imageLayers := []storagev1alpha1.ImageLayer{}

	// There can be more history entries than layers, as some history entries are empty layers
	// For example, a command like "ENV VAR=1" will create a new history entry but no new layer
	layerCounter := 0
	for _, history := range details.History {
		if history.EmptyLayer {
			continue
		}

		if len(details.Layers) < layerCounter {
			return storagev1alpha1.Image{}, fmt.Errorf("layer %d not found - got only %d layers", layerCounter, len(details.Layers))
		}
		layer := details.Layers[layerCounter]
		digest, err := layer.Digest()
		if err != nil {
			return storagev1alpha1.Image{}, fmt.Errorf("cannot read layer digest: %w", err)
		}
		diffID, err := layer.DiffID()
		if err != nil {
			return storagev1alpha1.Image{}, fmt.Errorf("cannot read layer diffID: %w", err)
		}

		imageLayers = append(imageLayers, storagev1alpha1.ImageLayer{
			Command: base64.StdEncoding.EncodeToString([]byte(history.CreatedBy)),
			Digest:  digest.String(),
			DiffID:  diffID.String(),
		})

		layerCounter++
	}

	image := storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{
			Name:      computeImageUID(ref, details.Digest.String()),
			Namespace: registry.Namespace,
		},
		Spec: storagev1alpha1.ImageSpec{
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:    registry.Name,
				RegistryURI: ref.Context().RegistryStr(),
				Repository:  ref.Context().RepositoryStr(),
				Tag:         ref.Identifier(),
				Platform:    details.Platform.String(),
				Digest:      details.Digest.String(),
			},
			Layers: imageLayers,
		},
	}

	return image, nil
}

// computeImageUID returns the sha256 of “<image-name>@sha256:<digest>`
func computeImageUID(ref name.Reference, digest string) string {
	sha := sha256.New()
	sha.Write([]byte(fmt.Sprintf("%s:%s@%s", ref.Context().Name(), ref.Identifier(), digest)))
	return hex.EncodeToString(sha.Sum(nil))
}
