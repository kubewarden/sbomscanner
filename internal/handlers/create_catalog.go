package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cel"
	"github.com/kubewarden/sbomscanner/internal/filters"
	"github.com/kubewarden/sbomscanner/internal/handlers/dockerauth"
	registryclient "github.com/kubewarden/sbomscanner/internal/handlers/registry"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

// CreateCatalogHandler is a handler for creating a catalog of images in a registry.
type CreateCatalogHandler struct {
	registryClientFactory registryclient.ClientFactory
	k8sClient             client.Client
	scheme                *runtime.Scheme
	publisher             messaging.Publisher
	logger                *slog.Logger
}

// NewCreateCatalogHandler creates a new instance of CreateCatalogHandler.
func NewCreateCatalogHandler(
	registryClientFactory registryclient.ClientFactory,
	k8sClient client.Client,
	scheme *runtime.Scheme,
	publisher messaging.Publisher,
	logger *slog.Logger,
) *CreateCatalogHandler {
	return &CreateCatalogHandler{
		registryClientFactory: registryClientFactory,
		k8sClient:             k8sClient,
		publisher:             publisher,
		scheme:                scheme,
		logger:                logger.With("handler", "create_catalog_handler"),
	}
}

// Handle processes the create catalog message and creates Image resources.
func (h *CreateCatalogHandler) Handle(ctx context.Context, message messaging.Message) error { //nolint:gocognit,gocyclo,cyclop,funlen // TODO: refactor this function to reduce cognitive complexity
	createCatalogMessage := &CreateCatalogMessage{}
	err := json.Unmarshal(message.Data(), createCatalogMessage)
	if err != nil {
		return fmt.Errorf("cannot unmarshal message: %w", err)
	}

	h.logger.InfoContext(ctx, "Catalog creation requested",
		"scanjob", createCatalogMessage.ScanJob.Name,
		"namespace", createCatalogMessage.ScanJob.Namespace,
	)

	// It is possible that the controller is slow to set the status condition "Scheduled" to true,
	// so we might encounter conflicts when setting the status condition to "InProgress".
	scanJob := &v1alpha1.ScanJob{}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err = h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      createCatalogMessage.ScanJob.Name,
			Namespace: createCatalogMessage.ScanJob.Namespace,
		}, scanJob); err != nil {
			return fmt.Errorf("cannot get scanjob %s/%s: %w", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name, err)
		}

		if string(scanJob.GetUID()) != createCatalogMessage.ScanJob.UID {
			return apierrors.NewNotFound(
				v1alpha1.GroupVersion.WithResource("scanjobs").GroupResource(),
				fmt.Sprintf("%s/%s", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name),
			)
		}

		scanJob.MarkInProgress(v1alpha1.ReasonCatalogCreationInProgress, "Catalog creation in progress")
		return h.k8sClient.Status().Update(ctx, scanJob)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Stop processing if the scanjob is not found, since it might have been deleted.
			h.logger.InfoContext(ctx, "ScanJob not found, stopping catalog creation", "scanjob", createCatalogMessage.ScanJob.Name, "namespace", createCatalogMessage.ScanJob.Namespace)
			return nil
		}
		return fmt.Errorf("cannot update scan job status %s/%s: %w", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name, err)
	}

	// Retrieve the registry from the scan job annotations.
	registryData, ok := scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]
	if !ok {
		return fmt.Errorf("scan job %s/%s does not have a registry annotation", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name)
	}
	registry := &v1alpha1.Registry{}
	if err = json.Unmarshal([]byte(registryData), registry); err != nil {
		return fmt.Errorf("cannot unmarshal registry data from scan job %s/%s: %w", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name, err)
	}
	h.logger.DebugContext(ctx, "Registry found", "registry", registry.Name, "namespace", registry.Namespace)

	transport, err := h.transportFromRegistry(registry)
	if err != nil {
		return fmt.Errorf("cannot create transport for registry %s: %w", registry.Name, err)
	}
	registryClient := h.registryClientFactory(transport)
	// if authSecret value is set, then setup Docker
	// authentication to get access to the registry
	if registry.IsPrivate() {
		var dockerConfig string
		dockerConfig, err = dockerauth.BuildDockerConfigForRegistry(ctx, h.k8sClient, registry)
		if err != nil {
			return fmt.Errorf("cannot setup docker auth: %w", err)
		}
		h.logger.DebugContext(ctx, "Setup registry authentication", "dockerconfig", os.Getenv("DOCKER_CONFIG"))
		defer func() {
			if err = os.RemoveAll(dockerConfig); err != nil {
				h.logger.Error("failed to remove dockerconfig directory", "error", err)
			}
			// uset the DOCKER_CONFIG variable so at every run
			// we start from a clean environment.
			if err = os.Unsetenv("DOCKER_CONFIG"); err != nil {
				h.logger.Error("failed to unset DOCKER_CONFIG variable", "error", err)
			}
		}()
	}

	repositories, err := h.discoverRepositories(ctx, registryClient, registry)
	if err != nil {
		return fmt.Errorf("cannot discover repositories: %w", err)
	}

	discoveredImageReferences := sets.Set[string]{}
	for _, repository := range repositories {
		var repoImages []string
		repoImages, err = h.discoverImages(ctx, registryClient, repository)
		if err != nil {
			return fmt.Errorf("cannot discover images in registry %s: %w", registry.Name, err)
		}
		discoveredImageReferences.Insert(repoImages...)
	}

	existingImageList := &storagev1alpha1.ImageList{}
	listOpts := []client.ListOption{
		client.InNamespace(registry.Namespace),
		client.MatchingFields{storagev1alpha1.IndexImageMetadataRegistry: registry.Name},
	}
	if err = h.k8sClient.List(ctx, existingImageList, listOpts...); err != nil {
		return fmt.Errorf("cannot list existing images in registry %s: %w", registry.Name, err)
	}
	existingImageNames := sets.Set[string]{}
	for _, existingImage := range existingImageList.Items {
		existingImageNames.Insert(existingImage.Name)
	}

	if err = message.InProgress(); err != nil {
		return fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	tagEvaluator, err := cel.NewTagEvaluator()
	if err != nil {
		return fmt.Errorf("cannot instantiate new tag evaluator: %w", err)
	}

	var discoveredImages []storagev1alpha1.Image
	for newImageName := range discoveredImageReferences {
		ref, err := name.ParseReference(newImageName)
		if err != nil {
			return fmt.Errorf("cannot parse image reference %q: %w", newImageName, err)
		}

		repository := registry.GetRepository(ref.Context().RepositoryStr())
		tagIsAllowed, err := filters.FilterByTag(tagEvaluator, repository, ref.Identifier())
		if err != nil {
			return fmt.Errorf("cannot evaluate image tag for %q: %w", newImageName, err)
		}
		// if tag is not allowed by the CEL filter,
		// then skip the image fetching.
		if !tagIsAllowed {
			continue
		}

		images, err := h.refToImages(ctx, message, registryClient, ref, registry)
		if err != nil {
			return fmt.Errorf("cannot get images for %q: %w", ref.String(), err)
		}

		for _, image := range images {
			// Re-fetch the scanjob to be sure it was not deleted while we were processing images.
			// If the scanjob is not found, we circuit-break the image creation.
			err = h.k8sClient.Get(ctx, types.NamespacedName{
				Name:      createCatalogMessage.ScanJob.Name,
				Namespace: createCatalogMessage.ScanJob.Namespace,
			}, scanJob)
			if err != nil {
				if apierrors.IsNotFound(err) {
					h.logger.InfoContext(ctx, "ScanJob not found, stopping catalog creation", "scanjob", createCatalogMessage.ScanJob.Name, "namespace", createCatalogMessage.ScanJob.Namespace)
					return nil
				}
				return fmt.Errorf("cannot get scanjob %s/%s: %w", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name, err)
			}
			if string(scanJob.GetUID()) != createCatalogMessage.ScanJob.UID {
				h.logger.InfoContext(ctx, "ScanJob not found, stopping SBOM generation (UID changed)", "scanjob", createCatalogMessage.ScanJob.Name, "namespace", createCatalogMessage.ScanJob.Namespace,
					"uid", createCatalogMessage.ScanJob.UID)
				return nil
			}

			discoveredImages = append(discoveredImages, image)

			if existingImageNames.Has(image.Name) {
				continue
			}

			h.logger.InfoContext(ctx, "Creating image", "image", image.Name, "namespace", image.Namespace)
			if err = h.k8sClient.Create(ctx, &image); err != nil {
				if apierrors.IsAlreadyExists(err) {
					h.logger.InfoContext(ctx, "Image already exists, skipping creation", "image", image.Name, "namespace", image.Namespace)
					continue
				}
				return fmt.Errorf("cannot create image %s: %w", image.Name, err)
			}

			if err = message.InProgress(); err != nil {
				return fmt.Errorf("failed to ack message as in progress: %w", err)
			}
		}
	}

	discoveredImageNames := sets.Set[string]{}
	for _, image := range discoveredImages {
		discoveredImageNames.Insert(image.Name)
	}
	if err = h.deleteObsoleteImages(ctx, existingImageNames, discoveredImageNames, registry.Namespace, message); err != nil {
		return fmt.Errorf("cannot delete obsolete images in registry %s: %w", registry.Name, err)
	}

	// It is possible that the controller is slow to set the status condition "Scheduled" to true,
	// so we might encounter conflicts when setting the status conditions.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err = h.k8sClient.Get(ctx, types.NamespacedName{
			Name:      scanJob.Name,
			Namespace: scanJob.Namespace,
		}, scanJob); err != nil {
			return fmt.Errorf("cannot get scan job %s/%s while updating status: %w", scanJob.Namespace, scanJob.Name, err)
		}

		if string(scanJob.GetUID()) != createCatalogMessage.ScanJob.UID {
			return apierrors.NewNotFound(
				v1alpha1.GroupVersion.WithResource("scanjobs").GroupResource(),
				fmt.Sprintf("%s/%s", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name),
			)
		}

		if len(discoveredImages) == 0 {
			h.logger.InfoContext(ctx, "No images to process", "scanjob", scanJob.Name, "namespace", scanJob.Namespace)
			scanJob.MarkComplete(v1alpha1.ReasonNoImagesToScan, "No images to process")
		} else {
			h.logger.InfoContext(ctx, "Images to process", "count", len(discoveredImages))
			scanJob.MarkInProgress(v1alpha1.ReasonSBOMGenerationInProgress, "SBOM generation in progress")
			scanJob.Status.ImagesCount = len(discoveredImages)
			scanJob.Status.ScannedImagesCount = 0
		}

		return h.k8sClient.Status().Update(ctx, scanJob)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Stop processing if the scanjob is not found, since it might have been deleted.
			h.logger.InfoContext(ctx, "ScanJob not found, stopping catalog creation", "scanjob", createCatalogMessage.ScanJob.Name, "namespace", createCatalogMessage.ScanJob.Namespace)
			return nil
		}
		return fmt.Errorf("cannot update scan job status %s/%s: %w", createCatalogMessage.ScanJob.Namespace, createCatalogMessage.ScanJob.Name, err)
	}

	for _, image := range discoveredImages {
		h.logger.DebugContext(ctx, "Sending generate SBOM message", "image", image.Name, "namespace", image.Namespace)

		messageID := fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, image.Name)
		message, err := json.Marshal(&GenerateSBOMMessage{
			BaseMessage: BaseMessage{
				ScanJob: createCatalogMessage.ScanJob,
			},
			Image: ObjectRef{
				Name:      image.Name,
				Namespace: image.Namespace,
			},
		})
		if err != nil {
			return fmt.Errorf("cannot marshal generate sbom message for image %s/%s: %w", image.Namespace, image.Name, err)
		}

		if err = h.publisher.Publish(ctx, GenerateSBOMSubject, messageID, message); err != nil {
			return fmt.Errorf("cannot publish generate sbom message for image %s/%s: %w", image.Namespace, image.Name, err)
		}
	}

	return nil
}

// discoverRepositories discovers all the repositories in a registry.
// Returns the list of fully qualified repository names (e.g. registryclientexample.com/repo)
func (h *CreateCatalogHandler) discoverRepositories(
	ctx context.Context,
	registryClient *registryclient.Client,
	registry *v1alpha1.Registry,
) ([]string, error) {
	reg, err := name.NewRegistry(registry.Spec.URI)
	if err != nil {
		return nil, fmt.Errorf("cannot parse registry %s %s: %w", registry.Name, registry.Namespace, err)
	}

	// If the registry doesn't have any repositories defined, it means we need to catalog all of them.
	// In this case, we need to discover all the repositories in the registry.
	if len(registry.Spec.Repositories) == 0 {
		var allRepositories []string
		allRepositories, err = registryClient.Catalog(ctx, reg)
		if err != nil {
			return []string{}, fmt.Errorf("cannot discover repositories: %w", err)
		}

		return allRepositories, nil
	}

	repositories := []string{}
	for _, repository := range registry.Spec.Repositories {
		repositories = append(repositories, path.Join(reg.Name(), repository.Name))
	}

	return repositories, nil
}

// discoverImages discovers all the images defined inside of a repository.
// Returns the list of fully qualified image names (e.g. registryclientexample.com/repo:tag)
func (h *CreateCatalogHandler) discoverImages(
	ctx context.Context,
	registryClient *registryclient.Client,
	repository string,
) ([]string, error) {
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

// refToImages converts a reference to a list of Image resources.
// Returns an empty slice if the reference points to a non-image artifact (e.g., Helm chart, signature).
func (h *CreateCatalogHandler) refToImages(
	ctx context.Context,
	message messaging.Message,
	registryClient *registryclient.Client,
	ref name.Reference,
	registry *v1alpha1.Registry,
) ([]storagev1alpha1.Image, error) {
	desc, err := registryClient.GetDescriptor(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("cannot get descriptor for %q: %w", ref.Name(), err)
	}

	isContainerImage, err := registryClient.IsContainerImage(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("cannot check if %s is a container image: %w", ref.Name(), err)
	}

	if !isContainerImage {
		h.logger.DebugContext(ctx, "Skipping non-image artifact",
			"ref", ref.Name(),
			"mediaType", desc.MediaType,
		)
		return []storagev1alpha1.Image{}, nil
	}

	if desc.MediaType.IsIndex() {
		return h.multiArchRefToImages(ctx, message, registryClient, ref, registry)
	}

	return h.singleArchRefToImages(ctx, message, registryClient, ref, registry)
}

// singleArchRefToImages handles single-arch images.
func (h *CreateCatalogHandler) singleArchRefToImages(
	ctx context.Context,
	message messaging.Message,
	registryClient *registryclient.Client,
	ref name.Reference,
	registry *v1alpha1.Registry,
) ([]storagev1alpha1.Image, error) {
	imageDetails, err := registryClient.GetImageDetails(ctx, ref, nil)
	if err != nil {
		return []storagev1alpha1.Image{}, fmt.Errorf("cannot get image details for %q: %w", ref.Name(), err)
	}

	if !filters.IsPlatformAllowed(
		imageDetails.Platform.OS,
		imageDetails.Platform.Architecture,
		imageDetails.Platform.Variant,
		registry.Spec.Platforms) {
		return []storagev1alpha1.Image{}, nil
	}

	image, err := imageDetailsToImage(ref, imageDetails, registry, h.scheme, "")
	if err != nil {
		return []storagev1alpha1.Image{}, fmt.Errorf("cannot convert image details to image for %q: %w", ref.Name(), err)
	}

	if err = message.InProgress(); err != nil {
		return []storagev1alpha1.Image{}, fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	return []storagev1alpha1.Image{image}, nil
}

// multiArchRefToImages handles multi-arch images by iterating over platforms.
func (h *CreateCatalogHandler) multiArchRefToImages(
	ctx context.Context,
	message messaging.Message,
	registryClient *registryclient.Client,
	ref name.Reference,
	registry *v1alpha1.Registry,
) ([]storagev1alpha1.Image, error) {
	imageIndex, err := registryClient.GetImageIndex(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch image index for %q: %w", ref.Name(), err)
	}

	manifest, err := imageIndex.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("cannot read index manifest of %q: %w", ref.Name(), err)
	}
	indexDigest, err := imageIndex.Digest()
	if err != nil {
		return nil, fmt.Errorf("cannot get index digest for %q: %w", ref.Name(), err)
	}

	images := []storagev1alpha1.Image{}

	for _, m := range manifest.Manifests {
		if !filters.IsPlatformAllowed(
			m.Platform.OS,
			m.Platform.Architecture,
			m.Platform.Variant,
			registry.Spec.Platforms) {
			continue
		}

		imageDetails, err := registryClient.GetImageDetails(ctx, ref, m.Platform)
		if err != nil {
			return nil, fmt.Errorf("cannot get image details for %q platform %v: %w", ref.Name(), m.Platform, err)
		}

		image, err := imageDetailsToImage(ref, imageDetails, registry, h.scheme, indexDigest.String())
		if err != nil {
			return nil, fmt.Errorf("cannot convert image details to image for %q: %w", ref.Name(), err)
		}

		images = append(images, image)

		if err = message.InProgress(); err != nil {
			return nil, fmt.Errorf("failed to ack message as in progress: %w", err)
		}
	}

	return images, nil
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

		ok = rootCAs.AppendCertsFromPEM([]byte(registry.Spec.CABundle))
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
func (h *CreateCatalogHandler) deleteObsoleteImages(
	ctx context.Context,
	existingImageNames sets.Set[string],
	discoveredImageNames sets.Set[string],
	namespace string,
	message messaging.Message,
) error {
	obsoleteImageNames := existingImageNames.Difference(discoveredImageNames)

	h.logger.DebugContext(ctx, "Existing images", "names", existingImageNames)
	h.logger.DebugContext(ctx, "Discovered images", "names", discoveredImageNames)
	h.logger.DebugContext(ctx, "Obsolete images", "names", obsoleteImageNames)

	for obsoleteImageName := range obsoleteImageNames {
		existingImage := storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      obsoleteImageName,
				Namespace: namespace,
			},
		}

		h.logger.DebugContext(ctx, "Deleting obsolete image", "name", obsoleteImageName, "namespace", namespace)

		if err := h.k8sClient.Delete(ctx, &existingImage); err != nil {
			return fmt.Errorf("cannot delete image %s/%s: %w", obsoleteImageName, namespace, err)
		}
		if err := message.InProgress(); err != nil {
			return fmt.Errorf("cannot mark message as in progress: %w", err)
		}
	}

	return nil
}

// imageDetailsToImage converts ImageDetails from the registry client to an Image resource.
func imageDetailsToImage(
	ref name.Reference,
	details registryclient.ImageDetails,
	registry *v1alpha1.Registry,
	scheme *runtime.Scheme,
	indexDigest string,
) (storagev1alpha1.Image, error) {
	imageLayers := []storagev1alpha1.ImageLayer{}

	// There can be more history entries than layers, as some history entries are empty layers
	// For example, a command like "ENV VAR=1" will create a new history entry but no new layer
	layerCounter := 0
	for _, history := range details.History {
		if history.EmptyLayer {
			continue
		}

		if len(details.Layers) < layerCounter {
			return storagev1alpha1.Image{}, fmt.Errorf(
				"layer %d not found - got only %d layers",
				layerCounter,
				len(details.Layers),
			)
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
			Name:      computeImageUID(ref.Context().Name(), ref.Identifier(), details.Digest.String()),
			Namespace: registry.Namespace,
			Labels: map[string]string{
				api.LabelManagedByKey: api.LabelManagedByValue,
				api.LabelPartOfKey:    api.LabelPartOfValue,
			},
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    registry.Name,
			RegistryURI: ref.Context().RegistryStr(),
			Repository:  ref.Context().RepositoryStr(),
			Tag:         ref.Identifier(),
			Platform:    details.Platform.String(),
			Digest:      details.Digest.String(),
			IndexDigest: indexDigest,
		},
		Layers: imageLayers,
	}

	if err := controllerutil.SetControllerReference(registry, &image, scheme); err != nil {
		return storagev1alpha1.Image{}, fmt.Errorf("cannot set owner reference: %w", err)
	}

	return image, nil
}

// computeImageUID returns a unique identifier for an image.
func computeImageUID(name, identifier, digest string) string {
	sha := sha256.New()
	fmt.Fprintf(sha, "%s:%s@%s", name, identifier, digest)
	return hex.EncodeToString(sha.Sum(nil))
}
