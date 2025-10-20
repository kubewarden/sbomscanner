package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/name"
	cranev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	registryClient "github.com/kubewarden/sbomscanner/internal/handlers/registry"
	registryMocks "github.com/kubewarden/sbomscanner/internal/handlers/registry/mocks"
	messagingMocks "github.com/kubewarden/sbomscanner/internal/messaging/mocks"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	corev1 "k8s.io/api/core/v1"
)

// TestCreateCatalogHandler_Handle tests the create catalog handler with a platform error
// Ensures that the handler does not block other images from being cataloged
func TestCreateCatalogHandler_Handle(t *testing.T) {
	registryURI := "registry.test"
	repositoryName := "repo1"
	imageTag := "tag1"

	repository, err := name.NewRepository(path.Join(registryURI, repositoryName))
	require.NoError(t, err)
	image, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryURI, repositoryName, imageTag))
	require.NoError(t, err)

	mockRegistryClient := registryMocks.NewClient(t)
	mockRegistryClient.On("ListRepositoryContents", mock.Anything, repository).Return([]string{fmt.Sprintf("%s/%s:%s", registryURI, repositoryName, imageTag)}, nil)

	platformLinuxAmd64 := cranev1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}
	platformLinuxArm64 := cranev1.Platform{
		Architecture: "arm64",
		OS:           "linux",
	}
	platformLinux386 := cranev1.Platform{
		Architecture: "386",
		OS:           "linux",
	}
	platformUnknown := cranev1.Platform{
		Architecture: "unknown",
		OS:           "unknown",
	}

	digestLinuxAmd64, err := cranev1.NewHash("sha256:8ec69d882e7f29f0652d537557160e638168550f738d0d49f90a7ef96bf31787")
	require.NoError(t, err)
	digestLinuxArm64, err := cranev1.NewHash("sha256:ca9d8b5d1cc2f2186983fc6b9507da6ada5eb92f2b518c06af1128d5396c6f34")
	require.NoError(t, err)
	digestLinux386, err := cranev1.NewHash("sha256:8fd4c2b9e1a68e52d77b30c9f2e3b3f8e9e2b7484c0b4a7e1d2e5a9c1b3d4f67")
	require.NoError(t, err)
	digestUnknown, err := cranev1.NewHash("sha256:f1c2e7a5b4d3c8a9e6f5d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a291807")
	require.NoError(t, err)

	indexManifest := cranev1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Manifests: []cranev1.Descriptor{
			{
				MediaType:    types.OCIManifestSchema1,
				Size:         100,
				Digest:       digestLinuxAmd64,
				Data:         []byte(""),
				URLs:         []string{},
				Annotations:  map[string]string{},
				Platform:     &platformLinuxAmd64,
				ArtifactType: "",
			},
			{
				MediaType:    types.OCIManifestSchema1,
				Size:         100,
				Digest:       digestLinuxArm64,
				Data:         []byte(""),
				URLs:         []string{},
				Annotations:  map[string]string{},
				Platform:     &platformLinuxArm64,
				ArtifactType: "",
			},
			{
				MediaType:    types.OCIManifestSchema1,
				Size:         100,
				Digest:       digestLinux386,
				Data:         []byte(""),
				URLs:         []string{},
				Annotations:  map[string]string{},
				Platform:     &platformLinux386,
				ArtifactType: "",
			},
			{
				MediaType:    types.OCIManifestSchema1,
				Size:         100,
				Digest:       digestUnknown,
				Data:         []byte(""),
				URLs:         []string{},
				Annotations:  map[string]string{},
				Platform:     &platformUnknown,
				ArtifactType: "",
			},
		},
	}

	imageIndex := registryMocks.NewImageIndex(t)
	imageIndex.On("IndexManifest").Return(&indexManifest, nil)
	mockRegistryClient.On("GetImageIndex", image).Return(imageIndex, nil)

	imageDetailsLinuxAmd64, err := buildImageDetails(digestLinuxAmd64, platformLinuxAmd64)
	require.NoError(t, err)

	imageDetailsLinuxArm64, err := buildImageDetails(digestLinuxArm64, platformLinuxArm64)
	require.NoError(t, err)

	mockRegistryClient.On("GetImageDetails", image, &platformLinuxAmd64).Return(imageDetailsLinuxAmd64, nil)
	mockRegistryClient.On("GetImageDetails", image, &platformLinuxArm64).Return(imageDetailsLinuxArm64, nil)
	mockRegistryClientFactory := func(_ http.RoundTripper) registryClient.Client { return mockRegistryClient }

	mockPublisher := messagingMocks.NewMockPublisher(t)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          registryURI,
			Repositories: []string{repositoryName},
			Platforms: []v1alpha1.Platform{
				{
					OS:   "linux",
					Arch: "amd64",
				},
				{
					OS:   "linux",
					Arch: "arm64",
				},
			},
		},
	}
	registryData, err := json.Marshal(registry)
	require.NoError(t, err)

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: string(registryData),
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: registry.Name,
		},
	}

	scheme := scheme.Scheme
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = storagev1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(registry, scanJob).
		WithStatusSubresource(&v1alpha1.ScanJob{}).
		WithIndex(&storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataRegistry, func(obj client.Object) []string {
			image, ok := obj.(*storagev1alpha1.Image)
			if !ok {
				return nil
			}

			return []string{image.GetImageMetadata().Registry}
		}).
		Build()

	handler := NewCreateCatalogHandler(
		mockRegistryClientFactory,
		k8sClient,
		scheme,
		mockPublisher,
		slog.Default().With("handler", "create_catalog_handler"),
	)

	message, err := json.Marshal(&CreateCatalogMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
	})
	require.NoError(t, err)

	amd64ImageName := computeImageUID(image, digestLinuxAmd64.String())
	expectedMessageAmd64, err := json.Marshal(&GenerateSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		Image: ObjectRef{
			Name:      amd64ImageName,
			Namespace: registry.Namespace,
		},
	})
	require.NoError(t, err)

	arm64ImageName := computeImageUID(image, digestLinuxArm64.String())
	expectedMessageArm64, err := json.Marshal(&GenerateSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		Image: ObjectRef{
			Name:      arm64ImageName,
			Namespace: registry.Namespace,
		},
	})
	require.NoError(t, err)

	mockPublisher.On("Publish",
		mock.Anything,
		GenerateSBOMSubject,
		fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, amd64ImageName),
		expectedMessageAmd64,
	).Return(nil).Once()

	mockPublisher.On("Publish",
		mock.Anything,
		GenerateSBOMSubject,
		fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, arm64ImageName),
		expectedMessageArm64,
	).Return(nil).Once()

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	imageList := &storagev1alpha1.ImageList{}
	err = k8sClient.List(t.Context(), imageList)
	require.NoError(t, err)
	require.Len(t, imageList.Items, 2)

	image1 := imageList.Items[0]
	image2 := imageList.Items[1]

	assert.Equal(t, registry.Namespace, image1.Namespace)
	assert.Equal(t, registry.Name, image1.GetImageMetadata().Registry)
	assert.Equal(t, registry.Spec.URI, image1.GetImageMetadata().RegistryURI)
	assert.Equal(t, repositoryName, image1.GetImageMetadata().Repository)
	assert.Equal(t, imageTag, image1.GetImageMetadata().Tag)
	assert.Equal(t, digestLinuxAmd64.String(), image1.GetImageMetadata().Digest)
	assert.Equal(t, platformLinuxAmd64.String(), image1.GetImageMetadata().Platform)
	assert.Len(t, image1.Layers, 8)
	assert.Equal(t, registry.UID, image1.GetOwnerReferences()[0].UID)

	assert.Equal(t, registry.Namespace, image2.Namespace)
	assert.Equal(t, registry.Name, image2.GetImageMetadata().Registry)
	assert.Equal(t, registry.Spec.URI, image2.GetImageMetadata().RegistryURI)
	assert.Equal(t, repositoryName, image2.GetImageMetadata().Repository)
	assert.Equal(t, imageTag, image2.GetImageMetadata().Tag)
	assert.Equal(t, digestLinuxArm64.String(), image2.GetImageMetadata().Digest)
	assert.Equal(t, platformLinuxArm64.String(), image2.GetImageMetadata().Platform)
	assert.Len(t, image2.Layers, 8)
	assert.Equal(t, registry.UID, image2.GetOwnerReferences()[0].UID)

	updatedScanJob := &v1alpha1.ScanJob{}
	err = k8sClient.Get(t.Context(), client.ObjectKey{
		Name:      scanJob.Name,
		Namespace: scanJob.Namespace,
	}, updatedScanJob)
	require.NoError(t, err)
	assert.Equal(t, 2, updatedScanJob.Status.ImagesCount)
	assert.Equal(t, 0, updatedScanJob.Status.ScannedImagesCount)
	assert.True(t, updatedScanJob.IsInProgress())
	assert.Equal(t, v1alpha1.ReasonSBOMGenerationInProgress, meta.FindStatusCondition(updatedScanJob.Status.Conditions, v1alpha1.ConditionTypeInProgress).Reason)
}

// TestCreateCatalogHandler_Handle_ObsoleteImages tests that obsolete images are deleted
// while existing images that match the current catalog are preserved
func TestCreateCatalogHandler_Handle_ObsoleteImages(t *testing.T) {
	registryURI := "registry.test"
	repositoryName := "repo1"
	imageTag := "v1.0"

	repository, err := name.NewRepository(path.Join(registryURI, repositoryName))
	require.NoError(t, err)
	image, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryURI, repositoryName, imageTag))
	require.NoError(t, err)

	mockRegistryClient := registryMocks.NewClient(t)
	mockRegistryClient.On("ListRepositoryContents", mock.Anything, repository).
		Return([]string{fmt.Sprintf("%s/%s:%s", registryURI, repositoryName, imageTag)}, nil)

	platform := cranev1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}
	digest, err := cranev1.NewHash("sha256:8ec69d882e7f29f0652d537557160e638168550f738d0d49f90a7ef96bf31787")
	require.NoError(t, err)

	// Mock GetImageIndex to return an error (indicating it's not a multi-platform image)
	mockRegistryClient.On("GetImageIndex", image).
		Return(nil, errors.New("not an image index"))

	imageDetails, err := buildImageDetails(digest, platform)
	require.NoError(t, err)
	mockRegistryClient.On("GetImageDetails", image, (*cranev1.Platform)(nil)).
		Return(imageDetails, nil)

	mockRegistryClientFactory := func(_ http.RoundTripper) registryClient.Client { return mockRegistryClient }
	mockPublisher := messagingMocks.NewMockPublisher(t)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
			UID:       "registry-uid",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          registryURI,
			Repositories: []string{repositoryName},
		},
	}
	registryData, err := json.Marshal(registry)
	require.NoError(t, err)

	obsoleteImage := &storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "obsolete-image",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "sbomscanner.io/v1alpha1",
				Kind:       "Registry",
				Name:       registry.Name,
				UID:        registry.UID,
			}},
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    registry.Name,
			RegistryURI: registryURI,
			Repository:  repositoryName,
			Tag:         "old-tag", // This tag no longer exists
			Digest:      "sha256:obsolete",
			Platform:    platform.String(),
		},
	}

	existingImageUID := computeImageUID(image, digest.String())
	existingImage := &storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{
			Name:      existingImageUID,
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "sbomscanner.io/v1alpha1",
				Kind:       "Registry",
				Name:       registry.Name,
				UID:        registry.UID,
			}},
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    registry.Name,
			RegistryURI: registryURI,
			Repository:  repositoryName,
			Tag:         imageTag,
			Digest:      digest.String(),
			Platform:    platform.String(),
		},
	}

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: string(registryData),
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: registry.Name,
		},
	}

	expectedMessage, err := json.Marshal(&GenerateSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		Image: ObjectRef{
			Name:      existingImage.Name,
			Namespace: registry.Namespace,
		},
	})
	require.NoError(t, err)

	mockPublisher.On("Publish",
		mock.Anything,
		GenerateSBOMSubject,
		fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, existingImage.Name),
		expectedMessage,
	).Return(nil).Once()

	scheme := scheme.Scheme
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = storagev1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(registry, obsoleteImage, existingImage, scanJob).
		WithStatusSubresource(&v1alpha1.ScanJob{}).
		WithIndex(&storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataRegistry, func(obj client.Object) []string {
			image, ok := obj.(*storagev1alpha1.Image)
			if !ok {
				return nil
			}
			return []string{image.GetImageMetadata().Registry}
		}).
		Build()

	handler := NewCreateCatalogHandler(
		mockRegistryClientFactory,
		k8sClient,
		scheme,
		mockPublisher,
		slog.Default().With("handler", "create_catalog_handler"),
	)

	message, err := json.Marshal(&CreateCatalogMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
	})
	require.NoError(t, err)

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	err = k8sClient.Get(t.Context(), client.ObjectKey{
		Name:      obsoleteImage.Name,
		Namespace: obsoleteImage.Namespace,
	}, &storagev1alpha1.Image{})
	assert.True(t, apierrors.IsNotFound(err), "obsolete image should be deleted")

	imageList := &storagev1alpha1.ImageList{}
	err = k8sClient.List(t.Context(), imageList, client.InNamespace("default"))
	require.NoError(t, err)
	assert.Len(t, imageList.Items, 1, "should only contain the existing image")
	assert.Equal(t, existingImageUID, imageList.Items[0].Name)
}

func TestCreateCatalogHandler_DiscoverRepositories(t *testing.T) {
	tests := []struct {
		name                 string
		registry             *v1alpha1.Registry
		expectedRepositories []string
		setupMock            func(mockRegistryClient *registryMocks.Client)
	}{
		{
			name: "repositories are not specified",
			registry: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					URI:          "registry.test",
					Repositories: []string{},
				},
			},
			expectedRepositories: []string{"registry.test/repo1", "registry.test/repo2"},
			setupMock: func(mockRegistryClient *registryMocks.Client) {
				mockRegistryClient.On("Catalog", mock.Anything, mock.Anything).
					Return([]string{"registry.test/repo1", "registry.test/repo2"}, nil)
			},
		},
		{
			name: "repositories are specified",
			registry: &v1alpha1.Registry{
				Spec: v1alpha1.RegistrySpec{
					URI:          "registry.test",
					Repositories: []string{"repo3"},
				},
			},
			expectedRepositories: []string{"registry.test/repo3"},
			setupMock: func(_ *registryMocks.Client) {
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockRegistryClient := registryMocks.NewClient(t)

			test.setupMock(mockRegistryClient)
			handler := &CreateCatalogHandler{}

			actual, err := handler.discoverRepositories(t.Context(), mockRegistryClient, test.registry)
			require.NoError(t, err)
			assert.ElementsMatch(t, actual, test.expectedRepositories)
		})
	}
}

func TestCatalogHandler_DeleteObsoleteImages(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	existingImages := []runtime.Object{
		&storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "image-1",
				Namespace: "default",
			},
		},
		&storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "image-2",
				Namespace: "default",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(existingImages...).Build()

	handler := &CreateCatalogHandler{
		k8sClient: k8sClient,
		logger:    slog.Default(),
	}

	ctx := t.Context()

	existingImageNames := sets.New(
		"image-1",
		"image-2",
	)
	newImageNames := sets.New(
		"image-1", // Image 2 is obsolete
	)

	err := handler.deleteObsoleteImages(ctx, existingImageNames, newImageNames, "default", &testMessage{})
	require.NoError(t, err)

	var remainingImages storagev1alpha1.ImageList
	err = k8sClient.List(ctx, &remainingImages, client.InNamespace("default"))
	require.NoError(t, err)

	require.Len(t, remainingImages.Items, 1)
	assert.Equal(t, "image-1", remainingImages.Items[0].Name)
}

func TestCreateCatalogHandler_Handle_StopProcessing(t *testing.T) {
	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI: "test.io",
		},
	}
	registryData, err := json.Marshal(registry)
	require.NoError(t, err)

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: string(registryData),
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: "test-registry",
		},
	}

	tests := []struct {
		name                string
		existingObjects     []runtime.Object
		setupRegistryClient func(*registryMocks.Client, client.Client, *v1alpha1.ScanJob)
	}{
		{
			name:            "scanjob not found initially",
			existingObjects: []runtime.Object{registry},
			setupRegistryClient: func(_ *registryMocks.Client, _ client.Client, _ *v1alpha1.ScanJob) {
			},
		},
		{
			name:            "scanjob with differnt UID initially",
			existingObjects: []runtime.Object{registry},
			setupRegistryClient: func(_ *registryMocks.Client, k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				differentUIDScanJob := scanJob.DeepCopy()
				differentUIDScanJob.UID = "test-scanjob-different-uid"
				err = k8sClient.Create(context.Background(), differentUIDScanJob)
				require.NoError(t, err)
			},
		},
		{
			name:            "scanjob deleted before image creation",
			existingObjects: []runtime.Object{registry, scanJob},
			setupRegistryClient: func(mockClient *registryMocks.Client, k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				mockClient.On("Catalog", mock.Anything, mock.Anything).Return([]string{"test.io/repo"}, nil)
				mockClient.On("ListRepositoryContents", mock.Anything, mock.Anything).Return([]string{"test.io/repo:latest"}, nil)
				mockClient.On("GetImageIndex", mock.Anything).Return(nil, errors.New("not multi-arch"))

				digest, _ := cranev1.NewHash("sha256:abc123def456")
				platform := cranev1.Platform{OS: "linux", Architecture: "amd64"}
				mockLayer := &registryMocks.Layer{}
				mockLayer.On("Digest").Return(cranev1.Hash{Algorithm: "sha256", Hex: "layer123"}, nil)
				mockLayer.On("DiffID").Return(cranev1.Hash{Algorithm: "sha256", Hex: "diff123"}, nil)

				imageDetails := registryClient.ImageDetails{
					Digest:   digest,
					Platform: platform,
					History:  []cranev1.History{{CreatedBy: "test command", EmptyLayer: false}},
					Layers:   []cranev1.Layer{mockLayer},
				}

				mockClient.On("GetImageDetails", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
					// Delete the ScanJob when GetImageDetails is called
					// This ensures the handler gets valid image details but then finds the ScanJob missing
					// when it tries to re-fetch it before image creation
					err = k8sClient.Delete(context.Background(), scanJob)
					require.NoError(t, err)
				}).Return(imageDetails, nil)
			},
		},
		{
			name:            "scanjob with different UID before image creation",
			existingObjects: []runtime.Object{registry, scanJob},
			setupRegistryClient: func(mockClient *registryMocks.Client, k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				mockClient.On("Catalog", mock.Anything, mock.Anything).Return([]string{"test.io/repo"}, nil)
				mockClient.On("ListRepositoryContents", mock.Anything, mock.Anything).Return([]string{"test.io/repo:latest"}, nil)
				mockClient.On("GetImageIndex", mock.Anything).Return(nil, errors.New("not multi-arch"))

				digest, _ := cranev1.NewHash("sha256:abc123def456")
				platform := cranev1.Platform{OS: "linux", Architecture: "amd64"}
				mockLayer := &registryMocks.Layer{}
				mockLayer.On("Digest").Return(cranev1.Hash{Algorithm: "sha256", Hex: "layer123"}, nil)
				mockLayer.On("DiffID").Return(cranev1.Hash{Algorithm: "sha256", Hex: "diff123"}, nil)

				imageDetails := registryClient.ImageDetails{
					Digest:   digest,
					Platform: platform,
					History:  []cranev1.History{{CreatedBy: "test command", EmptyLayer: false}},
					Layers:   []cranev1.Layer{mockLayer},
				}

				mockClient.On("GetImageDetails", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
					// Recreate the ScanJob when GetImageDetails is called
					// This ensures the handler gets valid image details but then finds the ScanJob with a different UID
					// when it tries to re-fetch it before image creation
					err := k8sClient.Delete(context.Background(), scanJob)
					require.NoError(t, err)

					differentUIDScanJob := scanJob.DeepCopy()
					differentUIDScanJob.UID = "test-scanjob-different-uid"
					differentUIDScanJob.ResourceVersion = ""
					err = k8sClient.Create(context.Background(), differentUIDScanJob)
					require.NoError(t, err)
				}).Return(imageDetails, nil)
			},
		},
		{
			name:            "scanjob deleted before status update",
			existingObjects: []runtime.Object{registry, scanJob},
			setupRegistryClient: func(mockClient *registryMocks.Client, k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				mockClient.On("Catalog", mock.Anything, mock.Anything).Return([]string{"test.io/repo"}, nil)
				mockClient.On("ListRepositoryContents", mock.Anything, mock.Anything).Return([]string{"test.io/repo:latest"}, nil)
				mockClient.On("GetImageIndex", mock.Anything).Return(nil, errors.New("not multi-arch"))

				// On GetImageDetails call, delete the ScanJob to simulate mid-processing deletion
				mockClient.On("GetImageDetails", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
					err := k8sClient.Delete(context.Background(), scanJob)
					require.NoError(t, err)
				}).Return(registryClient.ImageDetails{}, errors.New("something went wrong"))
			},
		},
		{
			name:            "scanjob with different UID before status update",
			existingObjects: []runtime.Object{registry, scanJob},
			setupRegistryClient: func(mockClient *registryMocks.Client, k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				mockClient.On("Catalog", mock.Anything, mock.Anything).Return([]string{"test.io/repo"}, nil)
				mockClient.On("ListRepositoryContents", mock.Anything, mock.Anything).Return([]string{"test.io/repo:latest"}, nil)
				mockClient.On("GetImageIndex", mock.Anything).Return(nil, errors.New("not multi-arch"))

				// On GetImageDetails call, recreate the ScanJob to simulate the UID change mid-processing
				mockClient.On("GetImageDetails", mock.Anything, mock.Anything).Run(func(_ mock.Arguments) {
					err := k8sClient.Delete(context.Background(), scanJob)
					require.NoError(t, err)

					differentUIDScanJob := scanJob.DeepCopy()
					differentUIDScanJob.UID = "test-scanjob-different-uid"
					differentUIDScanJob.ResourceVersion = ""
					err = k8sClient.Create(context.Background(), differentUIDScanJob)
					require.NoError(t, err)
				}).Return(registryClient.ImageDetails{}, errors.New("something went wrong"))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := scheme.Scheme
			err := storagev1alpha1.AddToScheme(scheme)
			require.NoError(t, err)
			err = v1alpha1.AddToScheme(scheme)
			require.NoError(t, err)

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(test.existingObjects...).
				WithStatusSubresource(&v1alpha1.ScanJob{}).
				WithIndex(&storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataRegistry, func(obj client.Object) []string {
					image, ok := obj.(*storagev1alpha1.Image)
					if !ok {
						return nil
					}
					return []string{image.GetImageMetadata().Registry}
				}).
				Build()

			mockRegistryClient := registryMocks.NewClient(t)
			test.setupRegistryClient(mockRegistryClient, k8sClient, scanJob)

			mockRegistryClientFactory := func(_ http.RoundTripper) registryClient.Client {
				return mockRegistryClient
			}
			mockPublisher := messagingMocks.NewMockPublisher(t)

			handler := NewCreateCatalogHandler(mockRegistryClientFactory, k8sClient, scheme, mockPublisher, slog.Default())

			message, err := json.Marshal(&CreateCatalogMessage{
				BaseMessage: BaseMessage{
					ScanJob: ObjectRef{
						Name:      scanJob.Name,
						Namespace: scanJob.Namespace,
						UID:       string(scanJob.UID),
					},
				},
			})
			require.NoError(t, err)

			// Should return nil (no error) when resource doesn't exist
			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			// Verify no Image resources were created
			imageList := &storagev1alpha1.ImageList{}
			err = k8sClient.List(context.Background(), imageList)
			require.NoError(t, err)
			assert.Empty(t, imageList.Items, "No images should be created")
		})
	}
}

func TestImageDetailsToImage(t *testing.T) {
	digest, err := cranev1.NewHash("sha256:f41b7d70c5779beba4a570ca861f788d480156321de2876ce479e072fb0246f1")
	require.NoError(t, err)

	platform, err := cranev1.ParsePlatform("linux/amd64")
	require.NoError(t, err)

	details, err := buildImageDetails(digest, *platform)
	require.NoError(t, err)
	numberOfLayers := len(details.Layers)

	registryURI := "registry.test"
	repo := "repo1"
	tag := "latest"
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryURI, repo, tag))
	require.NoError(t, err)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          registryURI,
			Repositories: []string{repo},
		},
	}

	image, err := imageDetailsToImage(ref, details, registry)
	require.NoError(t, err)

	assert.Equal(t, image.Name, computeImageUID(ref, digest.String()))
	assert.Equal(t, "default", image.Namespace)
	assert.Equal(t, "test-registry", image.GetImageMetadata().Registry)
	assert.Equal(t, registryURI, image.GetImageMetadata().RegistryURI)
	assert.Equal(t, repo, image.GetImageMetadata().Repository)
	assert.Equal(t, tag, image.GetImageMetadata().Tag)
	assert.Equal(t, platform.String(), image.GetImageMetadata().Platform)
	assert.Equal(t, digest.String(), image.GetImageMetadata().Digest)

	assert.Len(t, image.Layers, numberOfLayers)
	for i := range numberOfLayers {
		var expectedDigest, expectedDiffID cranev1.Hash
		expectedDigest, expectedDiffID, err = fakeDigestAndDiffID(i)
		require.NoError(t, err)

		layer := image.Layers[i]
		assert.Equal(t, expectedDigest.String(), layer.Digest)
		assert.Equal(t, expectedDiffID.String(), layer.DiffID)

		var command []byte
		command, err = base64.StdEncoding.DecodeString(layer.Command)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("command-%d", i), string(command))
	}
}

func buildImageDetails(digest cranev1.Hash, platform cranev1.Platform) (registryClient.ImageDetails, error) {
	numberOfLayers := 8

	layers := make([]cranev1.Layer, 0, numberOfLayers)
	history := make([]cranev1.History, 0, numberOfLayers*2)

	for i := range numberOfLayers {
		layerDigest, layerDiffID, err := fakeDigestAndDiffID(i)
		if err != nil {
			return registryClient.ImageDetails{}, err
		}

		layer := &registryMocks.Layer{}

		layer.On("Digest").Return(layerDigest, nil)
		layer.On("DiffID").Return(layerDiffID, nil)

		layers = append(layers, layer)

		history = append(history, cranev1.History{
			Author:     fmt.Sprintf("author-layer-%d", i),
			Created:    cranev1.Time{Time: time.Now()},
			CreatedBy:  fmt.Sprintf("command-%d", i),
			Comment:    fmt.Sprintf("comment-layer-%d", i),
			EmptyLayer: false,
		})

		history = append(history, cranev1.History{
			Author:     fmt.Sprintf("author-empty-layer-%d", i),
			Created:    cranev1.Time{Time: time.Now()},
			CreatedBy:  fmt.Sprintf("command-empty-layer-%d", i),
			Comment:    fmt.Sprintf("comment-empty-layer-%d", i),
			EmptyLayer: true,
		})
	}

	return registryClient.ImageDetails{
		Digest:   digest,
		Layers:   layers,
		History:  history,
		Platform: platform,
	}, nil
}

func fakeDigestAndDiffID(layerIndex int) (cranev1.Hash, cranev1.Hash, error) {
	random := strings.Repeat(strconv.Itoa(layerIndex), 63)
	digestStr := fmt.Sprintf("sha256:a%s", random)
	diffIDStr := fmt.Sprintf("sha256:b%s", random)

	digest, err := cranev1.NewHash(digestStr)
	if err != nil {
		return cranev1.Hash{}, cranev1.Hash{}, err
	}

	diffID, err := cranev1.NewHash(diffIDStr)
	if err != nil {
		return cranev1.Hash{}, cranev1.Hash{}, err
	}

	return digest, diffID, nil
}

func TestCreateCatalogHandler_Handle_PrivateRegistry(t *testing.T) {
	r, err := startTestPrivateRegistry(t.Context())
	require.NoError(t, err)
	defer require.NoError(t, r.stop(t.Context()))

	repository, err := name.NewRepository(path.Join(r.registryURL, imageName))
	require.NoError(t, err)
	image, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", r.registryURL, imageName, tag))
	require.NoError(t, err)

	mockRegistryClient := registryMocks.NewClient(t)
	mockRegistryClient.On("ListRepositoryContents", mock.Anything, repository).Return([]string{fmt.Sprintf("%s/%s:%s", r.registryURL, imageName, tag)}, nil)

	platformLinuxAmd64 := cranev1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}
	digestLinuxAmd64, err := cranev1.NewHash(digest)
	require.NoError(t, err)

	indexManifest := cranev1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Manifests: []cranev1.Descriptor{
			{
				MediaType:    types.OCIManifestSchema1,
				Size:         100,
				Digest:       digestLinuxAmd64,
				Data:         []byte(""),
				URLs:         []string{},
				Annotations:  map[string]string{},
				Platform:     &platformLinuxAmd64,
				ArtifactType: "",
			},
		},
	}

	imageIndex := registryMocks.NewImageIndex(t)
	imageIndex.On("IndexManifest").Return(&indexManifest, nil)
	mockRegistryClient.On("GetImageIndex", image).Return(imageIndex, nil)

	imageDetailsLinuxAmd64, err := buildImageDetails(digestLinuxAmd64, platformLinuxAmd64)
	require.NoError(t, err)

	mockRegistryClient.On("GetImageDetails", image, &platformLinuxAmd64).Return(imageDetailsLinuxAmd64, nil)
	mockRegistryClientFactory := func(_ http.RoundTripper) registryClient.Client { return mockRegistryClient }

	mockPublisher := messagingMocks.NewMockPublisher(t)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          r.registryURL,
			Repositories: []string{imageName},
			AuthSecret:   "my-auth-secret",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-auth-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			// dXNlcjpwYXNzd29yZA== -> user:password
			corev1.DockerConfigJsonKey: fmt.Appendf([]byte{},
				`{
					"auths": {
						"%s":{
							"auth": "dXNlcjpwYXNzd29yZA=="
						}
					}
				}`, r.registryURL),
		},
		Type: corev1.SecretTypeDockerConfigJson,
	}

	registryData, err := json.Marshal(registry)
	require.NoError(t, err)

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
			Annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: string(registryData),
			},
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: registry.Name,
		},
	}

	scheme := scheme.Scheme
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = storagev1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = k8sscheme.AddToScheme(scheme)
	require.NoError(t, err)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(registry, scanJob, secret).
		WithStatusSubresource(&v1alpha1.ScanJob{}).
		WithIndex(&storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataRegistry, func(obj client.Object) []string {
			image, ok := obj.(*storagev1alpha1.Image)
			if !ok {
				return nil
			}

			return []string{image.GetImageMetadata().Registry}
		}).
		Build()

	handler := NewCreateCatalogHandler(
		mockRegistryClientFactory,
		k8sClient,
		scheme,
		mockPublisher,
		slog.Default().With("handler", "create_catalog_handler"),
	)

	message, err := json.Marshal(&CreateCatalogMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
	})
	require.NoError(t, err)

	amd64ImageName := computeImageUID(image, digestLinuxAmd64.String())
	expectedMessageAmd64, err := json.Marshal(&GenerateSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		Image: ObjectRef{
			Name:      amd64ImageName,
			Namespace: registry.Namespace,
		},
	})
	require.NoError(t, err)

	mockPublisher.On("Publish",
		mock.Anything,
		GenerateSBOMSubject,
		fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, amd64ImageName),
		expectedMessageAmd64,
	).Return(nil).Once()

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err)

	imageList := &storagev1alpha1.ImageList{}
	err = k8sClient.List(t.Context(), imageList)
	require.NoError(t, err)
	require.Len(t, imageList.Items, 1)

	image1 := imageList.Items[0]

	assert.Equal(t, registry.Namespace, image1.Namespace)
	assert.Equal(t, registry.Name, image1.GetImageMetadata().Registry)
	assert.Equal(t, registry.Spec.URI, image1.GetImageMetadata().RegistryURI)
	assert.Equal(t, imageName, image1.GetImageMetadata().Repository)
	assert.Equal(t, tag, image1.GetImageMetadata().Tag)
	assert.Equal(t, digestLinuxAmd64.String(), image1.GetImageMetadata().Digest)
	assert.Equal(t, platformLinuxAmd64.String(), image1.GetImageMetadata().Platform)
	assert.Len(t, image1.Layers, 8)
	assert.Equal(t, registry.UID, image1.GetOwnerReferences()[0].UID)

	updatedScanJob := &v1alpha1.ScanJob{}
	err = k8sClient.Get(t.Context(), client.ObjectKey{
		Name:      scanJob.Name,
		Namespace: scanJob.Namespace,
	}, updatedScanJob)
	require.NoError(t, err)
	assert.Equal(t, 1, updatedScanJob.Status.ImagesCount)
	assert.Equal(t, 0, updatedScanJob.Status.ScannedImagesCount)
	assert.True(t, updatedScanJob.IsInProgress())
	assert.Equal(t, v1alpha1.ReasonSBOMGenerationInProgress, meta.FindStatusCondition(updatedScanJob.Status.Conditions, v1alpha1.ConditionTypeInProgress).Reason)
}

func Test_isPlatformAllowed(t *testing.T) {
	tests := []struct {
		name             string // description of this test case
		platform         cranev1.Platform
		allowedPlatforms []v1alpha1.Platform
		want             bool
	}{
		{
			name: "no platforms provided",
			platform: cranev1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			allowedPlatforms: []v1alpha1.Platform{},
			want:             true,
		},
		{
			name: "platform matches",
			platform: cranev1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Arch: "amd64",
					OS:   "linux",
				},
			},
			want: true,
		},
		{
			name: "platform doesn't match",
			platform: cranev1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Arch:    "arm",
					OS:      "linux",
					Variant: "v7",
				},
			},
			want: false,
		},
		{
			name: "platform is unknown",
			platform: cranev1.Platform{
				Architecture: "unknown",
				OS:           "unknown",
			},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Arch:    "arm",
					OS:      "linux",
					Variant: "v7",
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPlatformAllowed(tt.platform, tt.allowedPlatforms)
			if got != tt.want {
				t.Errorf("isPlatformAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
