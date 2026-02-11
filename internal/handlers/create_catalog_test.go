package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/name"
	cranev1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	registryClient "github.com/kubewarden/sbomscanner/internal/handlers/registry"
	registryMocks "github.com/kubewarden/sbomscanner/internal/handlers/registry/mocks"
	messagingMocks "github.com/kubewarden/sbomscanner/internal/messaging/mocks"
)

func TestCreateCatalogHandler_Handle(t *testing.T) {
	singleArchRef := name.MustParseReference(imageRefSingleArch)
	multiArchRef := name.MustParseReference(imageRefMultiArch)
	multiArchWithUnknownPlatformRef := name.MustParseReference(imageRefMultiArchWithUnknownPlatform)
	helmChartRef := name.MustParseReference(artifactRefHelmChart)
	kubewardenPolicyRef := name.MustParseReference(artifactRefKubewardenPolicy)

	testRegistry, err := runTestRegistry(t.Context(), []name.Reference{
		singleArchRef,
		multiArchRef,
		multiArchWithUnknownPlatformRef,
		helmChartRef,
		kubewardenPolicyRef,
	}, false)
	require.NoError(t, err)
	defer testRegistry.Terminate(t.Context())

	testPrivateRegistry, err := runTestRegistry(t.Context(), []name.Reference{
		singleArchRef,
	}, true)
	require.NoError(t, err)
	defer testPrivateRegistry.Terminate(t.Context())

	tests := []struct {
		name           string
		registry       *v1alpha1.Registry
		authSecret     *corev1.Secret
		existingImages []*storagev1alpha1.Image
		expectedImages []*storagev1alpha1.Image
	}{
		{
			name: "catalog all images",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI:         testRegistry.RegistryName,
					CatalogType: v1alpha1.CatalogTypeOCIDistribution,
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, singleArchRef.Context().RepositoryStr(), singleArchRef.Identifier(), "linux/amd64", imageDigestSingleArch, ""),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm/v6", imageDigestLinuxArmV6MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm/v7", imageDigestLinuxArmV7MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm64/v8", imageDigestLinuxArm64V8MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/386", imageDigestLinux386MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/ppc64le", imageDigestLinuxPpc64leMultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/s390x", imageDigestLinuxS390xMultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchWithUnknownPlatformRef.Context().RepositoryStr(), multiArchWithUnknownPlatformRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArchWithUnknownPlatform, imageIndexDigestMultiArchWithUnknownPlatform),
				imageFactory(testRegistry.RegistryName, multiArchWithUnknownPlatformRef.Context().RepositoryStr(), multiArchWithUnknownPlatformRef.Identifier(), "linux/arm64", imageDigestLinuxArm64MultiArchWithUnknownPlatform, imageIndexDigestMultiArchWithUnknownPlatform),
			},
		},
		{
			name: "singlearch image",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: singleArchRef.Context().RepositoryStr(),
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, singleArchRef.Context().RepositoryStr(), singleArchRef.Identifier(), "linux/amd64", imageDigestSingleArch, ""),
			},
		},
		{
			name: "multiarch image",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: multiArchRef.Context().RepositoryStr(),
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm/v6", imageDigestLinuxArmV6MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm/v7", imageDigestLinuxArmV7MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm64/v8", imageDigestLinuxArm64V8MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/386", imageDigestLinux386MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/ppc64le", imageDigestLinuxPpc64leMultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/s390x", imageDigestLinuxS390xMultiArch, imageIndexDigestMultiArch),
			},
		},
		{
			name: "multiarch image with platform filter",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: multiArchRef.Context().RepositoryStr(),
						},
					},
					Platforms: []v1alpha1.Platform{
						{OS: "linux", Architecture: "arm", Variant: "v7"},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm/v7", imageDigestLinuxArmV7MultiArch, imageIndexDigestMultiArch),
			},
		},
		{
			name: "tag filter does not match",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: singleArchRef.Context().RepositoryStr(),
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag ends with '-dev'",
									Expression: "tag.endsWith('-dev')",
								},
							},
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{},
		},
		{
			name: "tag filter matches",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: singleArchRef.Context().RepositoryStr(),
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag version is > than 1.20.0",
									Expression: "semver(tag, true).isGreaterThan(semver('1.20.0'))",
								},
							},
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, singleArchRef.Context().RepositoryStr(), singleArchRef.Identifier(), "linux/amd64", imageDigestSingleArch, ""),
			},
		},
		{
			name: "multiarch image with unknown/unknown platform",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: multiArchWithUnknownPlatformRef.Context().RepositoryStr(),
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, multiArchWithUnknownPlatformRef.Context().RepositoryStr(), multiArchWithUnknownPlatformRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArchWithUnknownPlatform, imageIndexDigestMultiArchWithUnknownPlatform),
				imageFactory(testRegistry.RegistryName, multiArchWithUnknownPlatformRef.Context().RepositoryStr(), multiArchWithUnknownPlatformRef.Identifier(), "linux/arm64", imageDigestLinuxArm64MultiArchWithUnknownPlatform, imageIndexDigestMultiArchWithUnknownPlatform),
			},
		},
		{
			name: "obsolete images are deleted",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: multiArchRef.Context().RepositoryStr(),
						},
						{
							Name: singleArchRef.Context().RepositoryStr(),
							// This match condition will filter out the existing single-arch image
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag version is > than 1.28.0",
									Expression: "semver(tag, true).isGreaterThan(semver('1.28.0'))",
								},
							},
						},
					},
					Platforms: []v1alpha1.Platform{
						{OS: "linux", Architecture: "amd64"},
					},
				},
			},
			existingImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/arm64", imageDigestLinuxArm64V8MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArch, imageIndexDigestMultiArch),
				imageFactory(testRegistry.RegistryName, singleArchRef.Context().RepositoryStr(), singleArchRef.Identifier(), "linux/amd64", imageDigestSingleArch, ""),
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testRegistry.RegistryName, multiArchRef.Context().RepositoryStr(), multiArchRef.Identifier(), "linux/amd64", imageDigestLinuxAmd64MultiArch, imageIndexDigestMultiArch),
			},
		},
		{
			name: "repository with non-image artifacts",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: testRegistry.RegistryName,
					Repositories: []v1alpha1.Repository{
						{
							Name: helmChartRef.Context().RepositoryStr(),
						},
						{
							Name: kubewardenPolicyRef.Context().RepositoryStr(),
						},
					},
				},
			},
			expectedImages: []*storagev1alpha1.Image{},
		},
		{
			name: "private registry",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI:        testPrivateRegistry.RegistryName,
					AuthSecret: "test-registry-auth-secret",
				},
			},
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry-auth-secret",
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
				}`, testPrivateRegistry.RegistryName),
				},
				Type: corev1.SecretTypeDockerConfigJson,
			},
			expectedImages: []*storagev1alpha1.Image{
				imageFactory(testPrivateRegistry.RegistryName, singleArchRef.Context().RepositoryStr(), singleArchRef.Identifier(), "linux/amd64", imageDigestSingleArch, ""),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registryData, err := json.Marshal(test.registry)
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
					Registry: test.registry.Name,
				},
			}

			scheme := scheme.Scheme
			err = corev1.AddToScheme(scheme)
			require.NoError(t, err)
			err = storagev1alpha1.AddToScheme(scheme)
			require.NoError(t, err)
			err = v1alpha1.AddToScheme(scheme)
			require.NoError(t, err)

			runtimeObjects := []runtime.Object{test.registry, scanJob}
			for _, img := range test.existingImages {
				runtimeObjects = append(runtimeObjects, img)
			}
			if test.authSecret != nil {
				runtimeObjects = append(runtimeObjects, test.authSecret)
			}

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(runtimeObjects...).
				WithStatusSubresource(&v1alpha1.ScanJob{}).
				WithIndex(&storagev1alpha1.Image{}, storagev1alpha1.IndexImageMetadataRegistry, func(obj client.Object) []string {
					image, ok := obj.(*storagev1alpha1.Image)
					if !ok {
						return nil
					}
					return []string{image.GetImageMetadata().Registry}
				}).
				Build()

			registryClientFactory := func(rt http.RoundTripper) *registryClient.Client {
				return registryClient.NewClient(rt, slog.Default())
			}

			mockPublisher := messagingMocks.NewMockPublisher(t)
			for _, expectedImage := range test.expectedImages {
				messageID := fmt.Sprintf("generateSBOM/%s/%s", scanJob.UID, expectedImage.Name)
				expectedMessage, err := json.Marshal(&GenerateSBOMMessage{
					BaseMessage: BaseMessage{
						ScanJob: ObjectRef{
							Name:      scanJob.Name,
							Namespace: scanJob.Namespace,
							UID:       string(scanJob.UID),
						},
					},
					Image: ObjectRef{
						Name:      expectedImage.Name,
						Namespace: expectedImage.Namespace,
					},
				})
				require.NoError(t, err)

				mockPublisher.On("Publish", mock.Anything, GenerateSBOMSubject, messageID, expectedMessage).Return(nil).Once()
			}

			handler := NewCreateCatalogHandler(registryClientFactory, k8sClient, scheme, mockPublisher, "sbomscanner", slog.Default())

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

			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			// Verify images match expected
			imageList := &storagev1alpha1.ImageList{}
			err = k8sClient.List(context.Background(), imageList)
			require.NoError(t, err)
			require.Len(t, imageList.Items, len(test.expectedImages))

			// Verify all expected images exist in actual results
			for _, expected := range test.expectedImages {
				assert.True(t, slices.ContainsFunc(imageList.Items, func(actual storagev1alpha1.Image) bool {
					return expected.Name == actual.Name && expected.ImageMetadata == actual.ImageMetadata
				}), "Expected image not found: %+v %+v", expected.ImageMetadata, imageList.Items)
			}

			// Verify obsolete images were deleted
			for _, obsoleteImg := range test.existingImages {
				err = k8sClient.Get(context.Background(), client.ObjectKey{
					Name:      obsoleteImg.Name,
					Namespace: obsoleteImg.Namespace,
				}, &storagev1alpha1.Image{})
				if !slices.ContainsFunc(test.expectedImages, func(expected *storagev1alpha1.Image) bool {
					return expected.ImageMetadata.Digest == obsoleteImg.ImageMetadata.Digest
				}) {
					assert.True(t, apierrors.IsNotFound(err), "Obsolete image %s should be deleted", obsoleteImg.Name)
				}
			}

			// Verify ScanJob status was updated
			updatedScanJob := &v1alpha1.ScanJob{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
			}, updatedScanJob)
			require.NoError(t, err)
			assert.Equal(t, len(test.expectedImages), updatedScanJob.Status.ImagesCount)
		})
	}
}

func TestCreateCatalogHandler_Handle_StopProcessing(t *testing.T) {
	// A registry with a single repository and platform
	// so that only one image is created during the test
	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI: "ghcr.io",
			Repositories: []v1alpha1.Repository{
				{
					Name: "kubewarden/sbomscanner/test-assets/golang",
				},
			},
			Platforms: []v1alpha1.Platform{
				{
					OS:           "linux",
					Architecture: "amd64",
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
			Registry: "test-registry",
		},
	}

	tests := []struct {
		name               string
		existingObjects    []runtime.Object
		setup              func(client.Client, *v1alpha1.ScanJob)
		interceptorFuncs   interceptor.Funcs
		expectedImageCount int
	}{
		{
			name:               "scanjob not found initially",
			existingObjects:    []runtime.Object{registry},
			setup:              func(_ client.Client, _ *v1alpha1.ScanJob) {},
			interceptorFuncs:   interceptor.Funcs{},
			expectedImageCount: 0,
		},
		{
			name:            "scanjob with different UID initially",
			existingObjects: []runtime.Object{registry},
			setup: func(k8sClient client.Client, scanJob *v1alpha1.ScanJob) {
				// Create a scanjob with different UID before test starts
				differentUIDScanJob := scanJob.DeepCopy()
				differentUIDScanJob.UID = "test-scanjob-different-uid"
				err := k8sClient.Create(context.Background(), differentUIDScanJob)
				require.NoError(t, err)
			},
			interceptorFuncs:   interceptor.Funcs{},
			expectedImageCount: 0,
		},
		{
			name:            "scanjob deleted before image creation",
			existingObjects: []runtime.Object{registry, scanJob},
			setup:           func(_ client.Client, _ *v1alpha1.ScanJob) {},
			interceptorFuncs: interceptor.Funcs{
				List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					// Delete the scanjob when listing existing images,
					// which occurs before creating new images.
					if _, ok := list.(*storagev1alpha1.ImageList); ok {
						err := client.Delete(ctx, scanJob)
						require.NoError(t, err)
					}
					return client.List(ctx, list, opts...)
				},
			},
			expectedImageCount: 0,
		},
		{
			name:            "scanjob with different UID before image creation",
			existingObjects: []runtime.Object{registry, scanJob},
			setup:           func(_ client.Client, _ *v1alpha1.ScanJob) {},
			interceptorFuncs: interceptor.Funcs{
				List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					// Replace the scanjob with different UID when listing existing images,
					// which occurs before creating new images.
					if _, ok := list.(*storagev1alpha1.ImageList); ok {
						err := client.Delete(ctx, scanJob)
						require.NoError(t, err)

						differentUIDScanJob := scanJob.DeepCopy()
						differentUIDScanJob.UID = "test-scanjob-different-uid"
						differentUIDScanJob.ResourceVersion = ""
						err = client.Create(ctx, differentUIDScanJob)
						require.NoError(t, err)
					}
					return client.List(ctx, list, opts...)
				},
			},
		},
		{
			name:            "scanjob deleted before status update",
			existingObjects: []runtime.Object{registry, scanJob},
			setup:           func(_ client.Client, _ *v1alpha1.ScanJob) {},
			interceptorFuncs: interceptor.Funcs{
				Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					// When creating the only image discovered delete the scanjob
					if _, ok := obj.(*storagev1alpha1.Image); ok {
						err := client.Delete(ctx, scanJob)
						require.NoError(t, err)
					}
					return client.Create(ctx, obj, opts...)
				},
			},
			expectedImageCount: 1,
		},
		{
			name:            "scanjob with different UID before status update",
			existingObjects: []runtime.Object{registry, scanJob},
			setup:           func(_ client.Client, _ *v1alpha1.ScanJob) {},
			interceptorFuncs: interceptor.Funcs{
				Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					// When creating the only image discovered replace the scanjob with a new one with a different UID
					if _, ok := obj.(*storagev1alpha1.Image); ok {
						err := client.Delete(ctx, scanJob)
						require.NoError(t, err)

						differentUIDScanJob := scanJob.DeepCopy()
						differentUIDScanJob.UID = "test-scanjob-different-uid"
						differentUIDScanJob.ResourceVersion = ""
						err = client.Create(ctx, differentUIDScanJob)
						require.NoError(t, err)
					}
					return client.Create(ctx, obj, opts...)
				},
			},
			expectedImageCount: 1,
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
			k8sClientWithInterceptors := interceptor.NewClient(k8sClient, test.interceptorFuncs)

			test.setup(k8sClient, scanJob)

			registryClient := func(rt http.RoundTripper) *registryClient.Client {
				return registryClient.NewClient(rt, slog.Default())
			}

			mockPublisher := messagingMocks.NewMockPublisher(t)

			handler := NewCreateCatalogHandler(registryClient, k8sClientWithInterceptors, scheme, mockPublisher, "sbomscanner", slog.Default())

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

			// Should return nil (no error) when resource doesn't exist or UID changes mid-processing
			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			imageList := &storagev1alpha1.ImageList{}
			err = k8sClient.List(context.Background(), imageList)
			require.NoError(t, err)
			assert.Len(t, imageList.Items, test.expectedImageCount, "unexpected number of images created")

			// Ensure no SBOM generation messages were published
			mockPublisher.AssertNotCalled(t, "Publish", mock.Anything, GenerateSBOMSubject, mock.Anything, mock.Anything)
		})
	}
}

func TestCreateCatalogHandler_imageDetailsToImage(t *testing.T) {
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
			URI: registryURI,
			Repositories: []v1alpha1.Repository{
				{
					Name: repo,
				},
			},
		},
	}

	scheme := scheme.Scheme
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	image, err := imageDetailsToImage(ref, details, registry, scheme, "test-index-digest")
	require.NoError(t, err)

	assert.Equal(t, image.Name, computeImageUID(ref.Context().Name(), ref.Identifier(), digest.String()))
	assert.Equal(t, "default", image.Namespace)
	assert.Equal(t, "test-registry", image.GetImageMetadata().Registry)
	assert.Equal(t, registryURI, image.GetImageMetadata().RegistryURI)
	assert.Equal(t, repo, image.GetImageMetadata().Repository)
	assert.Equal(t, tag, image.GetImageMetadata().Tag)
	assert.Equal(t, platform.String(), image.GetImageMetadata().Platform)
	assert.Equal(t, digest.String(), image.GetImageMetadata().Digest)
	assert.Equal(t, "test-index-digest", image.GetImageMetadata().IndexDigest)

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

		layer := &registryMocks.MockLayer{}

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
