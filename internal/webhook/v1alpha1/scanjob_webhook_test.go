package v1alpha1

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestScanJobDefaulter_Default(t *testing.T) {
	scanJob := &v1alpha1.ScanJob{
		Name:      "test-scan-job",
		Namespace: "default",
		Spec: v1alpha1.ScanJobSpec{
			Registry: "registry.example.com",
		},
	}

	defaulter := &ScanJobCustomDefaulter{}

	err := defaulter.Default(t.Context(), scanJob)
	require.NoError(t, err)

	timestampStr := scanJob.Annotations[v1alpha1.AnnotationScanJobCreationTimestampKey]
	assert.NotEmpty(t, timestampStr)

	_, err = time.Parse(time.RFC3339Nano, timestampStr)
	require.NoError(t, err)
}

func TestScanJobCustomValidator_ValidateCreate(t *testing.T) {
	defaultRegistry := &v1alpha1.Registry{
		Name:      "registry.example.com",
		Namespace: "default",
	}

	tests := []struct {
		name             string
		existingScanJob  *v1alpha1.ScanJob
		existingRegistry *v1alpha1.Registry
		scanJob          *v1alpha1.ScanJob
		expectedError    string
		expectedField    string
	}{
		{
			name:             "should admit creation when no existing jobs with same registry",
			existingScanJob:  nil,
			existingRegistry: defaultRegistry,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
		},
		{
			name: "should deny creation when existing job with same registry is pending",
			existingScanJob: func() *v1alpha1.ScanJob {
				job := &v1alpha1.ScanJob{
					Name:      "existing-job",
					Namespace: "default",
					Spec: v1alpha1.ScanJobSpec{
						Registry: "registry.example.com",
					},
				}
				job.InitializeConditions()
				return job
			}(),
			existingRegistry: defaultRegistry,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
			expectedField: "spec.registry",
			expectedError: "is already running",
		},
		{
			name: "should deny creation when existing job with same registry is in progress",
			existingScanJob: func() *v1alpha1.ScanJob {
				job := &v1alpha1.ScanJob{
					Name:      "existing-job",
					Namespace: "default",
					Spec: v1alpha1.ScanJobSpec{
						Registry: "registry.example.com",
					},
				}
				job.InitializeConditions()
				job.MarkInProgress(v1alpha1.ReasonScanJobImageScanInProgress, "Image scan in progress")
				return job
			}(),
			existingRegistry: defaultRegistry,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
			expectedField: "spec.registry",
			expectedError: "is already running",
		},
		{
			name: "should admit creation when existing job with same registry is completed",
			existingScanJob: func() *v1alpha1.ScanJob {
				job := &v1alpha1.ScanJob{
					Name:      "existing-job",
					Namespace: "default",
					Spec: v1alpha1.ScanJobSpec{
						Registry: "registry.example.com",
					},
				}
				job.InitializeConditions()
				job.MarkComplete(v1alpha1.ReasonScanJobAllImagesScanned, "Done")
				return job
			}(),
			existingRegistry: defaultRegistry,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
		},
		{
			name: "should admit creation when existing job with same registry failed",
			existingScanJob: func() *v1alpha1.ScanJob {
				job := &v1alpha1.ScanJob{
					Name:      "existing-job",
					Namespace: "default",
					Spec: v1alpha1.ScanJobSpec{
						Registry: "registry.example.com",
					},
				}
				job.InitializeConditions()
				job.MarkFailed(v1alpha1.ReasonScanJobInternalError, "Failed")
				return job
			}(),
			existingRegistry: defaultRegistry,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
		},
		{
			name:             "should deny creation when referenced Registry does not exist",
			existingScanJob:  nil,
			existingRegistry: nil,
			scanJob: &v1alpha1.ScanJob{
				Name:      "test-scan-job",
				Namespace: "default",
				Spec: v1alpha1.ScanJobSpec{
					Registry: "registry.example.com",
				},
			},
			expectedField: "spec.registry",
			expectedError: "Not found",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, v1alpha1.AddToScheme(scheme))

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithIndex(&v1alpha1.ScanJob{}, v1alpha1.IndexScanJobSpecRegistry, func(obj client.Object) []string {
					scanJob, ok := obj.(*v1alpha1.ScanJob)
					if !ok {
						panic(fmt.Sprintf("expected a ScanJob object but got %T", obj))
					}

					return []string{scanJob.Spec.Registry}
				}).
				Build()
			validator := ScanJobCustomValidator{client: client}

			if test.existingScanJob != nil {
				require.NoError(t, client.Create(t.Context(), test.existingScanJob))
			}
			if test.existingRegistry != nil {
				require.NoError(t, client.Create(t.Context(), test.existingRegistry.DeepCopy()))
			}

			warnings, err := validator.ValidateCreate(t.Context(), test.scanJob)

			if test.expectedError != "" {
				require.Error(t, err)
				statusErr, ok := err.(interface{ Status() metav1.Status })
				require.True(t, ok)
				details := statusErr.Status().Details
				require.NotNil(t, details)
				require.Len(t, details.Causes, 1)
				assert.Equal(t, test.expectedField, details.Causes[0].Field)
				assert.Contains(t, details.Causes[0].Message, test.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Empty(t, warnings)
		})
	}
}

func TestScanJobCustomValidator_RegistrySnapshotOnCreate(t *testing.T) {
	const controllerUser = "system:serviceaccount:sbomscanner:sbomscanner-controller"
	const otherUser = "system:serviceaccount:default:other-sa"

	tests := []struct {
		name            string
		annotations     map[string]string
		username        string
		expectForbidden bool
	}{
		{
			name:            "should deny a registry snapshot set by other user",
			annotations:     map[string]string{v1alpha1.AnnotationScanJobRegistryKey: `{"metadata":{"name":"registry.example.com","namespace":"kube-system"}}`},
			username:        otherUser,
			expectForbidden: true,
		},
		{
			name:            "should allow a registry snapshot set by allowed service account",
			annotations:     map[string]string{v1alpha1.AnnotationScanJobRegistryKey: `{"metadata":{"name":"registry.example.com","namespace":"default"}}`},
			username:        controllerUser,
			expectForbidden: false,
		},
		{
			name:            "should allow a ScanJob without a registry snapshot by other user",
			annotations:     nil,
			username:        otherUser,
			expectForbidden: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, v1alpha1.AddToScheme(scheme))

			registry := &v1alpha1.Registry{
				Name:      "registry.example.com",
				Namespace: "default",
				Spec:      v1alpha1.RegistrySpec{URI: "registry.example.com"},
			}
			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(registry).
				WithIndex(&v1alpha1.ScanJob{}, v1alpha1.IndexScanJobSpecRegistry, func(obj client.Object) []string {
					scanJob, ok := obj.(*v1alpha1.ScanJob)
					if !ok {
						panic(fmt.Sprintf("expected a ScanJob object but got %T", obj))
					}
					return []string{scanJob.Spec.Registry}
				}).
				Build()
			validator := &ScanJobCustomValidator{
				client:                  k8sClient,
				serviceAccountNamespace: "sbomscanner",
				serviceAccountName:      "sbomscanner-controller",
				logger:                  logr.Discard(),
			}

			scanJob := &v1alpha1.ScanJob{
				Name:        "test-scan-job",
				Namespace:   "default",
				Annotations: test.annotations,
				Spec:        v1alpha1.ScanJobSpec{Registry: "registry.example.com"},
			}

			ctx := admission.NewContextWithRequest(t.Context(), admission.Request{
				UserInfo: authenticationv1.UserInfo{Username: test.username},
			})

			warnings, err := validator.ValidateCreate(ctx, scanJob)

			if test.expectForbidden {
				require.Error(t, err)
				assert.True(t, apierrors.IsForbidden(err), "expected a forbidden error, got: %v", err)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, warnings)
		})
	}
}

func TestScanJobCustomValidator_RegistrySnapshotOnUpdate(t *testing.T) {
	const controllerUser = "system:serviceaccount:sbomscanner:sbomscanner-controller"
	const otherUser = "system:serviceaccount:default:other-sa"
	const snapshot = `{"metadata":{"name":"registry.example.com","namespace":"default"}}`
	const forgedSnapshot = `{"metadata":{"name":"registry.example.com","namespace":"kube-system"}}`

	tests := []struct {
		name            string
		oldAnnotations  map[string]string
		newAnnotations  map[string]string
		username        string
		expectForbidden bool
	}{
		{
			name:            "should deny adding a registry snapshot by other user",
			oldAnnotations:  nil,
			newAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: forgedSnapshot},
			username:        otherUser,
			expectForbidden: true,
		},
		{
			name:            "should deny changing the registry snapshot by other user",
			oldAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: snapshot},
			newAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: forgedSnapshot},
			username:        otherUser,
			expectForbidden: true,
		},
		{
			name:            "should deny removing the registry snapshot by other user",
			oldAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: snapshot},
			newAnnotations:  nil,
			username:        otherUser,
			expectForbidden: true,
		},
		{
			name:            "should allow an update that keeps the registry snapshot by other user",
			oldAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: snapshot},
			newAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: snapshot, "example.com/other": "value"},
			username:        otherUser,
			expectForbidden: false,
		},
		{
			name:            "should allow adding a registry snapshot by allowed service account",
			oldAnnotations:  nil,
			newAnnotations:  map[string]string{v1alpha1.AnnotationScanJobRegistryKey: snapshot},
			username:        controllerUser,
			expectForbidden: false,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	validator := &ScanJobCustomValidator{
		client:                  fake.NewClientBuilder().WithScheme(scheme).Build(),
		serviceAccountNamespace: "sbomscanner",
		serviceAccountName:      "sbomscanner-controller",
		logger:                  logr.Discard(),
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldObj := &v1alpha1.ScanJob{
				Name: "test-scan-job", Namespace: "default",
				Annotations: test.oldAnnotations,
				Spec:        v1alpha1.ScanJobSpec{Registry: "registry.example.com"},
			}
			newObj := oldObj.DeepCopy()
			newObj.Annotations = test.newAnnotations

			ctx := admission.NewContextWithRequest(t.Context(), admission.Request{
				UserInfo: authenticationv1.UserInfo{Username: test.username},
			})

			warnings, err := validator.ValidateUpdate(ctx, oldObj, newObj)

			if test.expectForbidden {
				require.Error(t, err)
				assert.True(t, apierrors.IsForbidden(err), "expected a forbidden error, got: %v", err)
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, warnings)
		})
	}
}

func TestScanJobCustomValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name           string
		oldSpec        v1alpha1.ScanJobSpec
		newSpec        v1alpha1.ScanJobSpec
		expectedFields []string
	}{
		{
			name:           "registry changed is rejected",
			oldSpec:        v1alpha1.ScanJobSpec{Registry: "registry.example.com"},
			newSpec:        v1alpha1.ScanJobSpec{Registry: "new-registry.example.com"},
			expectedFields: []string{"spec.registry"},
		},
		{
			name: "repositories changed is rejected",
			oldSpec: v1alpha1.ScanJobSpec{
				Registry:     "registry.example.com",
				Repositories: []v1alpha1.ScanJobRepository{{Name: "foo/bar"}},
			},
			newSpec: v1alpha1.ScanJobSpec{
				Registry:     "registry.example.com",
				Repositories: []v1alpha1.ScanJobRepository{{Name: "foo/baz"}},
			},
			expectedFields: []string{"spec.repositories"},
		},
		{
			name:    "no changes is admitted",
			oldSpec: v1alpha1.ScanJobSpec{Registry: "registry.example.com"},
			newSpec: v1alpha1.ScanJobSpec{Registry: "registry.example.com"},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	validator := ScanJobCustomValidator{client: fake.NewClientBuilder().WithScheme(scheme).Build()}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldObj := &v1alpha1.ScanJob{
				Name: "test-scan-job", Namespace: "default",
				Spec: test.oldSpec,
			}
			newObj := &v1alpha1.ScanJob{
				Name: "test-scan-job", Namespace: "default",
				Spec: test.newSpec,
			}

			warnings, err := validator.ValidateUpdate(t.Context(), oldObj, newObj)
			assert.Empty(t, warnings)

			if len(test.expectedFields) == 0 {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			statusErr, ok := err.(interface{ Status() metav1.Status })
			require.True(t, ok)
			details := statusErr.Status().Details
			require.NotNil(t, details)
			require.Len(t, details.Causes, len(test.expectedFields))
			for i, field := range test.expectedFields {
				assert.Equal(t, field, details.Causes[i].Field)
				assert.Contains(t, details.Causes[i].Message, "immutable")
			}
		})
	}
}
