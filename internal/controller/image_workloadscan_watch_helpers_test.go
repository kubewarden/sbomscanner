package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

func TestWorkloadScanPredicate(t *testing.T) {
	predicate := workloadScanPredicate()

	tests := []struct {
		name     string
		object   client.Object
		expected bool
	}{
		{
			name: "image with workloadscan label",
			object: &storagev1alpha1.Image{
				Labels: map[string]string{
					api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
				},
			},
			expected: true,
		},
		{
			name: "image without workloadscan label",
			object: &storagev1alpha1.Image{
				Labels: map[string]string{
					"other-label": "other-value",
				},
			},
			expected: false,
		},
		{
			name: "image with no labels",
			object: &storagev1alpha1.Image{
				ObjectMeta: metav1.ObjectMeta{},
			},
			expected: false,
		},
		{
			name: "image with workloadscan label set to wrong value",
			object: &storagev1alpha1.Image{
				Labels: map[string]string{
					api.LabelWorkloadScanKey: "false",
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := predicate.Generic(event.GenericEvent{Object: test.object})
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestMapWorkloadScanReportToImages(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))

	tests := []struct {
		name             string
		workloadScan     client.Object
		existingImages   []storagev1alpha1.Image
		expectedRequests int
	}{
		{
			name: "workload scan with matching images",
			workloadScan: &storagev1alpha1.WorkloadScanReport{
				Name:      "test-workload",
				Namespace: "default",
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "nginx",
								Tag:        "1.19",
							},
						},
					},
				},
			},
			existingImages: []storagev1alpha1.Image{
				{
					Name:       "image-1",
					Namespace:  "sbomscanner",
					Registry:   "docker-hub",
					Repository: "nginx",
					Tag:        "1.19",
				},
			},
			expectedRequests: 1,
		},
		{
			name: "workload scan with no matching images",
			workloadScan: &storagev1alpha1.WorkloadScanReport{
				Name:      "test-workload",
				Namespace: "default",
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "nginx",
								Tag:        "1.19",
							},
						},
					},
				},
			},
			existingImages:   []storagev1alpha1.Image{},
			expectedRequests: 0,
		},
		{
			name: "workload scan with duplicate image refs deduplicates",
			workloadScan: &storagev1alpha1.WorkloadScanReport{
				Name:      "test-workload",
				Namespace: "default",
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "nginx",
								Tag:        "1.19",
							},
						},
						{
							Name: "sidecar",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "nginx",
								Tag:        "1.19",
							},
						},
					},
				},
			},
			existingImages: []storagev1alpha1.Image{
				{
					Name:       "image-1",
					Namespace:  "sbomscanner",
					Registry:   "docker-hub",
					Repository: "nginx",
					Tag:        "1.19",
				},
			},
			expectedRequests: 1,
		},
		{
			name: "workload scan with multiple different image refs",
			workloadScan: &storagev1alpha1.WorkloadScanReport{
				Name:      "test-workload",
				Namespace: "default",
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "nginx",
								Tag:        "1.19",
							},
						},
						{
							Name: "sidecar",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "docker-hub",
								Namespace:  "sbomscanner",
								Repository: "envoy",
								Tag:        "latest",
							},
						},
					},
				},
			},
			existingImages: []storagev1alpha1.Image{
				{
					Name:       "image-nginx",
					Namespace:  "sbomscanner",
					Registry:   "docker-hub",
					Repository: "nginx",
					Tag:        "1.19",
				},
				{
					Name:       "image-envoy",
					Namespace:  "sbomscanner",
					Registry:   "docker-hub",
					Repository: "envoy",
					Tag:        "latest",
				},
			},
			expectedRequests: 2,
		},
		{
			name:             "non-WorkloadScanReport object returns nil",
			workloadScan:     &corev1.Pod{},
			existingImages:   []storagev1alpha1.Image{},
			expectedRequests: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := make([]client.Object, 0, len(test.existingImages))
			for index := range test.existingImages {
				objects = append(objects, &test.existingImages[index])
			}

			clientBuilder := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...)

			if len(test.existingImages) > 0 {
				clientBuilder = clientBuilder.WithIndex(
					&storagev1alpha1.Image{},
					storagev1alpha1.IndexImageMetadataComposite,
					indexImageByMetadata,
				)
			}

			fakeClient := clientBuilder.Build()

			mapFunction := mapWorkloadScanReportToImages(fakeClient)
			requests := mapFunction(context.Background(), test.workloadScan)

			if test.expectedRequests == 0 {
				assert.Empty(t, requests)
			} else {
				assert.Len(t, requests, test.expectedRequests)
			}
		})
	}
}

func TestMapWorkloadScanReportToImages_VerifiesRequestContent(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))

	image := &storagev1alpha1.Image{
		Name:       "my-image",
		Namespace:  "sbomscanner",
		Registry:   "docker-hub",
		Repository: "nginx",
		Tag:        "1.19",
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(image).
		WithIndex(
			&storagev1alpha1.Image{},
			storagev1alpha1.IndexImageMetadataComposite,
			indexImageByMetadata,
		).
		Build()

	workloadScan := &storagev1alpha1.WorkloadScanReport{
		Name:      "test-workload",
		Namespace: "default",
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: []storagev1alpha1.ContainerRef{
				{
					Name: "app",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "docker-hub",
						Namespace:  "sbomscanner",
						Repository: "nginx",
						Tag:        "1.19",
					},
				},
			},
		},
	}

	mapFunction := mapWorkloadScanReportToImages(fakeClient)
	requests := mapFunction(context.Background(), workloadScan)

	require.Len(t, requests, 1)
	assert.Equal(t, "my-image", requests[0].Name)
	assert.Equal(t, "sbomscanner", requests[0].Namespace)
}
