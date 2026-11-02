package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestRegistryFromScanJob(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		expectedError string
	}{
		{
			name: "snapshot of the referenced registry in the ScanJob namespace",
			annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: `{"metadata":{"name":"my-registry","namespace":"tenant-ns"},"spec":{"authSecret":"my-secret"}}`,
			},
		},
		{
			name:          "missing annotation",
			annotations:   nil,
			expectedError: "does not have a registry annotation",
		},
		{
			name: "invalid JSON",
			annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: "not json",
			},
			expectedError: "cannot unmarshal registry data",
		},
		{
			name: "snapshot in another namespace",
			annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: `{"metadata":{"name":"my-registry","namespace":"kube-system"},"spec":{"authSecret":"my-secret"}}`,
			},
			expectedError: "refers to registry kube-system/my-registry, expected tenant-ns/my-registry",
		},
		{
			name: "snapshot of another registry",
			annotations: map[string]string{
				v1alpha1.AnnotationScanJobRegistryKey: `{"metadata":{"name":"other-registry","namespace":"tenant-ns"}}`,
			},
			expectedError: "refers to registry tenant-ns/other-registry, expected tenant-ns/my-registry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanJob := &v1alpha1.ScanJob{
				Name:        "my-scanjob",
				Namespace:   "tenant-ns",
				Annotations: test.annotations,
				Spec:        v1alpha1.ScanJobSpec{Registry: "my-registry"},
			}

			registry, err := registryFromScanJob(scanJob)

			if test.expectedError != "" {
				require.ErrorContains(t, err, test.expectedError)
				assert.Nil(t, registry)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "tenant-ns", registry.Namespace)
			assert.Equal(t, "my-registry", registry.Name)
			assert.Equal(t, "my-secret", registry.Spec.AuthSecret)
		})
	}
}
