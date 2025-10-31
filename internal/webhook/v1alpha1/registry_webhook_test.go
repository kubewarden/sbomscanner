package v1alpha1

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

type registryTestCase struct {
	name          string
	registry      *v1alpha1.Registry
	expectedError string
	expectedField string
}

func TestRegistryDefaulter_Default(t *testing.T) {
	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:         "registry.test.local",
			CatalogType: "",
		},
	}

	defaulter := &RegistryCustomDefaulter{}

	err := defaulter.Default(t.Context(), registry)
	require.NoError(t, err)

	assert.NotEmpty(t, registry.Spec.CatalogType)
	assert.Equal(t, defaultCatalogType, registry.Spec.CatalogType)
}

var registryTestCases = []registryTestCase{
	{
		name: "should admit creation when scanInterval is nil",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI:          "registry.example.com",
				ScanInterval: nil,
			},
		},
	},
	{
		name: "should admit creation when scanInterval is exactly 1 minute",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI: "registry.example.com",
				ScanInterval: &metav1.Duration{
					Duration: time.Minute,
				},
			},
		},
	},
	{
		name: "should admit creation when scanInterval is greater than 1 minute",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI: "registry.test.local",
				ScanInterval: &metav1.Duration{
					Duration: 1 * time.Hour,
				},
			},
		},
	},
	{
		name: "should deny creation when scanInterval is less than 1 minute",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI: "registry.test.local",
				ScanInterval: &metav1.Duration{
					Duration: 30 * time.Second,
				},
			},
		},
		expectedField: "spec.scanInterval",
		expectedError: "scanInterval must be at least 1 minute",
	},
	{
		name: "should allow creation when catalogType is NoCatalog and Repositories are provided",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: "NoCatalog",
				Repositories: []string{
					"repo-test-1",
					"repo-test-2",
					"repo-test-3",
				},
			},
		},
	},
	{
		name: "should deny creation when catalogType is NoCatalog and Repositories are not provided",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: "NoCatalog",
			},
		},
		expectedField: "spec.repositories",
		expectedError: "repositories must be explicitly provided when catalogType is NoCatalog",
	},
	{
		name: "should allow creation when catalogType is valid",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: "OCIDistribution",
			},
		},
	},
	{
		name: "should deny creation when catalogType is not valid",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: "notvalidcatalogtype",
			},
		},
		expectedField: "spec.catalogType",
		expectedError: "is not a valid CatalogType",
	},
	{
		name: "should allow creation when platforms are valid",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI: "registry.test.local",
				Platforms: []v1alpha1.Platform{
					{
						Architecture: "amd64",
						OS:           "linux",
					},
				},
			},
		},
	},
	{
		name: "should deny creation when platforms are not valid",
		registry: &v1alpha1.Registry{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-registry",
				Namespace: "default",
			},
			Spec: v1alpha1.RegistrySpec{
				URI: "registry.test.local",
				Platforms: []v1alpha1.Platform{
					{
						Architecture: "xxx",
						OS:           "yyy",
					},
				},
			},
		},
		expectedField: "spec.platforms",
		expectedError: "is not an allowed platform",
	},
}

func TestRegistryCustomValidator_ValidateCreate(t *testing.T) {
	for _, test := range registryTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &RegistryCustomValidator{
				logger: logr.Discard(),
			}
			warnings, err := validator.ValidateCreate(t.Context(), test.registry)

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

func TestRegistryCustomValidator_ValidateUpdate(t *testing.T) {
	for _, test := range registryTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &RegistryCustomValidator{
				logger: logr.Discard(),
			}

			warnings, err := validator.ValidateUpdate(t.Context(), &v1alpha1.Registry{}, test.registry)

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
