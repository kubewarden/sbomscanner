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

type nodeScanConfigurationTestCase struct {
	name          string
	configuration *v1alpha1.NodeScanConfiguration
	expectedError string
	expectedField string
}

var nodeScanConfigurationTestCases = []nodeScanConfigurationTestCase{
	{
		name: "should allow when all fields are empty",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{},
		},
	},
	// ScanInterval test cases
	{
		name: "should allow when scanInterval is nil",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				ScanInterval: nil,
			},
		},
	},
	{
		name: "should admit when scanInterval is exactly 1 minute",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				ScanInterval: &metav1.Duration{
					Duration: time.Minute,
				},
			},
		},
	},
	{
		name: "should admit when scanInterval is greater than 1 minute",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				ScanInterval: &metav1.Duration{
					Duration: 1 * time.Hour,
				},
			},
		},
	},
	{
		name: "should deny when scanInterval is less than 1 minute",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				ScanInterval: &metav1.Duration{
					Duration: 30 * time.Second,
				},
			},
		},
		expectedField: "spec.scanInterval",
		expectedError: "scanInterval must be at least 1 minute",
	},
	// Platform test cases
	{
		name: "should allow when platforms are valid",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
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
		name: "should deny when platforms are not valid",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				Platforms: []v1alpha1.Platform{
					{
						Architecture: "xxx",
						OS:           "yyy",
					},
				},
			},
		},
		expectedField: "spec.platforms[0]",
		expectedError: "unsupported OS: yyy",
	},
	// NodeSelector test cases
	{
		name: "should allow when nodeSelector is nil",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				NodeSelector: nil,
			},
		},
	},
	{
		name: "should allow when nodeSelector is valid",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				NodeSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"env": "production",
					},
				},
			},
		},
	},
	{
		name: "should deny when nodeSelector is invalid",
		configuration: &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.NodeScanConfigurationSpec{
				NodeSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"invalid key": "value",
					},
				},
			},
		},
		expectedField: "spec.nodeSelector.matchLabels",
		expectedError: "Invalid value",
	},
}

func TestNodeScanConfigurationCustomValidator_ValidateCreate(t *testing.T) {
	for _, test := range nodeScanConfigurationTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &NodeScanConfigurationCustomValidator{
				logger: logr.Discard(),
			}
			warnings, err := validator.ValidateCreate(t.Context(), test.configuration)

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

func TestNodeScanConfigurationCustomValidator_ValidateUpdate(t *testing.T) {
	for _, test := range nodeScanConfigurationTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &NodeScanConfigurationCustomValidator{
				logger: logr.Discard(),
			}

			old := &v1alpha1.NodeScanConfiguration{}
			warnings, err := validator.ValidateUpdate(t.Context(), old, test.configuration)

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

func TestNodeScanConfigurationCustomValidator_ValidateDelete(t *testing.T) {
	t.Run("should return warning on delete", func(t *testing.T) {
		validator := &NodeScanConfigurationCustomValidator{
			logger: logr.Discard(),
		}

		config := &v1alpha1.NodeScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}

		warnings, err := validator.ValidateDelete(t.Context(), config)

		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Equal(t, "NodeScanConfiguration deleted. Node scan feature is now disabled", warnings[0])
	})
}
