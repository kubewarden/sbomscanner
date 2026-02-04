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

type workloadScanConfigurationTestCase struct {
	name          string
	configuration *v1alpha1.WorkloadScanConfiguration
	expectedError string
	expectedField string
}

var workloadScanConfigurationTestCases = []workloadScanConfigurationTestCase{
	// ScanInterval test cases
	{
		name: "should admit creation when scanInterval is nil",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				ScanInterval: nil,
			},
		},
	},
	{
		name: "should admit creation when scanInterval is exactly 1 minute",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				ScanInterval: &metav1.Duration{
					Duration: time.Minute,
				},
			},
		},
	},
	{
		name: "should admit creation when scanInterval is greater than 1 minute",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				ScanInterval: &metav1.Duration{
					Duration: 1 * time.Hour,
				},
			},
		},
	},
	{
		name: "should deny creation when scanInterval is less than 1 minute",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
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
		name: "should allow creation when platforms are valid",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
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
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
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
	// NamespaceSelector test cases
	{
		name: "should allow creation when namespaceSelector is nil",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				NamespaceSelector: nil,
			},
		},
	},
	{
		name: "should allow creation when namespaceSelector is valid",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"env": "production",
					},
				},
			},
		},
	},
	{
		name: "should deny creation when namespaceSelector is invalid",
		configuration: &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
			Spec: v1alpha1.WorkloadScanConfigurationSpec{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"invalid key": "value",
					},
				},
			},
		},
		expectedField: "spec.namespaceSelector.matchLabels",
		expectedError: "Invalid value",
	},
}

func TestWorkloadScanConfigurationCustomValidator_ValidateCreate(t *testing.T) {
	for _, test := range workloadScanConfigurationTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &WorkloadScanConfigurationCustomValidator{
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

func TestWorkloadScanConfigurationCustomValidator_ValidateUpdate(t *testing.T) {
	for _, test := range workloadScanConfigurationTestCases {
		t.Run(test.name, func(t *testing.T) {
			validator := &WorkloadScanConfigurationCustomValidator{
				logger: logr.Discard(),
			}

			warnings, err := validator.ValidateUpdate(t.Context(), &v1alpha1.WorkloadScanConfiguration{}, test.configuration)

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

func TestWorkloadScanConfigurationCustomValidator_ValidateDelete(t *testing.T) {
	t.Run("should return warning on delete", func(t *testing.T) {
		validator := &WorkloadScanConfigurationCustomValidator{
			logger: logr.Discard(),
		}

		configuration := &v1alpha1.WorkloadScanConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-workload-scan-configuration",
				Namespace: "default",
			},
		}

		warnings, err := validator.ValidateDelete(t.Context(), configuration)

		require.NoError(t, err)
		require.Len(t, warnings, 1)
		assert.Equal(t, "WorkloadScanConfiguration deleted. Workload scan feature is now disabled", warnings[0])
	})
}
