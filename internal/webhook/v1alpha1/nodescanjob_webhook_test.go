package v1alpha1

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestNodeScanJobCustomValidator_ValidateCreate(t *testing.T) {
	tests := []struct {
		name          string
		config        *v1alpha1.NodeScanConfiguration
		node          *corev1.Node
		job           *v1alpha1.NodeScanJob
		expectedError string
		expectedField string
	}{
		{
			name: "should admit when config exists and node matches",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v1alpha1.NodeScanConfigurationSpec{},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
		},
		{
			name:   "should deny when NodeScanConfiguration is missing",
			config: nil,
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
			expectedField: "spec.nodeName",
			expectedError: "NodeScanConfiguration not found",
		},
		{
			name: "should deny when node does not exist",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v1alpha1.NodeScanConfigurationSpec{},
			},
			node: nil,
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "non-existent"},
			},
			expectedField: "spec.nodeName",
			expectedError: "Not found",
		},
		{
			name: "should deny when node does not match nodeSelector",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-1",
					Labels: map[string]string{"env": "staging"},
				},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
			expectedField: "spec.nodeName",
			expectedError: "does not match the NodeScanConfiguration nodeSelector",
		},
		{
			name: "should admit when node matches nodeSelector",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-1",
					Labels: map[string]string{"env": "production"},
				},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
		},
		{
			name: "should deny when node platform is not allowed",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "arm64",
					},
				},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
			expectedField: "spec.nodeName",
			expectedError: "platform linux/arm64 is not allowed",
		},
		{
			name: "should admit when node platform matches",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "amd64",
					},
				},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
		},
		{
			name: "should deny when nodeSelector and platform both fail",
			config: &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
					},
				},
			},
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "worker-1",
					Labels: map[string]string{"env": "staging"},
				},
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "arm64",
					},
				},
			},
			job: &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: "worker-1"},
			},
			expectedField: "spec.nodeName",
			expectedError: "does not match the NodeScanConfiguration nodeSelector",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, v1alpha1.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			builder := fake.NewClientBuilder().WithScheme(scheme)
			if test.config != nil {
				builder = builder.WithObjects(test.config)
			}
			if test.node != nil {
				builder = builder.WithObjects(test.node)
			}
			fakeClient := builder.Build()

			validator := &NodeScanJobCustomValidator{
				client: fakeClient,
				logger: logr.Discard(),
			}

			warnings, err := validator.ValidateCreate(t.Context(), test.job)

			if test.expectedError != "" {
				require.Error(t, err)
				statusErr, ok := err.(interface{ Status() metav1.Status })
				require.True(t, ok)
				details := statusErr.Status().Details
				require.NotNil(t, details)
				require.NotEmpty(t, details.Causes)
				assert.Equal(t, test.expectedField, details.Causes[0].Field)
				assert.Contains(t, details.Causes[0].Message, test.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Empty(t, warnings)
		})
	}
}

func TestNodeScanJobCustomValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name           string
		oldNodeName    string
		newNodeName    string
		expectedFields []string
	}{
		{
			name:           "nodeName changed is rejected",
			oldNodeName:    "worker-1",
			newNodeName:    "worker-2",
			expectedFields: []string{"spec.nodeName"},
		},
		{
			name:        "no changes is admitted",
			oldNodeName: "worker-1",
			newNodeName: "worker-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := &NodeScanJobCustomValidator{
				logger: logr.Discard(),
			}

			oldObj := &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: test.oldNodeName},
			}
			newObj := &v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: test.newNodeName},
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
			for i, f := range test.expectedFields {
				assert.Equal(t, f, details.Causes[i].Field)
				assert.Contains(t, details.Causes[i].Message, "immutable")
			}
		})
	}
}

func TestNodeScanJobCustomValidator_ValidateDelete(t *testing.T) {
	t.Run("should allow deletion", func(t *testing.T) {
		validator := &NodeScanJobCustomValidator{
			logger: logr.Discard(),
		}

		job := &v1alpha1.NodeScanJob{
			ObjectMeta: metav1.ObjectMeta{Name: "test-job"},
		}

		warnings, err := validator.ValidateDelete(t.Context(), job)

		require.NoError(t, err)
		assert.Empty(t, warnings)
	})
}
