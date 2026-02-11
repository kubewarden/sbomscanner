package dockerauth

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestBuildDockerConfigForRegistry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	tests := []struct {
		name                  string
		registry              *v1alpha1.Registry
		secret                *corev1.Secret
		installationNamespace string
		expectSecretNamespace string
		expectedError         string
	}{
		{
			name: "regular registry uses registry namespace for secret lookup",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-registry",
					Namespace: "registry-ns",
				},
				Spec: v1alpha1.RegistrySpec{
					URI:        "ghcr.io",
					AuthSecret: "my-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-secret",
					Namespace: "registry-ns",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: dockerConfigJSON(t, "ghcr.io", "user", "pass"),
				},
			},
			installationNamespace: "sbomscanner",
			expectSecretNamespace: "registry-ns",
		},
		{
			name: "workloadscan-managed registry uses installation namespace for secret lookup",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workloadscan-ghcr-io",
					Namespace: "artifacts-ns",
					Labels: map[string]string{
						api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
					},
				},
				Spec: v1alpha1.RegistrySpec{
					URI:        "ghcr.io",
					AuthSecret: "my-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-secret",
					Namespace: "sbomscanner",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: dockerConfigJSON(t, "ghcr.io", "user", "pass"),
				},
			},
			installationNamespace: "sbomscanner",
			expectSecretNamespace: "sbomscanner",
		},
		{
			name: "secret not found",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-registry",
					Namespace: "registry-ns",
				},
				Spec: v1alpha1.RegistrySpec{
					URI:        "ghcr.io",
					AuthSecret: "missing-secret",
				},
			},
			installationNamespace: "sbomscanner",
			expectedError:         "cannot get Secret missing-secret",
		},
		{
			name: "secret with wrong type",
			registry: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-registry",
					Namespace: "registry-ns",
				},
				Spec: v1alpha1.RegistrySpec{
					URI:        "ghcr.io",
					AuthSecret: "my-secret",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-secret",
					Namespace: "registry-ns",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"data": []byte("not-docker-config"),
				},
			},
			installationNamespace: "sbomscanner",
			expectedError:         "secret is not of type kubernetes.io/dockerconfigjson",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if test.secret != nil {
				builder = builder.WithObjects(test.secret)
			}
			k8sClient := builder.Build()

			dockerConfig, err := BuildDockerConfigForRegistry(
				context.Background(),
				k8sClient,
				test.registry,
				test.installationNamespace,
			)

			if test.expectedError != "" {
				require.ErrorContains(t, err, test.expectedError)
				return
			}

			require.NoError(t, err)
			defer os.RemoveAll(dockerConfig)

			// Verify the config file was created
			configFile := path.Join(dockerConfig, "config.json")
			_, err = os.Stat(configFile)
			require.NoError(t, err)

			// Verify DOCKER_CONFIG was set
			assert.Equal(t, dockerConfig, os.Getenv("DOCKER_CONFIG"))
			os.Unsetenv("DOCKER_CONFIG")
		})
	}
}

func dockerConfigJSON(t *testing.T, server, username, password string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"auths": map[string]any{
			server: map[string]string{
				"username": username,
				"password": password,
			},
		},
	})
	require.NoError(t, err)
	return data
}
