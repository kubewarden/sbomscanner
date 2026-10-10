package cabundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	caPEM := generateCAPEM(t)

	tests := []struct {
		name           string
		registry       *v1alpha1.Registry
		objects        []client.Object
		expectedBundle []byte
		expectedError  string
	}{
		{
			name:     "no CA bundle configured",
			registry: newRegistry(v1alpha1.RegistrySpec{}),
		},
		{
			name: "inline CA bundle",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundle: string(caPEM),
			}),
			expectedBundle: caPEM,
		},
		{
			name: "inline CA bundle without valid certificates",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundle: "not a certificate",
			}),
			expectedError: "does not contain any valid PEM-encoded certificate",
		},
		{
			name: "ConfigMap reference with default key",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
				},
			}),
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:      "trust-bundle",
					Namespace: "registry-ns",
					Data:      map[string]string{v1alpha1.CABundleDefaultKey: string(caPEM)},
				},
			},
			expectedBundle: caPEM,
		},
		{
			name: "ConfigMap reference with custom key",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle", Key: "root-certs.pem"},
				},
			}),
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:      "trust-bundle",
					Namespace: "registry-ns",
					Data:      map[string]string{"root-certs.pem": string(caPEM)},
				},
			},
			expectedBundle: caPEM,
		},
		{
			name: "ConfigMap reference with key in binaryData",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
				},
			}),
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:       "trust-bundle",
					Namespace:  "registry-ns",
					BinaryData: map[string][]byte{v1alpha1.CABundleDefaultKey: caPEM},
				},
			},
			expectedBundle: caPEM,
		},
		{
			name: "ConfigMap reference with missing key",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle", Key: "missing"},
				},
			}),
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:      "trust-bundle",
					Namespace: "registry-ns",
					Data:      map[string]string{v1alpha1.CABundleDefaultKey: string(caPEM)},
				},
			},
			expectedError: `ConfigMap registry-ns/trust-bundle has no key "missing"`,
		},
		{
			name: "ConfigMap reference to missing object",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
				},
			}),
			expectedError: "cannot get CA bundle ConfigMap registry-ns/trust-bundle",
		},
		{
			name: "Secret reference",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					Secret: &v1alpha1.CABundleKeySelector{Name: "registry-tls"},
				},
			}),
			objects: []client.Object{
				&corev1.Secret{
					Name:      "registry-tls",
					Namespace: "registry-ns",
					Data:      map[string][]byte{v1alpha1.CABundleDefaultKey: caPEM},
				},
			},
			expectedBundle: caPEM,
		},
		{
			name: "Secret reference with missing key",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					Secret: &v1alpha1.CABundleKeySelector{Name: "registry-tls"},
				},
			}),
			objects: []client.Object{
				&corev1.Secret{
					Name:      "registry-tls",
					Namespace: "registry-ns",
					Data:      map[string][]byte{"tls.crt": caPEM},
				},
			},
			expectedError: `Secret registry-ns/registry-tls has no key "ca.crt"`,
		},
		{
			name: "referenced object without valid certificates",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
				},
			}),
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:      "trust-bundle",
					Namespace: "registry-ns",
					Data:      map[string]string{v1alpha1.CABundleDefaultKey: "not a certificate"},
				},
			},
			expectedError: "does not contain any valid PEM-encoded certificate",
		},
		{
			name: "empty reference",
			registry: newRegistry(v1alpha1.RegistrySpec{
				CABundleRef: &v1alpha1.CABundleSource{},
			}),
			expectedError: "must reference either a ConfigMap or a Secret",
		},
		{
			name: "workloadscan-managed registry looks up the installation namespace",
			registry: &v1alpha1.Registry{
				Name:      "workloadscan-registry",
				Namespace: "artifacts-ns",
				Labels: map[string]string{
					api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
				},
				Spec: v1alpha1.RegistrySpec{
					CABundleRef: &v1alpha1.CABundleSource{
						ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
					},
				},
			},
			objects: []client.Object{
				&corev1.ConfigMap{
					Name:      "trust-bundle",
					Namespace: "sbomscanner",
					Data:      map[string]string{v1alpha1.CABundleDefaultKey: string(caPEM)},
				},
			},
			expectedBundle: caPEM,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(test.objects...).
				Build()

			bundle, err := Resolve(t.Context(), k8sClient, test.registry, "sbomscanner")

			if test.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError)
				assert.Nil(t, bundle)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectedBundle, bundle)
		})
	}
}

func newRegistry(spec v1alpha1.RegistrySpec) *v1alpha1.Registry {
	return &v1alpha1.Registry{
		Name:      "my-registry",
		Namespace: "registry-ns",
		Spec:      spec,
	}
}

func generateCAPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
