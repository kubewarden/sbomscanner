// Package cabundle resolves the CA bundle configured on a Registry, either inline or from a referenced ConfigMap or Secret.
package cabundle

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Resolve returns the PEM-encoded CA bundle configured for the registry, either inline in
// spec.caBundle or read from the ConfigMap/Secret referenced by spec.caBundleRef.
// It returns nil when the registry does not configure a CA bundle.
// For workloadscan-managed registries, referenced objects are looked up in installationNamespace
// instead of the registry namespace.
func Resolve(ctx context.Context, k8sClient client.Client, registry *v1alpha1.Registry, installationNamespace string) ([]byte, error) {
	var bundle []byte

	switch {
	case registry.Spec.CABundle != "":
		bundle = []byte(registry.Spec.CABundle)
	case registry.Spec.CABundleRef != nil:
		namespace := registry.Namespace
		if registry.IsWorkloadScanManaged() {
			namespace = installationNamespace
		}

		var err error
		bundle, err = readRef(ctx, k8sClient, registry.Spec.CABundleRef, namespace)
		if err != nil {
			return nil, err
		}
	default:
		return nil, nil
	}

	if !x509.NewCertPool().AppendCertsFromPEM(bundle) {
		return nil, errors.New("CA bundle does not contain any valid PEM-encoded certificate")
	}

	return bundle, nil
}

func readRef(ctx context.Context, k8sClient client.Client, ref *v1alpha1.CABundleSource, namespace string) ([]byte, error) {
	switch {
	case ref.ConfigMap != nil:
		key := keyOrDefault(ref.ConfigMap.Key)

		configMap := &corev1.ConfigMap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: ref.ConfigMap.Name, Namespace: namespace}, configMap); err != nil {
			return nil, fmt.Errorf("cannot get CA bundle ConfigMap %s/%s: %w", namespace, ref.ConfigMap.Name, err)
		}

		if value, ok := configMap.Data[key]; ok {
			return []byte(value), nil
		}
		if value, ok := configMap.BinaryData[key]; ok {
			return value, nil
		}

		return nil, fmt.Errorf("CA bundle ConfigMap %s/%s has no key %q", namespace, ref.ConfigMap.Name, key)
	case ref.Secret != nil:
		key := keyOrDefault(ref.Secret.Key)

		secret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: ref.Secret.Name, Namespace: namespace}, secret); err != nil {
			return nil, fmt.Errorf("cannot get CA bundle Secret %s/%s: %w", namespace, ref.Secret.Name, err)
		}

		if value, ok := secret.Data[key]; ok {
			return value, nil
		}

		return nil, fmt.Errorf("CA bundle Secret %s/%s has no key %q", namespace, ref.Secret.Name, key)
	default:
		return nil, errors.New("caBundleRef must reference either a ConfigMap or a Secret")
	}
}

func keyOrDefault(key string) string {
	if key == "" {
		return v1alpha1.CABundleDefaultKey
	}
	return key
}
