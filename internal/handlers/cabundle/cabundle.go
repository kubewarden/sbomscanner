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
// For registries managed by the workload scan feature, referenced objects are looked up in installationNamespace
// instead of the registry namespace.
func Resolve(ctx context.Context, k8sClient client.Client, registry *v1alpha1.Registry, installationNamespace string) ([]byte, error) {
	if registry.Spec.CABundle != "" {
		return validate([]byte(registry.Spec.CABundle))
	}
	if registry.Spec.CABundleRef == nil {
		return nil, nil
	}

	namespace := registry.Namespace
	if registry.IsManagedByWorkloadScan() {
		namespace = installationNamespace
	}

	bundle, err := readRef(ctx, k8sClient, registry.Spec.CABundleRef, namespace)
	if err != nil {
		return nil, err
	}

	return validate(bundle)
}

func validate(bundle []byte) ([]byte, error) {
	if !x509.NewCertPool().AppendCertsFromPEM(bundle) {
		return nil, errors.New("CA bundle does not contain any valid PEM-encoded certificate")
	}
	return bundle, nil
}

func readRef(ctx context.Context, k8sClient client.Client, ref *v1alpha1.CABundleSource, namespace string) ([]byte, error) {
	if ref.ConfigMap != nil {
		return readConfigMapKey(ctx, k8sClient, ref.ConfigMap, namespace)
	}
	if ref.Secret != nil {
		return readSecretKey(ctx, k8sClient, ref.Secret, namespace)
	}
	return nil, errors.New("caBundleRef must reference either a ConfigMap or a Secret")
}

func readConfigMapKey(ctx context.Context, k8sClient client.Client, selector *v1alpha1.CABundleKeySelector, namespace string) ([]byte, error) {
	key := keyOrDefault(selector.Key)

	configMap := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: selector.Name, Namespace: namespace}, configMap); err != nil {
		return nil, fmt.Errorf("cannot get CA bundle ConfigMap %s/%s: %w", namespace, selector.Name, err)
	}

	if value, ok := configMap.Data[key]; ok {
		return []byte(value), nil
	}
	if value, ok := configMap.BinaryData[key]; ok {
		return value, nil
	}

	return nil, fmt.Errorf("CA bundle ConfigMap %s/%s has no key %q", namespace, selector.Name, key)
}

func readSecretKey(ctx context.Context, k8sClient client.Client, selector *v1alpha1.CABundleKeySelector, namespace string) ([]byte, error) {
	key := keyOrDefault(selector.Key)

	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: selector.Name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("cannot get CA bundle Secret %s/%s: %w", namespace, selector.Name, err)
	}

	if value, ok := secret.Data[key]; ok {
		return value, nil
	}

	return nil, fmt.Errorf("CA bundle Secret %s/%s has no key %q", namespace, selector.Name, key)
}

func keyOrDefault(key string) string {
	if key == "" {
		return v1alpha1.CABundleDefaultKey
	}
	return key
}
