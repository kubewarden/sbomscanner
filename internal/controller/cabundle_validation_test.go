package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("CA bundle CRD validation", func() {
	caBundleRef := &v1alpha1.CABundleSource{
		ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
	}

	It("should reject a Registry setting both caBundle and caBundleRef", func(ctx context.Context) {
		registry := &v1alpha1.Registry{
			Name:      "both-ca-bundle",
			Namespace: "default",
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: v1alpha1.CatalogTypeOCIDistribution,
				CABundle:    "ca-bundle",
				CABundleRef: caBundleRef,
			},
		}
		err := k8sClient.Create(ctx, registry)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "unexpected error: %v", err)
		Expect(err.Error()).To(ContainSubstring("caBundle and caBundleRef are mutually exclusive"))
	})

	It("should reject a caBundleRef setting neither configMap nor secret", func(ctx context.Context) {
		registry := &v1alpha1.Registry{
			Name:      "empty-ca-bundle-ref",
			Namespace: "default",
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: v1alpha1.CatalogTypeOCIDistribution,
				CABundleRef: &v1alpha1.CABundleSource{},
			},
		}
		err := k8sClient.Create(ctx, registry)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "unexpected error: %v", err)
		Expect(err.Error()).To(ContainSubstring("exactly one of configMap or secret must be set"))
	})

	It("should reject a caBundleRef setting both configMap and secret", func(ctx context.Context) {
		registry := &v1alpha1.Registry{
			Name:      "double-ca-bundle-ref",
			Namespace: "default",
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: v1alpha1.CatalogTypeOCIDistribution,
				CABundleRef: &v1alpha1.CABundleSource{
					ConfigMap: &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
					Secret:    &v1alpha1.CABundleKeySelector{Name: "trust-bundle"},
				},
			},
		}
		err := k8sClient.Create(ctx, registry)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "unexpected error: %v", err)
		Expect(err.Error()).To(ContainSubstring("exactly one of configMap or secret must be set"))
	})

	It("should default the caBundleRef key to ca.crt", func(ctx context.Context) {
		registry := &v1alpha1.Registry{
			Name:      "defaulted-ca-bundle-ref",
			Namespace: "default",
			Spec: v1alpha1.RegistrySpec{
				URI:         "registry.test.local",
				CatalogType: v1alpha1.CatalogTypeOCIDistribution,
				CABundleRef: caBundleRef.DeepCopy(),
			},
		}
		Expect(k8sClient.Create(ctx, registry)).To(Succeed())
		DeferCleanup(func(ctx context.Context) {
			Expect(k8sClient.Delete(ctx, registry)).To(Succeed())
		})

		Expect(registry.Spec.CABundleRef.ConfigMap.Key).To(Equal(v1alpha1.CABundleDefaultKey))
	})
})
