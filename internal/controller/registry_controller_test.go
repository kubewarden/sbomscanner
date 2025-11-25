package controller

import (
	"context"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("Registry Controller", func() {
	When("Repositories are updated", func() {
		var registry v1alpha1.Registry

		BeforeEach(func(ctx context.Context) {
			By("Creating a new Registry")
			registry = v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "ghcr.io/kubewarden",
					Repositories: []v1alpha1.Repository{
						{
							Name: "sbomscanner-dev",
						},
						{
							Name: "sbomscanner-prod",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &registry)).To(Succeed())

			By("Creating a new Image inside the sbomscanner-dev repository")
			image := storagev1alpha1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				ImageMetadata: storagev1alpha1.ImageMetadata{
					Registry:   registry.Name,
					Repository: "sbomscanner-dev",
					Tag:        "latest",
					Digest:     "sha256:123",
					Platform:   "linux/amd64",
				},
			}
			Expect(k8sClient.Create(ctx, &image)).To(Succeed())

			By("Creating a new Image inside the sbomscanner-prod repository")
			image = storagev1alpha1.Image{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				ImageMetadata: storagev1alpha1.ImageMetadata{
					Registry:   registry.Name,
					Repository: "sbomscanner-prod",
					Tag:        "latest",
					Digest:     "sha256:234",
					Platform:   "linux/amd64",
				},
			}
			Expect(k8sClient.Create(ctx, &image)).To(Succeed())
		})

		It("Should delete all Images that are not in the current list of repositories", func(ctx context.Context) {
			By("Updating the Registry with a new list of repositories")
			registry.Spec.Repositories = []v1alpha1.Repository{
				{
					Name: "sbomscanner-prod",
				},
			}
			Expect(k8sClient.Update(ctx, &registry)).To(Succeed())

			By("Reconciling the Registry")
			reconciler := RegistryReconciler{
				Client: k8sClient,
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Expecting that the Images in the sbomscanner-dev repository are deleted")
			var images storagev1alpha1.ImageList
			Expect(k8sClient.List(ctx, &images, &client.ListOptions{
				Namespace:     "default",
				FieldSelector: fields.SelectorFromSet(fields.Set{storagev1alpha1.IndexImageMetadataRegistry: registry.Name}),
			})).To(Succeed())

			Expect(images.Items).To(HaveLen(1))
			Expect(images.Items[0].GetImageMetadata().Repository).To(Equal("sbomscanner-prod"))
		})

		It("Should delete all Images that does not match the tag filter", func(ctx context.Context) {
			By("Updating the Registry with a new configuration of repositories")
			registry.Spec.Repositories = []v1alpha1.Repository{
				{
					Name: "sbomscanner-dev",
				},
				{
					Name: "sbomscanner-prod",
					MatchConditions: []v1alpha1.MatchCondition{
						{
							Name:       "no latest tag",
							Expression: "tag != 'latest'",
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, &registry)).To(Succeed())

			By("Reconciling the Registry")
			reconciler := RegistryReconciler{
				Client: k8sClient,
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Expecting that the Images in the sbomscanner-prod repository are deleted")
			var images storagev1alpha1.ImageList
			Expect(k8sClient.List(ctx, &images, &client.ListOptions{
				Namespace:     "default",
				FieldSelector: fields.SelectorFromSet(fields.Set{storagev1alpha1.IndexImageMetadataRegistry: registry.Name}),
			})).To(Succeed())

			Expect(images.Items).To(HaveLen(1))
			Expect(images.Items[0].GetImageMetadata().Repository).To(Equal("sbomscanner-dev"))
		})
	})
})
