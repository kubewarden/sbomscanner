package controller

import (
	"context"
	"fmt"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("WorkloadScan Controller", func() {
	var reconciler WorkloadScanReconciler
	var pod corev1.Pod

	When("A Pod is detected", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating a Pod")
			// restore reconciler at every test run.
			reconciler = WorkloadScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			pod = corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "example-zxfe",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "example",
							Image: "example.io/example-company/example-ct:1.21.0",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &pod)).To(Succeed())
		})
		It("Should Reconcile without errors", func(ctx context.Context) {
			By("doing the reconciliation")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			registry := &v1alpha1.Registry{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      workloadScanRegistry + "-example.io",
				Namespace: pod.Namespace,
			}, registry)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry.Spec.Repositories).To(HaveLen(1))
			Expect(registry.Spec.Repositories[0].Name).To(BeEquivalentTo("example-company/example-ct"))
			Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfe"))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.21.0'"))
		})
	})

	When("Another Pod is detected (with same image but different tag)", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating a Pod")
			// restore reconciler at every test run.
			reconciler = WorkloadScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			pod = corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "example-zxfc",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "example",
							Image: "example.io/example-company/example-ct:1.21.1",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &pod)).To(Succeed())
		})
		It("Should Reconcile without errors", func(ctx context.Context) {
			By("doing the reconciliation")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			registry := &v1alpha1.Registry{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      workloadScanRegistry + "-example.io",
				Namespace: pod.Namespace,
			}, registry)
			fmt.Println(registry.Spec.Repositories)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry.Spec.Repositories).To(HaveLen(1))
			Expect(registry.Spec.Repositories[0].Name).To(BeEquivalentTo("example-company/example-ct"))
			Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(2))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfe"))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.21.0'"))
			Expect(registry.Spec.Repositories[0].MatchConditions[1].Name).To(BeEquivalentTo("example-zxfc"))
			Expect(registry.Spec.Repositories[0].MatchConditions[1].Expression).To(BeEquivalentTo("tag == '1.21.1'"))
		})
	})

	When("Another Pod is detected (with different image and different tag)", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating a Pod")
			// restore reconciler at every test run.
			reconciler = WorkloadScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			pod = corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "example-zxfa",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "example",
							Image: "example.io/example-company/example-ab:1.0.2",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &pod)).To(Succeed())
		})
		It("Should Reconcile without errors", func(ctx context.Context) {
			By("doing the reconciliation")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			registry := &v1alpha1.Registry{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      workloadScanRegistry + "-example.io",
				Namespace: pod.Namespace,
			}, registry)
			fmt.Println(registry.Spec.Repositories)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry.Spec.Repositories).To(HaveLen(2))
			Expect(registry.Spec.Repositories[0].Name).To(BeEquivalentTo("example-company/example-ct"))
			Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(2))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfe"))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.21.0'"))
			Expect(registry.Spec.Repositories[0].MatchConditions[1].Name).To(BeEquivalentTo("example-zxfc"))
			Expect(registry.Spec.Repositories[0].MatchConditions[1].Expression).To(BeEquivalentTo("tag == '1.21.1'"))
			Expect(registry.Spec.Repositories[1].Name).To(BeEquivalentTo("example-company/example-ab"))
			Expect(registry.Spec.Repositories[1].MatchConditions).To(HaveLen(1))
			Expect(registry.Spec.Repositories[1].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfa"))
			Expect(registry.Spec.Repositories[1].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.0.2'"))
		})
	})

	When("A Pod is deleted", func() {
		BeforeEach(func(ctx context.Context) {
			By("Deleting a Pod")
			// restore reconciler at every test run.
			reconciler = WorkloadScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			pod = corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      "example-zxfe",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "example",
							Image: "example.io/example-company/example-ct:1.21.0",
						},
					},
				},
			}
			//Expect(k8sClient.Delete(ctx, &pod)).To(Succeed())
		})
		It("Should Reconcile without errors", func(ctx context.Context) {
			By("doing the reconciliation")
			Expect(k8sClient.Delete(ctx, &pod)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			registry := &v1alpha1.Registry{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      workloadScanRegistry + "-example.io",
				Namespace: pod.Namespace,
			}, registry)
			// registry should have been deleted
			Expect(registry.Spec.Repositories).To(HaveLen(2))
			Expect(registry.Spec.Repositories[0].Name).To(BeEquivalentTo("example-company/example-ct"))
			Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfc"))
			Expect(registry.Spec.Repositories[0].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.21.1'"))
			Expect(registry.Spec.Repositories[1].Name).To(BeEquivalentTo("example-company/example-ab"))
			Expect(registry.Spec.Repositories[1].MatchConditions).To(HaveLen(1))
			Expect(registry.Spec.Repositories[1].MatchConditions[0].Name).To(BeEquivalentTo("example-zxfa"))
			Expect(registry.Spec.Repositories[1].MatchConditions[0].Expression).To(BeEquivalentTo("tag == '1.0.2'"))
		})
	})
})
