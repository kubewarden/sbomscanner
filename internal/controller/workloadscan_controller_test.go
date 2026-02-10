package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("WorkloadScan Controller", func() {
	var (
		reconciler    *WorkloadScanReconciler
		configuration *v1alpha1.WorkloadScanConfiguration
		namespace     *corev1.Namespace
	)

	BeforeEach(func() {
		By("Creating a new WorkloadScanReconciler")
		reconciler = &WorkloadScanReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	When("WorkloadScanConfiguration does not exist", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating a namespace")
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-configuration-namespace-" + uuid.New().String()[:8],
				},
			}
			Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
		})

		It("should return without error and not create any resources", func(ctx context.Context) {
			By("Reconciling the namespace")
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace.Name},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			By("Verifying no registries were created")
			var registryList v1alpha1.RegistryList
			Expect(k8sClient.List(ctx, &registryList, client.InNamespace(namespace.Name))).To(Succeed())
			Expect(registryList.Items).To(BeEmpty())
		})

		It("should cleanup all managed resources across all namespaces", func(ctx context.Context) {
			By("Creating another namespace")
			otherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-namespace-" + uuid.New().String()[:8],
				},
			}
			Expect(k8sClient.Create(ctx, otherNamespace)).To(Succeed())

			By("Creating managed registries in both namespaces")
			registry1 := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey:    api.LabelManagedByValue,
						api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
					},
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "ghcr.io",
					Repositories: []v1alpha1.Repository{
						{
							Name:          "test/app",
							MatchOperator: v1alpha1.MatchOperatorOr,
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag-v1",
									Expression: `tag == "v1"`,
									Labels:     map[string]string{"namespace/" + namespace.Name: "true"},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, registry1)).To(Succeed())

			registry2 := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workloadscan-quay-io",
					Namespace: otherNamespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey:    api.LabelManagedByValue,
						api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
					},
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "quay.io",
					Repositories: []v1alpha1.Repository{
						{
							Name:          "test/other",
							MatchOperator: v1alpha1.MatchOperatorOr,
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag-latest",
									Expression: `tag == "latest"`,
									Labels:     map[string]string{"namespace/" + otherNamespace.Name: "true"},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, registry2)).To(Succeed())

			By("Creating managed WorkloadScanReports in both namespaces")
			report1 := &storagev1alpha1.WorkloadScanReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-test-pod",
					Namespace: namespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "workloadscan-ghcr-io",
								Namespace:  namespace.Name,
								Repository: "test/app",
								Tag:        "v1",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, report1)).To(Succeed())

			report2 := &storagev1alpha1.WorkloadScanReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-other-pod",
					Namespace: otherNamespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "workloadscan-quay-io",
								Namespace:  otherNamespace.Name,
								Repository: "test/other",
								Tag:        "latest",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, report2)).To(Succeed())

			By("Reconciling any namespace (configuration doesn't exist)")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying all managed registries were deleted")
			var registryList v1alpha1.RegistryList
			Expect(k8sClient.List(ctx, &registryList,
				client.MatchingLabels{
					api.LabelManagedByKey:    api.LabelManagedByValue,
					api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
				},
			)).To(Succeed())
			Expect(registryList.Items).To(BeEmpty())

			By("Verifying all managed WorkloadScanReports were deleted")
			var reportList storagev1alpha1.WorkloadScanReportList
			Expect(k8sClient.List(ctx, &reportList,
				client.MatchingLabels{
					api.LabelManagedByKey: api.LabelManagedByValue,
				},
			)).To(Succeed())
			Expect(reportList.Items).To(BeEmpty())
		})
	})

	When("WorkloadScanConfiguration is disabled", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating a disabled WorkloadScanConfiguration")
			configuration = &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					Enabled: false,
				},
			}
			Expect(k8sClient.Create(ctx, configuration)).To(Succeed())

			By("Creating a namespace")
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "disabled-namespace-" + uuid.New().String()[:8],
				},
			}
			Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			By("Deleting the WorkloadScanConfiguration")
			Expect(k8sClient.Delete(ctx, configuration)).To(Succeed())
		})

		It("should cleanup all managed resources across all namespaces", func(ctx context.Context) {
			By("Creating another namespace")
			otherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-disabled-namespace-" + uuid.New().String()[:8],
				},
			}
			Expect(k8sClient.Create(ctx, otherNamespace)).To(Succeed())

			By("Creating managed registries in both namespaces")
			registry1 := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey:    api.LabelManagedByValue,
						api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
					},
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "ghcr.io",
					Repositories: []v1alpha1.Repository{
						{
							Name:          "test/app",
							MatchOperator: v1alpha1.MatchOperatorOr,
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag-v1",
									Expression: `tag == "v1"`,
									Labels:     map[string]string{"namespace/" + namespace.Name: "true"},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, registry1)).To(Succeed())

			registry2 := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "workloadscan-quay-io",
					Namespace: otherNamespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey:    api.LabelManagedByValue,
						api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
					},
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "quay.io",
					Repositories: []v1alpha1.Repository{
						{
							Name:          "test/other",
							MatchOperator: v1alpha1.MatchOperatorOr,
							MatchConditions: []v1alpha1.MatchCondition{
								{
									Name:       "tag-latest",
									Expression: `tag == "latest"`,
									Labels:     map[string]string{"namespace/" + otherNamespace.Name: "true"},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, registry2)).To(Succeed())

			By("Creating managed WorkloadScanReports in both namespaces")
			report1 := &storagev1alpha1.WorkloadScanReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-test-pod",
					Namespace: namespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "workloadscan-ghcr-io",
								Namespace:  namespace.Name,
								Repository: "test/app",
								Tag:        "v1",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, report1)).To(Succeed())

			report2 := &storagev1alpha1.WorkloadScanReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-other-pod",
					Namespace: otherNamespace.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				Spec: storagev1alpha1.WorkloadScanReportSpec{
					Containers: []storagev1alpha1.ContainerRef{
						{
							Name: "app",
							ImageRef: storagev1alpha1.ImageRef{
								Registry:   "workloadscan-quay-io",
								Namespace:  otherNamespace.Name,
								Repository: "test/other",
								Tag:        "latest",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, report2)).To(Succeed())

			By("Reconciling any namespace (configuration is disabled)")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace.Name},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying all managed registries were deleted")
			var registryList v1alpha1.RegistryList
			Expect(k8sClient.List(ctx, &registryList,
				client.MatchingLabels{
					api.LabelManagedByKey:    api.LabelManagedByValue,
					api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
				},
			)).To(Succeed())
			Expect(registryList.Items).To(BeEmpty())

			By("Verifying all managed WorkloadScanReports were deleted")
			var reportList storagev1alpha1.WorkloadScanReportList
			Expect(k8sClient.List(ctx, &reportList,
				client.MatchingLabels{
					api.LabelManagedByKey: api.LabelManagedByValue,
				},
			)).To(Succeed())
			Expect(reportList.Items).To(BeEmpty())
		})
	})

	When("WorkloadScanConfiguration exists", func() {
		BeforeEach(func(ctx context.Context) {
			By("Creating the WorkloadScanConfiguration")
			configuration = &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					Enabled: true,
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"scan": "enabled",
						},
					},
					AuthSecret: "auth-secret",
					CABundle:   "ca-bundle",
					Insecure:   true,
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
						{Architecture: "arm64", OS: "linux"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, configuration)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			By("Deleting the WorkloadScanConfiguration")
			Expect(k8sClient.Delete(ctx, configuration)).To(Succeed())
		})

		When("namespace does not match selector", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a namespace that does not match")
				namespace = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "unmatched-namespace-" + uuid.New().String()[:8],
						Labels: map[string]string{
							"scan": "disabled",
						},
					},
				}
				Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
			})

			It("should skip reconciliation and not create resources", func(ctx context.Context) {
				By("Creating a pod in the namespace")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying no registries were created")
				var registryList v1alpha1.RegistryList
				Expect(k8sClient.List(ctx, &registryList, client.InNamespace(namespace.Name))).To(Succeed())
				Expect(registryList.Items).To(BeEmpty())
			})

			It("should cleanup existing managed resources", func(ctx context.Context) {
				By("Creating a pre-existing managed registry")
				existingRegistry := &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "workloadscan-ghcr-io",
						Namespace: namespace.Name,
						Labels: map[string]string{
							api.LabelManagedByKey:    api.LabelManagedByValue,
							api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
						},
					},
					Spec: v1alpha1.RegistrySpec{
						URI: "ghcr.io",
						Repositories: []v1alpha1.Repository{
							{
								Name:          "test/app",
								MatchOperator: v1alpha1.MatchOperatorOr,
								MatchConditions: []v1alpha1.MatchCondition{
									{
										Name:       "tag-v1",
										Expression: `tag == "v1"`,
										Labels:     map[string]string{"namespace/" + namespace.Name: "true"},
									},
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, existingRegistry)).To(Succeed())

				By("Creating a pre-existing managed WorkloadScanReport")
				existingReport := &storagev1alpha1.WorkloadScanReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-old-pod",
						Namespace: namespace.Name,
						Labels: map[string]string{
							api.LabelManagedByKey: api.LabelManagedByValue,
						},
					},
					Spec: storagev1alpha1.WorkloadScanReportSpec{
						Containers: []storagev1alpha1.ContainerRef{
							{
								Name: "app",
								ImageRef: storagev1alpha1.ImageRef{
									Registry:   "workloadscan-ghcr-io",
									Namespace:  namespace.Name,
									Repository: "test/app",
									Tag:        "v1",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, existingReport)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the registry was deleted")
				var registry v1alpha1.Registry
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)
				Expect(client.IgnoreNotFound(err)).To(Succeed())
				Expect(err).To(HaveOccurred())

				By("Verifying the report was deleted")
				var report storagev1alpha1.WorkloadScanReport
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-old-pod",
					Namespace: namespace.Name,
				}, &report)
				Expect(client.IgnoreNotFound(err)).To(Succeed())
				Expect(err).To(HaveOccurred())
			})
		})

		When("namespace matches selector and has pods", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a namespace that matches")
				namespace = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "matched-namespace-" + uuid.New().String()[:8],
						Labels: map[string]string{
							"scan": "enabled",
						},
					},
				}
				Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
			})

			It("should create Registry and WorkloadScanReport for a standalone pod", func(ctx context.Context) {
				By("Creating a pod")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "standalone-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the registry was created with correct labels")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())

				Expect(registry.Labels[api.LabelManagedByKey]).To(Equal(api.LabelManagedByValue))
				Expect(registry.Labels[api.LabelWorkloadScanKey]).To(Equal(api.LabelWorkloadScanValue))
				Expect(registry.Spec.URI).To(Equal("ghcr.io"))
				Expect(registry.Spec.AuthSecret).To(Equal(configuration.Spec.AuthSecret))
				Expect(registry.Spec.CABundle).To(Equal(configuration.Spec.CABundle))
				Expect(registry.Spec.Insecure).To(Equal(configuration.Spec.Insecure))
				Expect(registry.Spec.Platforms).To(Equal(configuration.Spec.Platforms))

				By("Verifying the registry has the correct repository and match condition")
				Expect(registry.Spec.Repositories).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].Name).To(Equal("test/app"))
				Expect(registry.Spec.Repositories[0].MatchOperator).To(Equal(v1alpha1.MatchOperatorOr))
				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(Equal("tag-v1"))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Expression).To(Equal(`tag == "v1"`))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Labels).To(HaveKeyWithValue("namespace/"+namespace.Name, "true"))

				By("Verifying the WorkloadScanReport was created")
				var report storagev1alpha1.WorkloadScanReport
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-standalone-pod",
					Namespace: namespace.Name,
				}, &report)).To(Succeed())

				Expect(report.Labels[api.LabelManagedByKey]).To(Equal(api.LabelManagedByValue))
				Expect(report.Spec.Containers).To(HaveLen(1))
				Expect(report.Spec.Containers[0].Name).To(Equal("app"))
				Expect(report.Spec.Containers[0].ImageRef.Registry).To(Equal("workloadscan-ghcr-io"))
				Expect(report.Spec.Containers[0].ImageRef.Repository).To(Equal("test/app"))
				Expect(report.Spec.Containers[0].ImageRef.Tag).To(Equal("v1"))
			})

			It("should create registries for multiple container registries", func(ctx context.Context) {
				By("Creating a pod with images from multiple registries")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "multi-registry-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{Name: "init", Image: "docker.io/library/busybox:latest"},
						},
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
							{Name: "sidecar", Image: "quay.io/test/sidecar:v2"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registries were created for each container registry")
				var registryList v1alpha1.RegistryList
				Expect(k8sClient.List(ctx, &registryList,
					client.InNamespace(namespace.Name),
					client.MatchingLabels{api.LabelManagedByKey: api.LabelManagedByValue},
				)).To(Succeed())

				Expect(registryList.Items).To(HaveLen(3))

				registryNames := make([]string, len(registryList.Items))
				for index, registry := range registryList.Items {
					registryNames[index] = registry.Name
				}
				Expect(registryNames).To(ContainElements(
					"workloadscan-ghcr-io",
					"workloadscan-index-docker-io",
					"workloadscan-quay-io",
				))

				By("Verifying the WorkloadScanReport contains all containers")
				var report storagev1alpha1.WorkloadScanReport
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-multi-registry-pod",
					Namespace: namespace.Name,
				}, &report)).To(Succeed())

				Expect(report.Spec.Containers).To(HaveLen(3))
			})

			It("should delete stale WorkloadScanReports when pods are removed", func(ctx context.Context) {
				By("Creating a pod")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "temporary-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling to create resources")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the report was created")
				var report storagev1alpha1.WorkloadScanReport
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-temporary-pod",
					Namespace: namespace.Name,
				}, &report)).To(Succeed())

				By("Deleting the pod")
				Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

				By("Reconciling again")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the report was deleted")
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-temporary-pod",
					Namespace: namespace.Name,
				}, &report)
				Expect(client.IgnoreNotFound(err)).To(Succeed())
				Expect(err).To(HaveOccurred())

				By("Verifying the registry was also deleted")
				var registry v1alpha1.Registry
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)
				Expect(client.IgnoreNotFound(err)).To(Succeed())
				Expect(err).To(HaveOccurred())
			})
		})

		When("ArtifactsNamespace is configured", func() {
			var artifactsNamespace *corev1.Namespace
			var sourceNamespaceA *corev1.Namespace
			var sourceNamespaceB *corev1.Namespace

			BeforeEach(func(ctx context.Context) {
				By("Creating the target namespace")
				artifactsNamespace = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "target-namespace-" + uuid.New().String()[:8],
					},
				}
				Expect(k8sClient.Create(ctx, artifactsNamespace)).To(Succeed())

				By("Creating source namespace A")
				sourceNamespaceA = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "source-namespace-a-" + uuid.New().String()[:8],
						Labels: map[string]string{
							"scan": "enabled",
						},
					},
				}
				Expect(k8sClient.Create(ctx, sourceNamespaceA)).To(Succeed())

				By("Creating source namespace B")
				sourceNamespaceB = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "source-namespace-b-" + uuid.New().String()[:8],
						Labels: map[string]string{
							"scan": "enabled",
						},
					},
				}
				Expect(k8sClient.Create(ctx, sourceNamespaceB)).To(Succeed())

				By("Updating configuration with target namespace")
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, configuration)).To(Succeed())
				configuration.Spec.ArtifactsNamespace = artifactsNamespace.Name
				Expect(k8sClient.Update(ctx, configuration)).To(Succeed())
			})

			It("should create registries in the target namespace", func(ctx context.Context) {
				By("Creating a pod in source namespace A")
				podA := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-a",
						Namespace: sourceNamespaceA.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podA)).To(Succeed())

				By("Reconciling source namespace A")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registry was created in target namespace")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())

				By("Verifying no registry in source namespace")
				var registryList v1alpha1.RegistryList
				Expect(k8sClient.List(ctx, &registryList, client.InNamespace(sourceNamespaceA.Name))).To(Succeed())
				Expect(registryList.Items).To(BeEmpty())

				By("Verifying WorkloadScanReport was created in source namespace")
				var report storagev1alpha1.WorkloadScanReport
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "pod-pod-a",
					Namespace: sourceNamespaceA.Name,
				}, &report)).To(Succeed())

				By("Verifying ImageRef points to target namespace")
				Expect(report.Spec.Containers[0].ImageRef.Namespace).To(Equal(artifactsNamespace.Name))
			})

			It("should merge conditions from multiple namespaces using labels", func(ctx context.Context) {
				By("Creating a pod in source namespace A")
				podA := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-a",
						Namespace: sourceNamespaceA.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podA)).To(Succeed())

				By("Reconciling source namespace A")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Creating a pod in source namespace B with same and different images")
				podB := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-b",
						Namespace: sourceNamespaceB.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
							{Name: "other", Image: "ghcr.io/test/app:v2"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podB)).To(Succeed())

				By("Reconciling source namespace B")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceB.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registry has merged conditions")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())

				Expect(registry.Spec.Repositories).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].MatchOperator).To(Equal(v1alpha1.MatchOperatorOr))
				// Only 2 conditions: tag-v1 (shared) and tag-v2 (only namespace B)
				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(2))

				conditionsByName := make(map[string]v1alpha1.MatchCondition)
				for _, cond := range registry.Spec.Repositories[0].MatchConditions {
					conditionsByName[cond.Name] = cond
				}

				By("Verifying tag-v1 has labels for both namespaces")
				Expect(conditionsByName).To(HaveKey("tag-v1"))
				Expect(conditionsByName["tag-v1"].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceA.Name, "true"))
				Expect(conditionsByName["tag-v1"].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceB.Name, "true"))

				By("Verifying tag-v2 has label only for namespace B")
				Expect(conditionsByName).To(HaveKey("tag-v2"))
				Expect(conditionsByName["tag-v2"].Labels).NotTo(HaveKey("namespace/" + sourceNamespaceA.Name))
				Expect(conditionsByName["tag-v2"].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceB.Name, "true"))
			})

			It("should remove namespace label when namespace stops matching", func(ctx context.Context) {
				By("Creating pods in both namespaces with the same image")
				podA := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-a",
						Namespace: sourceNamespaceA.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podA)).To(Succeed())

				podB := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-b",
						Namespace: sourceNamespaceB.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podB)).To(Succeed())

				By("Reconciling both namespaces")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceB.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying condition has labels for both namespaces")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceA.Name, "true"))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceB.Name, "true"))

				By("Updating namespace A to no longer match selector")
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: sourceNamespaceA.Name}, sourceNamespaceA)).To(Succeed())
				sourceNamespaceA.Labels["scan"] = "disabled"
				Expect(k8sClient.Update(ctx, sourceNamespaceA)).To(Succeed())

				By("Reconciling namespace A")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying namespace A label was removed but condition still exists")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())

				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Labels).NotTo(HaveKey("namespace/" + sourceNamespaceA.Name))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Labels).To(HaveKeyWithValue("namespace/"+sourceNamespaceB.Name, "true"))
			})

			It("should delete condition when no namespace labels remain", func(ctx context.Context) {
				By("Creating pods in both namespaces with different images")
				podA := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-a",
						Namespace: sourceNamespaceA.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podA)).To(Succeed())

				podB := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-b",
						Namespace: sourceNamespaceB.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v2"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podB)).To(Succeed())

				By("Reconciling both namespaces")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceB.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying both conditions exist")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(2))

				By("Updating namespace A to no longer match selector")
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: sourceNamespaceA.Name}, sourceNamespaceA)).To(Succeed())
				sourceNamespaceA.Labels["scan"] = "disabled"
				Expect(k8sClient.Update(ctx, sourceNamespaceA)).To(Succeed())

				By("Reconciling namespace A")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying tag-v1 condition was deleted (no labels remain)")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())

				Expect(registry.Spec.Repositories[0].MatchConditions).To(HaveLen(1))
				Expect(registry.Spec.Repositories[0].MatchConditions[0].Name).To(Equal("tag-v2"))
			})

			It("should delete registry when all conditions are removed", func(ctx context.Context) {
				By("Creating a pod in source namespace A")
				podA := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-a",
						Namespace: sourceNamespaceA.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, podA)).To(Succeed())

				By("Reconciling namespace A")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registry exists")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)).To(Succeed())

				By("Deleting the pod")
				Expect(k8sClient.Delete(ctx, podA)).To(Succeed())

				By("Reconciling namespace A again")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: sourceNamespaceA.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registry was deleted")
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: artifactsNamespace.Name,
				}, &registry)
				Expect(client.IgnoreNotFound(err)).To(Succeed())
				Expect(err).To(HaveOccurred())
			})
		})

		When("namespace selector is not specified", func() {
			BeforeEach(func(ctx context.Context) {
				By("Updating configuration to have no namespace selector")
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, configuration)).To(Succeed())
				configuration.Spec.NamespaceSelector = nil
				Expect(k8sClient.Update(ctx, configuration)).To(Succeed())

				By("Creating a namespace without any labels")
				namespace = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "any-namespace-" + uuid.New().String()[:8],
					},
				}
				Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
			})

			It("should match all namespaces", func(ctx context.Context) {
				By("Creating a pod")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "any-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying registry was created")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
			})
		})

		When("ScanOnChange is enabled", func() {
			BeforeEach(func(ctx context.Context) {
				By("Updating configuration with ScanOnChange enabled")
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: v1alpha1.WorkloadScanConfigurationName}, configuration)).To(Succeed())
				configuration.Spec.ScanOnChange = true
				configuration.Spec.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"scan": "enabled",
					},
				}
				Expect(k8sClient.Update(ctx, configuration)).To(Succeed())

				By("Creating a namespace that matches")
				namespace = &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "scanonchange-namespace-" + uuid.New().String()[:8],
						Labels: map[string]string{
							"scan": "enabled",
						},
					},
				}
				Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
			})

			It("should set rescan annotation when a registry is created", func(ctx context.Context) {
				By("Creating a pod")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the registry has the rescan annotation")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).To(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})

			It("should set rescan annotation when a new tag condition is added", func(ctx context.Context) {
				By("Creating a pod with v1 tag")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying initial rescan annotation was set")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).To(HaveKey(v1alpha1.AnnotationRescanRequestedKey))

				By("Removing the rescan annotation to simulate it being processed")
				delete(registry.Annotations, v1alpha1.AnnotationRescanRequestedKey)
				Expect(k8sClient.Update(ctx, &registry)).To(Succeed())

				By("Verifying annotation was removed")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))

				By("Adding a new pod with v2 tag")
				pod2 := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-2",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v2"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod2)).To(Succeed())

				By("Reconciling the namespace again")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying rescan annotation was set again")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).To(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})

			It("should not set rescan annotation when a tag condition is removed", func(ctx context.Context) {
				By("Creating two pods with different tags")
				pod1 := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-1",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod1)).To(Succeed())

				pod2 := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-2",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v2"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod2)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Removing the rescan annotation to simulate it being processed")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				delete(registry.Annotations, v1alpha1.AnnotationRescanRequestedKey)
				Expect(k8sClient.Update(ctx, &registry)).To(Succeed())

				By("Deleting one pod to remove a tag condition")
				Expect(k8sClient.Delete(ctx, pod2)).To(Succeed())

				By("Reconciling the namespace again")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying rescan annotation was not set")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})

			It("should not set rescan annotation when conditions are unchanged", func(ctx context.Context) {
				By("Creating a pod")
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace.Name,
						UID:       types.UID(uuid.New().String()),
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "app", Image: "ghcr.io/test/app:v1"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				By("Reconciling the namespace")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Removing the rescan annotation to simulate it being processed")
				var registry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				delete(registry.Annotations, v1alpha1.AnnotationRescanRequestedKey)
				Expect(k8sClient.Update(ctx, &registry)).To(Succeed())

				By("Reconciling the namespace again without changes")
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: namespace.Name},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying rescan annotation was not set")
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      "workloadscan-ghcr-io",
					Namespace: namespace.Name,
				}, &registry)).To(Succeed())
				Expect(registry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})
		})
	})
})
