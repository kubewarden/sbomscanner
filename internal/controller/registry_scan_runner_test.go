package controller

import (
	"context"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("RegistryScanRunner", func() {
	Describe("scanRegistries", func() {
		var (
			runner   *RegistryScanRunner
			registry *v1alpha1.Registry
		)

		BeforeEach(func() {
			By("Setting up the RegistryScanRunner")
			runner = &RegistryScanRunner{
				Client: k8sClient,
			}
		})

		When("A registry needs scanning", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with a scan interval of 1 hour")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should create an initial scan job when no jobs exist", func(ctx context.Context) {
				By("Verifying no scan jobs exist initially")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(BeEmpty())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying a new scan job was created")
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))

				By("Checking the scan job has correct registry and trigger annotation")
				Expect(scanJobs.Items[0].Spec.Registry).To(Equal(registry.Name))
				Expect(scanJobs.Items[0].Annotations).To(HaveKeyWithValue(v1alpha1.AnnotationScanJobTriggerKey, "runner"))
			})

			It("Should not create a new job when one is already running", func(ctx context.Context) {
				By("Creating an existing scan job for the registry")
				existingJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-job-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, existingJob)).To(Succeed())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying no additional scan job was created")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))
			})

			It("Should create a new scan job when the last one completed and interval has passed", func(ctx context.Context) {
				By("Creating a completed scan job that's older than the scan interval")
				completedJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "completed-job-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, completedJob)).To(Succeed())
				completedJob.MarkComplete(v1alpha1.ReasonComplete, "Done")
				completedJob.Status.CompletionTime = &metav1.Time{Time: time.Now().Add(-2 * time.Hour)}
				Expect(k8sClient.Status().Update(ctx, completedJob)).To(Succeed())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying a new scan job was created due to interval expiration")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(2))
			})

			It("Should not create a new scan job when the last one completed recently", func(ctx context.Context) {
				By("Creating a recently completed scan job within the scan interval")
				recentJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "recent-job-" + uuid.New().String(),
						Namespace:         "default",
						CreationTimestamp: metav1.Time{Time: time.Now()},
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, recentJob)).To(Succeed())
				recentJob.MarkComplete(v1alpha1.ReasonComplete, "Done")
				recentJob.Status.CompletionTime = &metav1.Time{Time: time.Now()}
				Expect(k8sClient.Status().Update(ctx, recentJob)).To(Succeed())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying no new ScanJob was created due to recent completion")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))
			})
		})

		When("A Registry has no scan interval", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with scan interval disabled (0 duration)")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "disabled-registry-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 0},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should not create any scan job", func(ctx context.Context) {
				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying no ScanJobs were created for disabled registry")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(BeEmpty())
			})
		})

		When("A Registry has a rescan annotation", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with a rescan annotation")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							v1alpha1.AnnotationRescanRequestedKey: "2026-02-03T10:00:00Z",
						},
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should create a scan job and remove the annotation when no job is running", func(ctx context.Context) {
				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying a new scan job was created")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))

				By("Verifying the rescan annotation was removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})

			It("Should not create a scan job and keep the annotation when a job is already running", func(ctx context.Context) {
				By("Creating an existing running scan job for the registry")
				existingJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "running-job-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, existingJob)).To(Succeed())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying no additional scan job was created")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))

				By("Verifying the rescan annotation was NOT removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).To(HaveKeyWithValue(v1alpha1.AnnotationRescanRequestedKey, "2026-02-03T10:00:00Z"))
			})

			It("Should create a scan job after running job completes and remove the annotation", func(ctx context.Context) {
				By("Creating a completed scan job for the registry")
				completedJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "completed-job-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, completedJob)).To(Succeed())
				completedJob.MarkComplete(v1alpha1.ReasonComplete, "Done")
				completedJob.Status.CompletionTime = &metav1.Time{Time: time.Now()}
				Expect(k8sClient.Status().Update(ctx, completedJob)).To(Succeed())

				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying a new scan job was created due to rescan annotation")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(2))

				By("Verifying the rescan annotation was removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})

			It("Should not remove the annotation if it changed during processing", func(ctx context.Context) {
				By("Creating a completed scan job for the registry")
				completedJob := &v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "completed-job-" + uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, completedJob)).To(Succeed())
				completedJob.MarkComplete(v1alpha1.ReasonComplete, "Done")
				completedJob.Status.CompletionTime = &metav1.Time{Time: time.Now()}
				Expect(k8sClient.Status().Update(ctx, completedJob)).To(Succeed())

				By("Updating the rescan annotation to a newer timestamp before scanner runs")
				var currentRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &currentRegistry)).To(Succeed())
				currentRegistry.Annotations[v1alpha1.AnnotationRescanRequestedKey] = "2026-02-03T11:00:00Z"
				Expect(k8sClient.Update(ctx, &currentRegistry)).To(Succeed())

				By("Running the registry scanner with the old annotation value")
				// Simulate the runner having read the old annotation value
				err := runner.checkRegistryForScan(ctx, registry)
				Expect(err).To(Succeed())

				By("Verifying the newer rescan annotation was NOT removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).To(HaveKeyWithValue(v1alpha1.AnnotationRescanRequestedKey, "2026-02-03T11:00:00Z"))
			})
		})

		When("A Registry has a rescan annotation but no scan interval", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with rescan annotation but disabled scan interval")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							v1alpha1.AnnotationRescanRequestedKey: "2026-02-03T10:00:00Z",
						},
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 0},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should create a scan job for rescan even with disabled interval", func(ctx context.Context) {
				By("Running the registry scanner")
				err := runner.scanRegistries(ctx)
				Expect(err).To(Succeed())

				By("Verifying a scan job was created due to rescan annotation")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))

				By("Verifying the rescan annotation was removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(v1alpha1.AnnotationRescanRequestedKey))
			})
		})
	})
})
