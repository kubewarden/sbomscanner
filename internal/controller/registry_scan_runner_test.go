package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
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
			var rescanKey string

			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with a rescan annotation")
				rescanKey = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano())
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							rescanKey: `{}`,
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
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(rescanKey))
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
				Expect(updatedRegistry.Annotations).To(HaveKeyWithValue(rescanKey, `{}`))
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
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(rescanKey))
			})

			It("Should preserve a rescan annotation added during processing", func(ctx context.Context) {
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

				By("Adding a second rescan annotation before scanner runs")
				newKey := fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano()) + "-late"
				var currentRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &currentRegistry)).To(Succeed())
				currentRegistry.Annotations[newKey] = `{}`
				Expect(k8sClient.Update(ctx, &currentRegistry)).To(Succeed())

				By("Running the registry scanner with the original annotation snapshot")
				err := runner.checkRegistryForScan(ctx, registry)
				Expect(err).To(Succeed())

				By("Verifying the late annotation was preserved")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).To(HaveKeyWithValue(newKey, `{}`))
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(rescanKey))
			})
		})

		When("A Registry has a JSON rescan annotation targeting specific repositories", func() {
			var rescanKey, rescanValue string

			BeforeEach(func(ctx context.Context) {
				By("Building a JSON rescan request payload")
				req := v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}
				v, err := json.Marshal(req)
				Expect(err).NotTo(HaveOccurred())
				rescanValue = string(v)
				rescanKey = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano())

				By("Creating a Registry with the JSON rescan annotation")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							rescanKey: rescanValue,
						},
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should propagate the targets to the created ScanJob and remove the annotation", func(ctx context.Context) {
				By("Running the registry scanner")
				Expect(runner.scanRegistries(ctx)).To(Succeed())

				By("Verifying a new scan job was created with the targets")
				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))
				Expect(scanJobs.Items[0].Spec.Repositories).To(Equal([]v1alpha1.ScanJobRepository{
					{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
				}))

				By("Verifying the rescan annotation was removed")
				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(rescanKey))
			})
		})

		When("A Registry has multiple concurrent rescan annotations", func() {
			var keyA, keyB string

			BeforeEach(func(ctx context.Context) {
				By("Building two JSON rescan request payloads with disjoint targets")
				reqA := v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}
				reqB := v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/baz", MatchConditions: []string{"tag-v2"}},
					},
				}
				vA, err := json.Marshal(reqA)
				Expect(err).NotTo(HaveOccurred())
				vB, err := json.Marshal(reqB)
				Expect(err).NotTo(HaveOccurred())

				keyA = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano()) + "-a"
				keyB = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano()) + "-b"

				By("Creating a Registry with both annotations set")
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							keyA: string(vA),
							keyB: string(vB),
						},
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should create one ScanJob targeting the union of repositories and remove both annotations", func(ctx context.Context) {
				Expect(runner.scanRegistries(ctx)).To(Succeed())

				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))
				Expect(scanJobs.Items[0].Spec.Repositories).To(ConsistOf(
					v1alpha1.ScanJobRepository{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					v1alpha1.ScanJobRepository{Name: "foo/baz", MatchConditions: []string{"tag-v2"}},
				))

				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(keyA))
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(keyB))
			})
		})

		When("A Registry has a malformed rescan annotation alongside a valid one", func() {
			var malformedKey, validKey string

			BeforeEach(func(ctx context.Context) {
				validReq := v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}
				v, err := json.Marshal(validReq)
				Expect(err).NotTo(HaveOccurred())

				malformedKey = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano()) + "-bad"
				validKey = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano()) + "-good"

				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							malformedKey: `{not json`,
							validKey:     string(v),
						},
					},
					Spec: v1alpha1.RegistrySpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, registry)).To(Succeed())
			})

			It("Should ignore the malformed annotation, scan the valid targets, and remove both", func(ctx context.Context) {
				Expect(runner.scanRegistries(ctx)).To(Succeed())

				scanJobs := &v1alpha1.ScanJobList{}
				Expect(k8sClient.List(ctx, scanJobs,
					client.InNamespace("default"),
					client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name},
				)).To(Succeed())
				Expect(scanJobs.Items).To(HaveLen(1))
				Expect(scanJobs.Items[0].Spec.Repositories).To(Equal([]v1alpha1.ScanJobRepository{
					{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
				}))

				var updatedRegistry v1alpha1.Registry
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      registry.Name,
					Namespace: registry.Namespace,
				}, &updatedRegistry)).To(Succeed())
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(malformedKey))
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(validKey))
			})
		})

		When("A Registry has a rescan annotation but no scan interval", func() {
			var rescanKey string

			BeforeEach(func(ctx context.Context) {
				By("Creating a Registry with rescan annotation but disabled scan interval")
				rescanKey = fmt.Sprintf("%s%d", v1alpha1.AnnotationRescanRequestedKeyPrefix, time.Now().UnixNano())
				registry = &v1alpha1.Registry{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
						Annotations: map[string]string{
							rescanKey: `{}`,
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
				Expect(updatedRegistry.Annotations).NotTo(HaveKey(rescanKey))
			})
		})
	})
})

func TestCollectRescanRequests(t *testing.T) {
	tests := []struct {
		name               string
		annotations        map[string]string
		wantKeys           []string
		wantTargets        []v1alpha1.ScanJobRepository
		wantScanEverything bool
	}{
		{
			name:        "no annotations",
			annotations: nil,
		},
		{
			name: "empty payload triggers full-registry scan",
			annotations: map[string]string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "1": `{}`,
			},
			wantKeys:           []string{v1alpha1.AnnotationRescanRequestedKeyPrefix + "1"},
			wantScanEverything: true,
		},
		{
			name: "single targeted annotation",
			annotations: map[string]string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "1": marshalRescanRequest(t, v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}),
			},
			wantKeys: []string{v1alpha1.AnnotationRescanRequestedKeyPrefix + "1"},
			wantTargets: []v1alpha1.ScanJobRepository{
				{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
			},
		},
		{
			name: "two annotations for the same repo union their conditions",
			annotations: map[string]string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "a": marshalRescanRequest(t, v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}),
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "b": marshalRescanRequest(t, v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v2"}},
					},
				}),
			},
			wantKeys: []string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "a",
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "b",
			},
			wantTargets: []v1alpha1.ScanJobRepository{
				{Name: "foo/bar", MatchConditions: []string{"tag-v1", "tag-v2"}},
			},
		},
		{
			name: "wildcard annotation subsumes specific conditions for the same repo",
			annotations: map[string]string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "a": marshalRescanRequest(t, v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar", MatchConditions: []string{"tag-v1"}},
					},
				}),
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "b": marshalRescanRequest(t, v1alpha1.RescanRequest{
					Repositories: []v1alpha1.ScanJobRepository{
						{Name: "foo/bar"},
					},
				}),
			},
			wantKeys: []string{
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "a",
				v1alpha1.AnnotationRescanRequestedKeyPrefix + "b",
			},
			wantTargets: []v1alpha1.ScanJobRepository{
				{Name: "foo/bar"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{Annotations: test.annotations},
			}
			keys, targets, scanEverything := collectRescanRequests(context.Background(), registry)
			require.ElementsMatch(t, test.wantKeys, keys)
			require.Equal(t, test.wantTargets, targets)
			require.Equal(t, test.wantScanEverything, scanEverything)
		})
	}
}

func marshalRescanRequest(t *testing.T, req v1alpha1.RescanRequest) string {
	t.Helper()
	v, err := json.Marshal(req)
	require.NoError(t, err)
	return string(v)
}
