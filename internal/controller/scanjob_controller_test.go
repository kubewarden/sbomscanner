package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/handlers"
	messagingMocks "github.com/kubewarden/sbomscanner/internal/messaging/mocks"
)

var _ = Describe("ScanJob Controller", func() {
	When("A ScanJob is created with a valid Registry", func() {
		var reconciler ScanJobReconciler
		var scanJob v1alpha1.ScanJob
		var registry v1alpha1.Registry
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new ScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = ScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a Registry")
			registry = v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "https://registry.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, &registry)).To(Succeed())

			By("Creating a ScanJob")
			scanJob = v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: registry.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &scanJob)).To(Succeed())
		})

		It("should successfully reconcile and publish CreateCatalog message", func(ctx context.Context) {
			By("Setting up the expected message publication")
			message, err := json.Marshal(&handlers.CreateCatalogMessage{
				BaseMessage: handlers.BaseMessage{
					ScanJob: handlers.ObjectRef{
						Name:      scanJob.Name,
						Namespace: scanJob.Namespace,
						UID:       string(scanJob.GetUID()),
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			mockPublisher.On("Publish", mock.Anything, handlers.CreateCatalogSubject, fmt.Sprintf("createCatalog/%s", scanJob.GetUID()), message).Return(nil)

			By("Reconciling the ScanJob")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      scanJob.Name,
					Namespace: scanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			updatedScanJob := &v1alpha1.ScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
			}, updatedScanJob)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that the ScanJob has the correct owner reference")
			Expect(updatedScanJob.OwnerReferences).To(HaveLen(1))
			Expect(updatedScanJob.OwnerReferences[0].Name).To(Equal(registry.Name))
			Expect(updatedScanJob.OwnerReferences[0].Kind).To(Equal("Registry"))
			Expect(updatedScanJob.OwnerReferences[0].APIVersion).To(Equal(v1alpha1.GroupVersion.String()))
			Expect(updatedScanJob.OwnerReferences[0].UID).To(Equal(registry.UID))
			Expect(*updatedScanJob.OwnerReferences[0].Controller).To(BeTrue())

			By("Verifying that registry data was stored in annotations")
			registryData, exists := updatedScanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]
			Expect(exists).To(BeTrue())

			var storedRegistry v1alpha1.Registry
			err = json.Unmarshal([]byte(registryData), &storedRegistry)
			Expect(err).NotTo(HaveOccurred())
			Expect(storedRegistry.Name).To(Equal(registry.Name))

			By("Reconciling the ScanJob again after the patch")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      scanJob.Name,
					Namespace: scanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the ScanJob is marked as scheduled")
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
			}, &scanJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(scanJob.IsScheduled()).To(BeTrue())
		})
	})

	When("A ScanJob references a non-existent Registry", func() {
		var reconciler ScanJobReconciler
		var scanJob v1alpha1.ScanJob
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new ScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = ScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a ScanJob with non-existent Registry")
			scanJob = v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: "non-existent-registry",
				},
			}
			Expect(k8sClient.Create(ctx, &scanJob)).To(Succeed())
		})

		It("should mark the ScanJob as failed", func(ctx context.Context) {
			By("Reconciling the ScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      scanJob.Name,
					Namespace: scanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the ScanJob is marked as failed")
			updatedScanJob := &v1alpha1.ScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
			}, updatedScanJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedScanJob.IsFailed()).To(BeTrue())
		})
	})

	When("A ScanJob has Repositories that do not match the Registry", func() {
		var reconciler ScanJobReconciler
		var registry v1alpha1.Registry
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = ScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a Registry with known repositories and match conditions")
			registry = v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "https://registry.example.com",
					Repositories: []v1alpha1.Repository{
						{
							Name: "foo/bar",
							MatchConditions: []v1alpha1.MatchCondition{
								{Name: "tag-v1", Expression: `tag == "v1"`},
								{Name: "tag-v2", Expression: `tag == "v2"`},
							},
						},
						{
							Name: "foo/baz",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &registry)).To(Succeed())
		})

		DescribeTable("should mark the ScanJob as failed with the expected reason",
			func(ctx context.Context, repositories []v1alpha1.ScanJobRepository, expectedReason string) {
				By("Creating a ScanJob with invalid targets")
				scanJob := v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.New().String(),
						Namespace: "default",
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry:     registry.Name,
						Repositories: repositories,
					},
				}
				Expect(k8sClient.Create(ctx, &scanJob)).To(Succeed())

				By("Reconciling the ScanJob")
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      scanJob.Name,
						Namespace: scanJob.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the ScanJob is marked as failed with the expected reason")
				updated := &v1alpha1.ScanJob{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      scanJob.Name,
					Namespace: scanJob.Namespace,
				}, updated)).To(Succeed())
				Expect(updated.IsFailed()).To(BeTrue())
				cond := meta.FindStatusCondition(updated.Status.Conditions, v1alpha1.ConditionTypeFailed)
				Expect(cond).NotTo(BeNil())
				Expect(cond.Reason).To(Equal(expectedReason))
			},
			Entry("unknown repository => RepositoryNotFound",
				[]v1alpha1.ScanJobRepository{{Name: "missing/repo"}},
				v1alpha1.ReasonRepositoryNotFound,
			),
			Entry("unknown matchCondition => MatchConditionNotFound",
				[]v1alpha1.ScanJobRepository{{Name: "foo/bar", MatchConditions: []string{"tag-missing"}}},
				v1alpha1.ReasonMatchConditionNotFound,
			),
		)
	})

	When("A ScanJob is already completed", func() {
		var reconciler ScanJobReconciler
		var scanJob v1alpha1.ScanJob
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new ScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = ScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a completed ScanJob")
			scanJob = v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      uuid.New().String(),
					Namespace: "default",
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: "test-registry",
				},
			}
			Expect(k8sClient.Create(ctx, &scanJob)).To(Succeed())

			By("Marking the ScanJob as completed")
			scanJob.MarkComplete(v1alpha1.ReasonAllImagesScanned, "Scan completed successfully")
			Expect(k8sClient.Status().Update(ctx, &scanJob)).To(Succeed())
		})

		It("should not process the ScanJob", func(ctx context.Context) {
			By("Reconciling the ScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      scanJob.Name,
					Namespace: scanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	When("There are more than scanJobsHistoryLimit ScanJobs for a registry", func() {
		var reconciler ScanJobReconciler
		var mockPublisher *messagingMocks.MockPublisher
		var registry v1alpha1.Registry
		var scanJobs []v1alpha1.ScanJob
		var newScanJob v1alpha1.ScanJob

		BeforeEach(func(ctx context.Context) {
			By("Creating a new ScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = ScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}
			By("Creating a Registry")
			registry = v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cleanup-test-registry",
					Namespace: "default",
				},
				Spec: v1alpha1.RegistrySpec{
					URI: "https://registry.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, &registry)).To(Succeed())

			By("Creating scanJobsHistoryLimit existing ScanJobs")
			scanJobs = make([]v1alpha1.ScanJob, 12)
			for i := range scanJobsHistoryLimit {
				creationTimestamp := time.Now().Add(-time.Duration(i) * time.Hour).UTC().Format(time.RFC3339Nano)

				scanJob := v1alpha1.ScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("old-scanjob-%d", i),
						Namespace: "default",
						Annotations: map[string]string{
							v1alpha1.AnnotationScanJobCreationTimestampKey: creationTimestamp,
						},
					},
					Spec: v1alpha1.ScanJobSpec{
						Registry: registry.Name,
					},
				}
				Expect(k8sClient.Create(ctx, &scanJob)).To(Succeed())
				scanJobs[i] = scanJob
			}

			By("Creating a new ScanJob that will trigger cleanup")
			newScanJob = v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "new-scanjob",
					Namespace: "default",
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: registry.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &newScanJob)).To(Succeed())
		})

		It("should cleanup old ScanJobs during reconciliation", func(ctx context.Context) {
			By("Setting up the expected message publication")
			expectedMessage, err := json.Marshal(&handlers.CreateCatalogMessage{
				BaseMessage: handlers.BaseMessage{
					ScanJob: handlers.ObjectRef{
						Name:      newScanJob.Name,
						Namespace: newScanJob.Namespace,
						UID:       string(newScanJob.GetUID()),
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			mockPublisher.On("Publish", mock.Anything, handlers.CreateCatalogSubject, fmt.Sprintf("createCatalog/%s", newScanJob.GetUID()), expectedMessage).Return(nil)

			By("Reconciling the new ScanJob")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      newScanJob.Name,
					Namespace: newScanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that only 10 ScanJobs remain for this registry")
			scanJobList := &v1alpha1.ScanJobList{}
			err = k8sClient.List(ctx, scanJobList, client.InNamespace("default"), client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: registry.Name})
			Expect(err).NotTo(HaveOccurred())
			Expect(scanJobList.Items).To(HaveLen(scanJobsHistoryLimit))

			By("Reconciling the ScanJob again after the patch")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      newScanJob.Name,
					Namespace: newScanJob.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the new ScanJob still exists and is scheduled")
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      newScanJob.Name,
				Namespace: newScanJob.Namespace,
			}, &newScanJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(newScanJob.IsScheduled()).To(BeTrue())
		})
	})
})
