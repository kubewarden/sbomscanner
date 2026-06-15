package controller

import (
	"context"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/handlers"
	messagingMocks "github.com/kubewarden/sbomscanner/internal/messaging/mocks"
)

var _ = Describe("NodeScanJob Controller", func() {
	When("A NodeScanJob is created for a valid Node", func() {
		var reconciler NodeScanJobReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var node corev1.Node
		var config v1alpha1.NodeScanConfiguration
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new NodeScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = NodeScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a NodeScanConfiguration")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())

			By("Creating a Node")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating a NodeScanJob for the node")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", uuid.New().String()),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: node.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
		})

		It("should successfully reconcile and publish GenerateNodeSBOM message", func(ctx context.Context) {
			By("Setting up the expected message publication")
			message, err := json.Marshal(&handlers.GenerateNodeSBOMMessage{
				NodeBaseMessage: handlers.NodeBaseMessage{
					NodeScanJob: handlers.ObjectRef{
						Name:      nodeScanJob.Name,
						Namespace: nodeScanJob.Namespace,
						UID:       string(nodeScanJob.GetUID()),
					},
				},
				Node: handlers.ObjectRef{
					Name: node.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			mockPublisher.On("Publish", mock.Anything, handlers.GenerateNodeSBOMSubject+"."+node.Name, fmt.Sprintf("generateNodeSBOM/%s", nodeScanJob.GetUID()), message).Return(nil)

			By("Reconciling the NodeScanJob")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: nodeScanJob.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob is marked as scheduled")
			updatedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, updatedJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedJob.IsScheduled()).To(BeTrue())
		})
	})

	When("A NodeScanJob is created but NodeScanConfiguration is missing", func() {
		var reconciler NodeScanJobReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var node corev1.Node
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new NodeScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = NodeScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a Node")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating a NodeScanJob for the node")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", uuid.New().String()),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: node.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		It("should mark the NodeScanJob as failed", func(ctx context.Context) {
			By("Reconciling the NodeScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: nodeScanJob.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob is marked as failed")
			updatedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, updatedJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedJob.IsFailed()).To(BeTrue())
		})
	})

	When("A NodeScanJob is created but node does not match NodeScanConfiguration nodeSelector", func() {
		var reconciler NodeScanJobReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var node corev1.Node
		var config v1alpha1.NodeScanConfiguration
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new NodeScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = NodeScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a NodeScanConfiguration with a nodeSelector")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "production"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())

			By("Creating a Node without matching labels")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   fmt.Sprintf("node-%s", uuid.New().String()),
					Labels: map[string]string{"env": "staging"},
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating a NodeScanJob for the node")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", uuid.New().String()),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: node.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
		})

		It("should mark the NodeScanJob as failed", func(ctx context.Context) {
			By("Reconciling the NodeScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: nodeScanJob.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob is marked as failed")
			updatedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, updatedJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedJob.IsFailed()).To(BeTrue())
		})
	})

	When("A NodeScanJob is created but node platform is not allowed", func() {
		var reconciler NodeScanJobReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var node corev1.Node
		var config v1alpha1.NodeScanConfiguration
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new NodeScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = NodeScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a NodeScanConfiguration with platform filter")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())

			By("Creating a Node with a different platform")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "arm64",
					},
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating a NodeScanJob for the node")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", uuid.New().String()),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: node.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
		})

		It("should mark the NodeScanJob as failed", func(ctx context.Context) {
			By("Reconciling the NodeScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: nodeScanJob.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob is marked as failed")
			updatedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, updatedJob)
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedJob.IsFailed()).To(BeTrue())
		})
	})

	When("A NodeScanJob is created for an invalid Node", func() {
		var reconciler NodeScanJobReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var mockPublisher *messagingMocks.MockPublisher

		BeforeEach(func(ctx context.Context) {
			By("Creating a new NodeScanJobReconciler")
			mockPublisher = messagingMocks.NewMockPublisher(GinkgoT())
			reconciler = NodeScanJobReconciler{
				Client:    k8sClient,
				Publisher: mockPublisher,
				Scheme:    k8sClient.Scheme(),
			}

			By("Creating a NodeScanJob referencing a non-existent node")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", uuid.New().String()),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: "non-existent-node",
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		It("should delete the NodeScanJob when the node no longer exists", func(ctx context.Context) {
			By("Reconciling the NodeScanJob")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: nodeScanJob.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob was deleted")
			deletedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, deletedJob)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(deletedJob.Name).To(BeEmpty())
		})
	})
})
