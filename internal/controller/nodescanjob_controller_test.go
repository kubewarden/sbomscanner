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

		It("should still reconcile and publish GenerateNodeSBOM message", func(ctx context.Context) {
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
					Name: "non-existent-node",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			mockPublisher.On("Publish", mock.Anything, handlers.GenerateNodeSBOMSubject+".non-existent-node", fmt.Sprintf("generateNodeSBOM/%s", nodeScanJob.GetUID()), message).Return(nil)

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
})
