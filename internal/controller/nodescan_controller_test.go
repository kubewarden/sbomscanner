package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("NodeScan Controller", func() {
	When("a Node still exists", func() {
		var reconciler NodeScanReconciler
		var node corev1.Node

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanReconciler{
				Client: k8sClient,
			}

			By("Creating a Node")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())
		})

		It("should be a no-op", func(ctx context.Context) {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: node.Name},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	When("a Node is deleted", func() {
		var reconciler NodeScanReconciler
		var nodeName string

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanReconciler{
				Client: k8sClient,
			}

			nodeName = fmt.Sprintf("node-%s", uuid.New().String())

			By("Creating and then deleting a Node")
			node := corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())
			Expect(k8sClient.Delete(ctx, &node)).To(Succeed())
		})

		It("should cleanup NodeScanJobs for the deleted node", func(ctx context.Context) {
			By("Creating a NodeScanJob tied to the deleted node")
			nodeScanJob := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", nodeName),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: nodeName,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())

			By("Reconciling the deleted node")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob was deleted")
			deletedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nodeScanJob.Name}, deletedJob)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(deletedJob.Name).To(BeEmpty())
		})

		It("should cleanup NodeSBOMs for the deleted node", func(ctx context.Context) {
			By("Creating a NodeSBOM tied to the deleted node")
			nodesbom := storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{
					Name:     nodeName,
					Platform: "linux/amd64",
				},
				SPDX: runtime.RawExtension{Raw: []byte("{}")},
			}
			Expect(k8sClient.Create(ctx, &nodesbom)).To(Succeed())

			By("Reconciling the deleted node")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeSBOM was deleted")
			deletedSBOM := &storagev1alpha1.NodeSBOM{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: nodesbom.Name}, deletedSBOM)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(deletedSBOM.Name).To(BeEmpty())
		})

		It("should not affect resources for other nodes", func(ctx context.Context) {
			By("Creating a NodeScanJob for a different node")
			otherNodeName := fmt.Sprintf("other-node-%s", uuid.New().String())
			otherJob := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", otherNodeName),
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: otherNodeName,
				},
			}
			Expect(k8sClient.Create(ctx, &otherJob)).To(Succeed())

			By("Reconciling the deleted node")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: nodeName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the other node's NodeScanJob still exists")
			remainingJob := &v1alpha1.NodeScanJob{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: otherJob.Name}, remainingJob)).To(Succeed())
		})
	})
})
