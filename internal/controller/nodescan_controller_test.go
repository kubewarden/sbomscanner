package controller

import (
	"context"
	"fmt"

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
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("NodeScan Controller", func() {
	When("NodeScanConfiguration does not exist", func() {
		var reconciler NodeScanReconciler
		var nodeScanJob v1alpha1.NodeScanJob
		var node corev1.Node

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a Node")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating a NodeScanJob managed by the controller")
			nodeScanJob = v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("nodescanjob-%s", node.Name),
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
						api.LabelNodeScanKey:  api.LabelNodeScanValue,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Node",
							Name:       node.Name,
							UID:        node.UID,
						},
					},
				},
				Spec: v1alpha1.NodeScanJobSpec{
					NodeName: node.Name,
				},
			}
			Expect(k8sClient.Create(ctx, &nodeScanJob)).To(Succeed())
		})

		It("should cleanup managed NodeScanJobs", func(ctx context.Context) {
			By("Reconciling without a NodeScanConfiguration")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the managed NodeScanJob was deleted")
			deletedJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: nodeScanJob.Name,
			}, deletedJob)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
		})
	})

	When("NodeScanConfiguration exists", func() {
		var reconciler NodeScanReconciler
		var config v1alpha1.NodeScanConfiguration
		var node corev1.Node

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a Node")
			node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-%s", uuid.New().String()),
				},
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "amd64",
					},
				},
			}
			Expect(k8sClient.Create(ctx, &node)).To(Succeed())

			By("Creating the NodeScanConfiguration")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			By("Deleting the NodeScanConfiguration")
			Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
		})

		It("should create a NodeScanJob for the node", func(ctx context.Context) {
			By("Reconciling the NodeScanConfiguration")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying a NodeScanJob was created for the node")
			expectedName := fmt.Sprintf("nodescanjob-%s", node.Name)
			createdJob := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: expectedName,
			}, createdJob)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the NodeScanJob has the correct spec")
			Expect(createdJob.Spec.NodeName).To(Equal(node.Name))

			By("Verifying the NodeScanJob has the expected labels")
			Expect(createdJob.Labels).To(HaveKeyWithValue(api.LabelManagedByKey, api.LabelManagedByValue))
			Expect(createdJob.Labels).To(HaveKeyWithValue(api.LabelNodeScanKey, api.LabelNodeScanValue))

			By("Verifying the NodeScanJob has the Node as owner")
			Expect(createdJob.OwnerReferences).To(HaveLen(1))
			Expect(createdJob.OwnerReferences[0].Name).To(Equal(node.Name))
			Expect(createdJob.OwnerReferences[0].Kind).To(Equal("Node"))
		})
	})

	When("NodeScanConfiguration has a platform filter", func() {
		var reconciler NodeScanReconciler
		var config v1alpha1.NodeScanConfiguration
		var amd64Node corev1.Node
		var arm64Node corev1.Node

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an amd64 node")
			amd64Node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-amd64-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &amd64Node)).To(Succeed())
			amd64Node.Status = corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{
					OperatingSystem: "linux",
					Architecture:    "amd64",
				},
			}
			Expect(k8sClient.Status().Update(ctx, &amd64Node)).To(Succeed())

			By("Creating an arm64 node")
			arm64Node = corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("node-arm64-%s", uuid.New().String()),
				},
			}
			Expect(k8sClient.Create(ctx, &arm64Node)).To(Succeed())
			arm64Node.Status = corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{
					OperatingSystem: "linux",
					Architecture:    "arm64",
				},
			}
			Expect(k8sClient.Status().Update(ctx, &arm64Node)).To(Succeed())
		})

		It("should only create NodeScanJobs for nodes with allowed platforms", func(ctx context.Context) {
			By("Creating a NodeScanConfiguration that only allows linux/amd64")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Platforms: []v1alpha1.Platform{
						{OS: "linux", Architecture: "amd64"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())
			defer func() {
				Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
			}()

			By("Reconciling the NodeScanConfiguration")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying a NodeScanJob was created for the amd64 node")
			amd64Job := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", amd64Node.Name),
			}, amd64Job)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no NodeScanJob was created for the arm64 node")
			arm64Job := &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", arm64Node.Name),
			}, arm64Job)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(arm64Job.Name).To(BeEmpty())
		})

		It("should cleanup NodeScanJobs when platform filter changes", func(ctx context.Context) {
			By("Creating a NodeScanConfiguration with no platform filter")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())
			defer func() {
				Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
			}()

			By("Reconciling to create NodeScanJobs for all nodes")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NodeScanJobs exist for both nodes")
			amd64Job := &v1alpha1.NodeScanJob{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", amd64Node.Name),
			}, amd64Job)).To(Succeed())
			arm64Job := &v1alpha1.NodeScanJob{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", arm64Node.Name),
			}, arm64Job)).To(Succeed())

			By("Updating the NodeScanConfiguration to only allow linux/amd64")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: v1alpha1.NodeScanConfigurationName,
			}, &config)).To(Succeed())
			config.Spec.Platforms = []v1alpha1.Platform{
				{OS: "linux", Architecture: "amd64"},
			}
			Expect(k8sClient.Update(ctx, &config)).To(Succeed())

			By("Reconciling again")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the amd64 NodeScanJob still exists")
			amd64Job = &v1alpha1.NodeScanJob{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", amd64Node.Name),
			}, amd64Job)).To(Succeed())

			By("Verifying the arm64 NodeScanJob was deleted")
			arm64Job = &v1alpha1.NodeScanJob{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: fmt.Sprintf("nodescanjob-%s", arm64Node.Name),
			}, arm64Job)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(arm64Job.Name).To(BeEmpty())
		})

		It("should cleanup NodeSBOMs when platform filter changes", func(ctx context.Context) {
			By("Creating NodeSBOMs for both nodes")
			amd64SBOM := &storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name: amd64Node.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{
					Name:     amd64Node.Name,
					Platform: "linux/amd64",
				},
			}
			Expect(k8sClient.Create(ctx, amd64SBOM)).To(Succeed())

			arm64SBOM := &storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name: arm64Node.Name,
					Labels: map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{
					Name:     arm64Node.Name,
					Platform: "linux/arm64",
				},
			}
			Expect(k8sClient.Create(ctx, arm64SBOM)).To(Succeed())

			By("Creating a NodeScanConfiguration that only allows linux/amd64")
			config = v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Platforms: []v1alpha1.Platform{
						{OS: "linux", Architecture: "amd64"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &config)).To(Succeed())
			defer func() {
				Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
			}()

			By("Reconciling the NodeScanConfiguration")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the amd64 NodeSBOM still exists")
			remainingSBOM := &storagev1alpha1.NodeSBOM{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: amd64Node.Name,
			}, remainingSBOM)).To(Succeed())

			By("Verifying the arm64 NodeSBOM was deleted")
			deletedSBOM := &storagev1alpha1.NodeSBOM{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name: arm64Node.Name,
			}, deletedSBOM)
			Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
			Expect(deletedSBOM.Name).To(BeEmpty())
		})
	})
})
