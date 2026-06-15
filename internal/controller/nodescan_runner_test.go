package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("NodeScanRunner", func() {
	Describe("scanNodes", func() {
		var (
			runner *NodeScanRunner
			config *v1alpha1.NodeScanConfiguration
			node   *corev1.Node
		)

		BeforeEach(func() {
			runner = &NodeScanRunner{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
		})

		When("A node needs scanning", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Node")
				node = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("node-%s", uuid.New().String()),
					},
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())

				By("Creating a NodeScanConfiguration with a scan interval of 1 hour")
				config = &v1alpha1.NodeScanConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: v1alpha1.NodeScanConfigurationName,
					},
					Spec: v1alpha1.NodeScanConfigurationSpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, config)).To(Succeed())
			})

			AfterEach(func(ctx context.Context) {
				Expect(k8sClient.Delete(ctx, config)).To(Succeed())
			})

			It("Should create a NodeScanJob for the node", func(ctx context.Context) {
				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying a NodeScanJob was created for the node")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(HaveLen(1))

				By("Checking the NodeScanJob has correct node name and trigger annotation")
				Expect(nodeScanJobs.Items[0].Spec.NodeName).To(Equal(node.Name))
				Expect(nodeScanJobs.Items[0].Annotations).To(HaveKeyWithValue(v1alpha1.AnnotationNodeScanJobTriggerKey, "runner"))
			})
		})

		When("Node platform is not allowed by the configuration", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Node with linux/arm64 platform")
				node = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("node-%s", uuid.New().String()),
					},
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())
				node.Status = corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OperatingSystem: "linux",
						Architecture:    "arm64",
					},
				}
				Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())

				By("Creating a NodeScanConfiguration that only allows linux/amd64")
				config = &v1alpha1.NodeScanConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: v1alpha1.NodeScanConfigurationName,
					},
					Spec: v1alpha1.NodeScanConfigurationSpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
						Platforms: []v1alpha1.Platform{
							{OS: "linux", Architecture: "amd64"},
						},
					},
				}
				Expect(k8sClient.Create(ctx, config)).To(Succeed())
			})

			AfterEach(func(ctx context.Context) {
				Expect(k8sClient.Delete(ctx, config)).To(Succeed())
			})

			It("Should not create a NodeScanJob for the node", func(ctx context.Context) {
				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying no NodeScanJobs were created for the node")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(BeEmpty())
			})
		})

		When("NodeScanConfiguration has the force-node-scan annotation", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Node")
				node = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("node-%s", uuid.New().String()),
					},
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())

				By("Creating a NodeScanConfiguration with the force-node-scan annotation")
				config = &v1alpha1.NodeScanConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: v1alpha1.NodeScanConfigurationName,
						Annotations: map[string]string{
							v1alpha1.AnnotationNodeRescanRequested: "true",
						},
					},
					Spec: v1alpha1.NodeScanConfigurationSpec{
						ScanInterval: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(k8sClient.Create(ctx, config)).To(Succeed())
			})

			AfterEach(func(ctx context.Context) {
				Expect(k8sClient.Delete(ctx, config)).To(Succeed())
			})

			It("Should create a NodeScanJob even if the timer has not expired and remove the annotation", func(ctx context.Context) {
				By("Creating a recently completed NodeScanJob within the scan interval")
				recentJob := &v1alpha1.NodeScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("recent-node-job-%s", uuid.New().String()),
					},
					Spec: v1alpha1.NodeScanJobSpec{
						NodeName: node.Name,
					},
				}
				Expect(k8sClient.Create(ctx, recentJob)).To(Succeed())
				recentJob.MarkComplete(v1alpha1.ReasonScanJobComplete, "Done")
				recentJob.Status.CompletionTime = &metav1.Time{Time: time.Now()}
				Expect(k8sClient.Status().Update(ctx, recentJob)).To(Succeed())

				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying a new NodeScanJob was created despite the timer not being expired")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(HaveLen(2))

				By("Verifying the force-node-scan annotation was removed")
				var updatedConfig v1alpha1.NodeScanConfiguration
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &updatedConfig)).To(Succeed())
				Expect(updatedConfig.Annotations).NotTo(HaveKey(v1alpha1.AnnotationNodeRescanRequested))
			})

			It("Should not create a NodeScanJob when one is already running", func(ctx context.Context) {
				By("Creating an existing running NodeScanJob for the node")
				existingJob := &v1alpha1.NodeScanJob{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("running-node-job-%s", uuid.New().String()),
					},
					Spec: v1alpha1.NodeScanJobSpec{
						NodeName: node.Name,
					},
				}
				Expect(k8sClient.Create(ctx, existingJob)).To(Succeed())

				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying no additional NodeScanJob was created")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(HaveLen(1))
			})
		})

		When("NodeScanConfiguration has the force-node-scan annotation but no scan interval", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Node")
				node = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("node-%s", uuid.New().String()),
					},
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())

				By("Creating a NodeScanConfiguration with force annotation and disabled interval")
				config = &v1alpha1.NodeScanConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: v1alpha1.NodeScanConfigurationName,
						Annotations: map[string]string{
							v1alpha1.AnnotationNodeRescanRequested: "true",
						},
					},
					Spec: v1alpha1.NodeScanConfigurationSpec{
						ScanInterval: &metav1.Duration{Duration: 0},
					},
				}
				Expect(k8sClient.Create(ctx, config)).To(Succeed())
			})

			AfterEach(func(ctx context.Context) {
				Expect(k8sClient.Delete(ctx, config)).To(Succeed())
			})

			It("Should create a NodeScanJob even with disabled interval", func(ctx context.Context) {
				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying a NodeScanJob was created due to force annotation")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(HaveLen(1))

				By("Verifying the force-node-scan annotation was removed")
				var updatedConfig v1alpha1.NodeScanConfiguration
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &updatedConfig)).To(Succeed())
				Expect(updatedConfig.Annotations).NotTo(HaveKey(v1alpha1.AnnotationNodeRescanRequested))
			})
		})

		When("NodeScanConfiguration has no scan interval", func() {
			BeforeEach(func(ctx context.Context) {
				By("Creating a Node")
				node = &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("node-%s", uuid.New().String()),
					},
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())

				By("Creating a NodeScanConfiguration with scan interval disabled (0 duration)")
				config = &v1alpha1.NodeScanConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: v1alpha1.NodeScanConfigurationName,
					},
					Spec: v1alpha1.NodeScanConfigurationSpec{
						ScanInterval: &metav1.Duration{Duration: 0},
					},
				}
				Expect(k8sClient.Create(ctx, config)).To(Succeed())
			})

			AfterEach(func(ctx context.Context) {
				Expect(k8sClient.Delete(ctx, config)).To(Succeed())
			})

			It("Should not create any NodeScanJob", func(ctx context.Context) {
				By("Running the node scanner")
				err := runner.scanNodes(ctx)
				Expect(err).To(Succeed())

				By("Verifying no NodeScanJobs were created for the node")
				nodeScanJobs := &v1alpha1.NodeScanJobList{}
				Expect(k8sClient.List(ctx, nodeScanJobs,
					client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: node.Name},
				)).To(Succeed())
				Expect(nodeScanJobs.Items).To(BeEmpty())
			})
		})
	})
})
