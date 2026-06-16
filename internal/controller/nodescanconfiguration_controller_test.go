package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("NodeScanConfiguration Controller", func() {
	configRequest := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName},
	}

	When("the configuration is disabled", func() {
		var reconciler NodeScanConfigurationReconciler
		var configuration *v1alpha1.NodeScanConfiguration

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanConfigurationReconciler{Client: k8sClient}

			By("Creating a disabled NodeScanConfiguration")
			configuration = &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Enabled: false,
				},
			}
			Expect(k8sClient.Create(ctx, configuration)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			By("Deleting the NodeScanConfiguration")
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, configuration))).To(Succeed())
		})

		It("should cleanup all NodeScanJobs and NodeSBOMs across the cluster", func(ctx context.Context) {
			By("Seeding NodeScanJobs and NodeSBOMs for two different nodes")
			nodeA := fmt.Sprintf("node-a-%s", uuid.New().String())
			nodeB := fmt.Sprintf("node-b-%s", uuid.New().String())

			jobA := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("nodescanjob-%s", nodeA)},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: nodeA},
			}
			jobB := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("nodescanjob-%s", nodeB)},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: nodeB},
			}
			Expect(k8sClient.Create(ctx, &jobA)).To(Succeed())
			Expect(k8sClient.Create(ctx, &jobB)).To(Succeed())

			sbomA := storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:   nodeA,
					Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{Name: nodeA, Platform: "linux/amd64"},
				SPDX:         runtime.RawExtension{Raw: []byte("{}")},
			}
			sbomB := storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:   nodeB,
					Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{Name: nodeB, Platform: "linux/amd64"},
				SPDX:         runtime.RawExtension{Raw: []byte("{}")},
			}
			Expect(k8sClient.Create(ctx, &sbomA)).To(Succeed())
			Expect(k8sClient.Create(ctx, &sbomB)).To(Succeed())

			By("Reconciling the disabled configuration")
			_, err := reconciler.Reconcile(ctx, configRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying all NodeScanJobs are gone")
			var jobs v1alpha1.NodeScanJobList
			Expect(k8sClient.List(ctx, &jobs)).To(Succeed())
			Expect(jobs.Items).To(BeEmpty())

			By("Verifying all NodeSBOMs are gone")
			var sboms storagev1alpha1.NodeSBOMList
			Expect(k8sClient.List(ctx, &sboms)).To(Succeed())
			Expect(sboms.Items).To(BeEmpty())
		})
	})

	When("the configuration does not exist", func() {
		var reconciler NodeScanConfigurationReconciler

		BeforeEach(func() {
			reconciler = NodeScanConfigurationReconciler{Client: k8sClient}
		})

		It("should cleanup all NodeScanJobs and NodeSBOMs across the cluster", func(ctx context.Context) {
			By("Seeding a NodeScanJob and a NodeSBOM")
			nodeName := fmt.Sprintf("node-%s", uuid.New().String())
			job := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("nodescanjob-%s", nodeName)},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: nodeName},
			}
			Expect(k8sClient.Create(ctx, &job)).To(Succeed())

			sbom := storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:   nodeName,
					Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{Name: nodeName, Platform: "linux/amd64"},
				SPDX:         runtime.RawExtension{Raw: []byte("{}")},
			}
			Expect(k8sClient.Create(ctx, &sbom)).To(Succeed())

			By("Reconciling the missing configuration")
			_, err := reconciler.Reconcile(ctx, configRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying all NodeScanJobs are gone")
			var jobs v1alpha1.NodeScanJobList
			Expect(k8sClient.List(ctx, &jobs)).To(Succeed())
			Expect(jobs.Items).To(BeEmpty())

			By("Verifying all NodeSBOMs are gone")
			var sboms storagev1alpha1.NodeSBOMList
			Expect(k8sClient.List(ctx, &sboms)).To(Succeed())
			Expect(sboms.Items).To(BeEmpty())
		})
	})

	When("the configuration is enabled", func() {
		var reconciler NodeScanConfigurationReconciler
		var configuration *v1alpha1.NodeScanConfiguration

		BeforeEach(func(ctx context.Context) {
			reconciler = NodeScanConfigurationReconciler{Client: k8sClient}

			By("Creating an enabled NodeScanConfiguration")
			configuration = &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Enabled: true,
				},
			}
			Expect(k8sClient.Create(ctx, configuration)).To(Succeed())
		})

		AfterEach(func(ctx context.Context) {
			By("Deleting the NodeScanConfiguration")
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, configuration))).To(Succeed())
		})

		It("should not delete any NodeScanJobs or NodeSBOMs", func(ctx context.Context) {
			By("Seeding a NodeScanJob and a NodeSBOM")
			nodeName := fmt.Sprintf("node-%s", uuid.New().String())
			job := v1alpha1.NodeScanJob{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("nodescanjob-%s", nodeName)},
				Spec:       v1alpha1.NodeScanJobSpec{NodeName: nodeName},
			}
			Expect(k8sClient.Create(ctx, &job)).To(Succeed())

			sbom := storagev1alpha1.NodeSBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:   nodeName,
					Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
				},
				NodeMetadata: storagev1alpha1.NodeMetadata{Name: nodeName, Platform: "linux/amd64"},
				SPDX:         runtime.RawExtension{Raw: []byte("{}")},
			}
			Expect(k8sClient.Create(ctx, &sbom)).To(Succeed())

			By("Reconciling the enabled configuration")
			_, err := reconciler.Reconcile(ctx, configRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the seeded NodeScanJob still exists")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: job.Name}, &v1alpha1.NodeScanJob{})).To(Succeed())

			By("Verifying the seeded NodeSBOM still exists")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: sbom.Name}, &storagev1alpha1.NodeSBOM{})).To(Succeed())

			By("Cleaning up the seeded resources")
			Expect(k8sClient.Delete(ctx, &job)).To(Succeed())
			Expect(k8sClient.Delete(ctx, &sbom)).To(Succeed())
		})
	})
})
