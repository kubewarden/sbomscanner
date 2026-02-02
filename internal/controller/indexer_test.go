package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/fields"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

var _ = Describe("SetupIndexer", func() {
	It("should setup all required indexes", func(ctx context.Context) {
		By("Creating a new manager")
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: k8sClient.Scheme(),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Setting up the indexer")
		err = SetupIndexer(ctx, mgr)
		Expect(err).NotTo(HaveOccurred())

		By("Starting the manager")
		go func() {
			defer GinkgoRecover()
			err = mgr.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		}()

		By("Waiting for the cache to sync")
		Eventually(func() bool {
			return mgr.GetCache().WaitForCacheSync(ctx)
		}).Should(BeTrue())

		// Verify indexes are working by attempting to list with them
		// This will fail if the indexes weren't properly set up
		By("Listing ScanJobs by registry and UID indexes")
		var scanJobList v1alpha1.ScanJobList
		err = mgr.GetClient().List(ctx, &scanJobList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				v1alpha1.IndexScanJobSpecRegistry: "test-registry",
			}),
		})
		Expect(err).NotTo(HaveOccurred())

		By("Listing ScanJobs by UID index")
		err = mgr.GetClient().List(ctx, &scanJobList, &client.ListOptions{
			FieldSelector: fields.SelectorFromSet(fields.Set{
				v1alpha1.IndexScanJobMetadataUID: "test-uid",
			}),
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
