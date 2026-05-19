package controller

import (
	"context"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

var _ = Describe("ImageWorkloadScan Controller", func() {
	var cancel context.CancelFunc
	var mgrClient client.Client

	BeforeEach(func() {
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: k8sClient.Scheme(),
			Controller: config.Controller{
				SkipNameValidation: new(true),
			},
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
			HealthProbeBindAddress: "0",
		})
		Expect(err).ToNot(HaveOccurred())

		err = SetupIndexer(ctx, mgr)
		Expect(err).ToNot(HaveOccurred())

		reconciler := ImageWorkloadScanReconciler{
			Client: mgr.GetClient(),
		}
		mgrClient = mgr.GetClient()

		err = reconciler.SetupWithManager(mgr)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			err = mgr.Start(ctx)
			Expect(err).ToNot(HaveOccurred())
		}()

		Expect(mgr.GetCache().WaitForCacheSync(ctx)).To(BeTrue())
	})

	AfterEach(func() {
		cancel()
	})

	When("an Image has no matching WorkloadScanReports", func() {
		It("should not add any workload scans to status", func(ctx context.Context) {
			repo := uuid.NewString()
			image := testImageFactory(ctx, repo, "latest")

			Consistently(func() []storagev1alpha1.ImageWorkloadScanReports {
				updated := &storagev1alpha1.Image{}
				err := k8sClient.Get(ctx, client.ObjectKeyFromObject(image), updated)
				if err != nil {
					return nil
				}
				return updated.Status.WorkloadScanReports
			}, "3s").Should(BeEmpty())
		})
	})

	When("a WorkloadScanReport references an Image", func() {
		It("should add workload scan to the Image status", func(ctx context.Context) {
			repo := uuid.NewString()
			image := testImageFactory(ctx, repo, "latest")

			workload := testWorkloadScanReportFactory(ctx, "my-deploy", []storagev1alpha1.ContainerRef{
				{
					Name: "web",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "docker.io",
						Namespace:  "default",
						Repository: repo,
						Tag:        "latest",
					},
				},
			})

			Eventually(func(g Gomega) {
				updated := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(image), updated)).To(Succeed())

				g.Expect(updated.Status.WorkloadScanReports).To(HaveLen(1))
				g.Expect(updated.Status.WorkloadScanReports[0].Name).To(Equal(workload.Name))
				g.Expect(updated.Status.WorkloadScanReports[0].Namespace).To(Equal("default"))
			}, "10s").Should(Succeed())
		})
	})

	When("a WorkloadScanReport is deleted", func() {
		It("should remove the workload scan from the Image status", func(ctx context.Context) {
			repo := uuid.NewString()
			image := testImageFactory(ctx, repo, "latest")

			workload := testWorkloadScanReportFactory(ctx, "my-deploy", []storagev1alpha1.ContainerRef{
				{
					Name: "web",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "docker.io",
						Namespace:  "default",
						Repository: repo,
						Tag:        "latest",
					},
				},
			})

			By("waiting for workload scan to appear in status")
			Eventually(func(g Gomega) {
				updated := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(image), updated)).To(Succeed())
				g.Expect(updated.Status.WorkloadScanReports).To(ContainElement(storagev1alpha1.ImageWorkloadScanReports{
					Name:      workload.Name,
					Namespace: "default",
				}))
			}, "10s").Should(Succeed())

			By("deleting the WorkloadScanReport")
			Expect(k8sClient.Delete(ctx, workload)).To(Succeed())

			By("waiting for workload scan to be removed from status")
			Eventually(func(g Gomega) {
				updated := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(image), updated)).To(Succeed())
				g.Expect(updated.Status.WorkloadScanReports).To(BeEmpty())
			}, "10s").Should(Succeed())
		})
	})

	When("multiple WorkloadScanReports reference the same Image", func() {
		It("should add status entries for each workload", func(ctx context.Context) {
			repo := uuid.NewString()
			image := testImageFactory(ctx, repo, "latest")

			imageRef := storagev1alpha1.ImageRef{
				Registry:   "docker.io",
				Namespace:  "default",
				Repository: repo,
				Tag:        "latest",
			}

			workload1 := testWorkloadScanReportFactory(ctx, "deploy-a", []storagev1alpha1.ContainerRef{
				{Name: "web", ImageRef: imageRef},
			})
			workload2 := testWorkloadScanReportFactory(ctx, "deploy-b", []storagev1alpha1.ContainerRef{
				{Name: "web", ImageRef: imageRef},
			})

			Eventually(func(g Gomega) {
				updated := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(image), updated)).To(Succeed())

				g.Expect(updated.Status.WorkloadScanReports).To(HaveLen(2))
				g.Expect(updated.Status.WorkloadScanReports).To(ContainElement(storagev1alpha1.ImageWorkloadScanReports{
					Name:      workload1.Name,
					Namespace: "default",
				}))
				g.Expect(updated.Status.WorkloadScanReports).To(ContainElement(storagev1alpha1.ImageWorkloadScanReports{
					Name:      workload2.Name,
					Namespace: "default",
				}))
			}, "10s").Should(Succeed())
		})
	})

	When("an Image is reconciled that does not exist", func() {
		It("should return without error", func(ctx context.Context) {
			reconciler := ImageWorkloadScanReconciler{
				Client: mgrClient,
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})
	})

	When("a WorkloadScanReport has multiple containers referencing different Images", func() {
		It("should update status on each referenced Image", func(ctx context.Context) {
			repoNginx := uuid.NewString()
			repoRedis := uuid.NewString()
			imageNginx := testImageFactory(ctx, repoNginx, "latest")
			imageRedis := testImageFactory(ctx, repoRedis, "7")

			workload := testWorkloadScanReportFactory(ctx, "multi-container", []storagev1alpha1.ContainerRef{
				{
					Name: "nginx",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "docker.io",
						Namespace:  "default",
						Repository: repoNginx,
						Tag:        "latest",
					},
				},
				{
					Name: "redis",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "docker.io",
						Namespace:  "default",
						Repository: repoRedis,
						Tag:        "7",
					},
				},
			})

			Eventually(func(g Gomega) {
				updatedNginx := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(imageNginx), updatedNginx)).To(Succeed())
				g.Expect(updatedNginx.Status.WorkloadScanReports).To(ContainElement(storagev1alpha1.ImageWorkloadScanReports{
					Name:      workload.Name,
					Namespace: "default",
				}))

				updatedRedis := &storagev1alpha1.Image{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(imageRedis), updatedRedis)).To(Succeed())
				g.Expect(updatedRedis.Status.WorkloadScanReports).To(ContainElement(storagev1alpha1.ImageWorkloadScanReports{
					Name:      workload.Name,
					Namespace: "default",
				}))
			}, "10s").Should(Succeed())
		})
	})
})

func testImageFactory(ctx context.Context, repository, tag string) *storagev1alpha1.Image {
	image := &storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "image-" + uuid.NewString(),
			Namespace: "default",
			Labels: map[string]string{
				api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
			},
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:   "docker.io",
			Repository: repository,
			Tag:        tag,
		},
	}
	ExpectWithOffset(1, k8sClient.Create(ctx, image)).To(Succeed())
	return image
}

func testWorkloadScanReportFactory(ctx context.Context, name string, containers []storagev1alpha1.ContainerRef) *storagev1alpha1.WorkloadScanReport {
	workload := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-" + uuid.NewString(),
			Namespace: "default",
		},
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: containers,
		},
	}
	ExpectWithOffset(1, k8sClient.Create(ctx, workload)).To(Succeed())
	return workload
}
