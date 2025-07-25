package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/rancher/sbombastic/api"
	storagev1alpha1 "github.com/rancher/sbombastic/api/storage/v1alpha1"
	v1alpha1 "github.com/rancher/sbombastic/api/v1alpha1"
)

func TestRegistryCreation(t *testing.T) {
	releaseName := "sbombastic"
	registryName := "test-registry"
	registryURI := "ghcr.io"
	registryRepository := "rancher-sandbox/sbombastic/test-assets/golang"
	chartPath := "../../charts/sbombastic"
	totalImages := 7 // Current number of images in the test-assets/golang directory

	labelSelector := labels.FormatLabels(
		map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
	)

	f := features.New("Scan a Registry").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunInstall(helm.WithName(releaseName),
				helm.WithNamespace(cfg.Namespace()),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithArgs("--set", "controller.image.tag=latest",
					"--set", "storage.image.tag=latest",
					"--set", "worker.image.tag=latest",
					"--set", "controller.logLevel=debug",
					// TODO:: Uncomment when storage log level is supported
					// "--set", "storage.logLevel=debug",
					"--set", "worker.logLevel=debug",
				),
				helm.WithTimeout("5m"))

			require.NoError(t, err, "sbombastic helm chart is not installed correctly")

			err = storagev1alpha1.AddToScheme(cfg.Client().Resources(cfg.Namespace()).GetScheme())
			require.NoError(t, err)

			err = v1alpha1.AddToScheme(cfg.Client().Resources(cfg.Namespace()).GetScheme())
			require.NoError(t, err)

			return ctx
		}).
		Assess("Create a Registry", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			registry := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      registryName,
					Namespace: cfg.Namespace(),
				},
				Spec: v1alpha1.RegistrySpec{
					URI:          registryURI,
					Repositories: []string{registryRepository},
				},
			}
			err := cfg.Client().Resources().Create(ctx, registry)
			require.NoError(t, err)
			return ctx
		}).
		Assess("Create a ScanJob", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			scanJob := &v1alpha1.ScanJob{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-scanjob",
					Namespace: cfg.Namespace(),
				},
				Spec: v1alpha1.ScanJobSpec{
					Registry: registryName,
				},
			}
			err := cfg.Client().Resources().Create(ctx, scanJob)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Wait for the ScanJob to complete", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			scanJob := &v1alpha1.ScanJob{ObjectMeta: metav1.ObjectMeta{Name: "test-scanjob", Namespace: cfg.Namespace()}}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(scanJob, func(object k8s.Object) bool {
				s := object.(*v1alpha1.ScanJob)
				return s.IsComplete()
			}))
			require.NoError(t, err, "Timeout waiting for ScanJob to complete")

			return ctx
		}).
		Assess("Verify the Image is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			images := storagev1alpha1.ImageList{}
			err := wait.For(conditions.New(cfg.Client().Resources(cfg.Namespace())).ResourceListN(
				&images,
				totalImages,
				resources.WithLabelSelector(labelSelector)),
			)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Verify the SPDX SBOM is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			sboms := storagev1alpha1.SBOMList{}
			err := wait.For(conditions.New(cfg.Client().Resources(cfg.Namespace())).ResourceListN(
				&sboms,
				totalImages,
				resources.WithLabelSelector(labelSelector)),
			)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Verify the VulnerabilityReport is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			vulnReports := storagev1alpha1.VulnerabilityReportList{}
			err := wait.For(conditions.New(cfg.Client().Resources(cfg.Namespace())).ResourceListN(
				&vulnReports,
				totalImages,
				resources.WithLabelSelector(labelSelector)),
			)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Verify the OwnerReference deletion", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Get all the VulnerabilityReport/Image/SBOM associated with the Registry
			images := storagev1alpha1.ImageList{}
			err := wait.For(conditions.New(cfg.Client().Resources()).ResourceListN(
				&images,
				totalImages,
				resources.WithLabelSelector(labelSelector),
			))
			require.NoError(t, err)

			sboms := storagev1alpha1.SBOMList{}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceListN(
				&sboms,
				totalImages,
				resources.WithLabelSelector(labelSelector)),
			)
			require.NoError(t, err)

			vulnReports := storagev1alpha1.VulnerabilityReportList{}
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceListN(
				&vulnReports,
				totalImages,
				resources.WithLabelSelector(labelSelector)),
			)
			require.NoError(t, err)

			// Delete the Registry CR
			registry := &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{Name: registryName, Namespace: cfg.Namespace()},
			}
			err = cfg.Client().Resources().Delete(ctx, registry)
			require.NoError(t, err)

			// Wait for the deletion, with order: VulnerabilityReport/Image/SBOM/Registry
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourcesDeleted(&vulnReports))
			require.NoError(t, err)
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourcesDeleted(&sboms))
			require.NoError(t, err)
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourcesDeleted(&images))
			require.NoError(t, err)
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(registry))
			require.NoError(t, err)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunUninstall(
				helm.WithName(releaseName),
				helm.WithNamespace(cfg.Namespace()),
			)
			assert.NoError(t, err, "sbombastic helm chart is not deleted correctly")
			return ctx
		})

	testenv.Test(t, f.Feature())
}
