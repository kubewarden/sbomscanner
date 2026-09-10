package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// e2e tests share a single Kind cluster managed by TestMain and create
// cluster-wide resources, so they must run sequentially.
func TestRegistryScan(t *testing.T) {
	registryName := "test-registry"
	registryURI := "ghcr.io"
	registryRepository := "kubewarden/sbomscanner/test-assets/golang"
	totalImages := 7 // Current number of images in the test-assets/golang directory

	labelSelector := labels.FormatLabels(
		map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
	)

	f := features.New("Scan a Registry").
		Assess("Create a Registry", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			registry := &v1alpha1.Registry{
				Name:      registryName,
				Namespace: cfg.Namespace(),
				Spec: v1alpha1.RegistrySpec{
					URI: registryURI,
					Repositories: []v1alpha1.Repository{
						{
							Name: registryRepository,
						},
					},
				},
			}
			err := cfg.Client().Resources().Create(ctx, registry)
			require.NoError(t, err)
			return ctx
		}).
		Assess("Create a VEXHub", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			vexHub := &v1alpha1.VEXHub{
				Name: "kubewarden-vexhub",
				Spec: v1alpha1.VEXHubSpec{
					URL:     "https://github.com/rancher/vexhub",
					Enabled: true,
				},
			}
			err := cfg.Client().Resources().Create(ctx, vexHub)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Create a ScanJob", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			scanJob := &v1alpha1.ScanJob{
				Name:      "test-scanjob",
				Namespace: cfg.Namespace(),
				Spec: v1alpha1.ScanJobSpec{
					Registry: registryName,
				},
			}
			err := cfg.Client().Resources().Create(ctx, scanJob)
			require.NoError(t, err)

			return ctx
		}).
		Assess("Wait for the ScanJob to complete", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			scanJob := &v1alpha1.ScanJob{Name: "test-scanjob", Namespace: cfg.Namespace()}

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

			// The sbomscanner database test asset lists CVE-2021-3711 in KEV
			// and carries EPSS scores for the CVEs of the test images.
			sawKEV, sawEPSS := false, false
			for _, report := range vulnReports.Items {
				for _, result := range report.Report.Results {
					for _, vuln := range result.Vulnerabilities {
						sawEPSS = sawEPSS || vuln.EPSS != nil
						if vuln.CVE == "CVE-2021-3711" {
							require.NotNil(t, vuln.KEV, "CVE-2021-3711 should carry KEV data")
							assert.Equal(t, storagev1alpha1.RansomwareCampaignUseKnown, vuln.KEV.KnownRansomwareCampaignUse)
							sawKEV = true
						}
					}
				}
			}
			assert.True(t, sawKEV, "expected CVE-2021-3711 with KEV data in the vulnerability reports")
			assert.True(t, sawEPSS, "expected at least one vulnerability with EPSS data")

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
				Name: registryName, Namespace: cfg.Namespace(),
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
			// Verify the ScanJob is deleted
			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceDeleted(&v1alpha1.ScanJob{
				Name:      "test-scanjob",
				Namespace: cfg.Namespace(),
			}))
			require.NoError(t, err)

			return ctx
		})

	testenv.Test(t, f.Feature())
}
