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

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestNodeScan(t *testing.T) {
	nodeScanLabelSelector := labels.FormatLabels(map[string]string{
		api.LabelManagedByKey: api.LabelManagedByValue,
	})

	f := features.New("Node Scan").
		Assess("Create NodeScanConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanConfig := &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
					Annotations: map[string]string{
						"sbomscanner.kubewarden.io/node-rescan-requested": "true",
					},
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Enabled: true,
					SkipPatterns: []string{
						// Exclude containerd runtime files since they
						// can cause issues with file access and are not
						// relevant for node SBOM generation.
						"/run/containerd/",
					},
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
						{Architecture: "arm64", OS: "linux"},
					},
				},
			}
			err := cfg.Client().Resources().Create(ctx, nodeScanConfig)
			require.NoError(t, err, "failed to create NodeScanConfiguration")

			return ctx
		}).
		Assess("Wait for NodeScanJob to be created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanJobs := &v1alpha1.NodeScanJobList{}
			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceListN(
					nodeScanJobs, 1,
				),
				wait.WithTimeout(scanTimeout),
			)
			require.NoError(t, err, "expected at least 1 NodeScanJob to be created")

			return ctx
		}).
		Assess("Wait for NodeScanJob to complete", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanJobs := &v1alpha1.NodeScanJobList{}
			err := wait.For(func(ctx context.Context) (bool, error) {
				if err := cfg.Client().Resources().List(ctx, nodeScanJobs,
					resources.WithTimeout(scanTimeout)); err != nil {
					return false, err
				}

				if len(nodeScanJobs.Items) == 0 {
					return false, nil
				}

				for i := range nodeScanJobs.Items {
					if !nodeScanJobs.Items[i].IsComplete() {
						return false, nil
					}
				}
				return true, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "timeout waiting for NodeScanJobs to complete")

			for _, job := range nodeScanJobs.Items {
				assert.NotNil(t, job.Status.CompletionTime, "NodeScanJob %s should have a CompletionTime", job.Name)
			}

			return ctx
		}).
		Assess("Verify NodeSBOM is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeSBOMs := &storagev1alpha1.NodeSBOMList{}
			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceListN(
					nodeSBOMs, 1,
					resources.WithLabelSelector(labels.FormatLabels(map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					})),
				),
				wait.WithTimeout(scanTimeout),
			)
			require.NoError(t, err, "expected at least 1 NodeSBOM to be created")

			for _, sbom := range nodeSBOMs.Items {
				assert.NotEmpty(t, sbom.NodeMetadata.Name, "NodeSBOM should have a node name")
				assert.NotEmpty(t, sbom.NodeMetadata.Platform, "NodeSBOM should have a platform")
				assert.NotEmpty(t, sbom.SPDX.Raw, "NodeSBOM should have SPDX data")
			}

			return ctx
		}).
		Assess("Verify NodeVulnerabilityReport is created", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeVulnReports := &storagev1alpha1.NodeVulnerabilityReportList{}
			err := wait.For(
				conditions.New(cfg.Client().Resources()).ResourceListN(
					nodeVulnReports, 1,
					resources.WithLabelSelector(labels.FormatLabels(map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					})),
				),
				wait.WithTimeout(scanTimeout),
			)
			require.NoError(t, err, "expected at least 1 NodeVulnerabilityReport to be created")

			for _, report := range nodeVulnReports.Items {
				assert.NotEmpty(t, report.NodeMetadata.Name, "NodeVulnerabilityReport should have a node name")
				assert.NotEmpty(t, report.NodeMetadata.Platform, "NodeVulnerabilityReport should have a platform")
			}

			return ctx
		}).
		Assess("Disable NodeScanConfiguration and verify cleanup", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanConfig := &v1alpha1.NodeScanConfiguration{}
			err := cfg.Client().Resources().Get(ctx, v1alpha1.NodeScanConfigurationName, "", nodeScanConfig)
			require.NoError(t, err)

			nodeScanConfig.Spec.Enabled = false
			err = cfg.Client().Resources().Update(ctx, nodeScanConfig)
			require.NoError(t, err, "failed to disable NodeScanConfiguration")

			err = wait.For(func(ctx context.Context) (bool, error) {
				jobs := &v1alpha1.NodeScanJobList{}
				if err := cfg.Client().Resources().List(ctx, jobs,
					resources.WithLabelSelector(nodeScanLabelSelector),
				); err != nil {
					return false, err
				}
				return len(jobs.Items) == 0, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "NodeScanJobs should be cleaned up after disabling NodeScanConfiguration")

			err = wait.For(func(ctx context.Context) (bool, error) {
				sboms := &storagev1alpha1.NodeSBOMList{}
				if err := cfg.Client().Resources().List(ctx, sboms,
					resources.WithLabelSelector(nodeScanLabelSelector),
				); err != nil {
					return false, err
				}
				return len(sboms.Items) == 0, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "NodeSBOMs should be cleaned up after disabling NodeScanConfiguration")

			return ctx
		}).
		Assess("Delete NodeScanConfiguration and verify cleanup", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanConfig := &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			}
			err := cfg.Client().Resources().Delete(ctx, nodeScanConfig)
			require.NoError(t, err, "failed to delete NodeScanConfiguration")

			err = wait.For(func(ctx context.Context) (bool, error) {
				jobs := &v1alpha1.NodeScanJobList{}
				if err := cfg.Client().Resources().List(ctx, jobs,
					resources.WithLabelSelector(nodeScanLabelSelector),
				); err != nil {
					return false, err
				}
				return len(jobs.Items) == 0, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "NodeScanJobs should be cleaned up after deleting NodeScanConfiguration")

			err = wait.For(func(ctx context.Context) (bool, error) {
				sboms := &storagev1alpha1.NodeSBOMList{}
				if err := cfg.Client().Resources().List(ctx, sboms,
					resources.WithLabelSelector(labels.FormatLabels(map[string]string{
						api.LabelManagedByKey: api.LabelManagedByValue,
					}))); err != nil {
					return false, err
				}
				return len(sboms.Items) == 0, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "NodeSBOMs should be cleaned up after deleting NodeScanConfiguration")

			return ctx
		}).
		Assess("Recreate NodeScanConfiguration with NodeSelector and verify filtering", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			nodeScanConfig := &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
				Spec: v1alpha1.NodeScanConfigurationSpec{
					Enabled: true,
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"non-existent-label": "no-match",
						},
					},
				},
			}
			err := cfg.Client().Resources().Create(ctx, nodeScanConfig)
			require.NoError(t, err, "failed to create NodeScanConfiguration with NodeSelector")

			err = wait.For(conditions.New(cfg.Client().Resources()).ResourceMatch(nodeScanConfig, func(object k8s.Object) bool {
				return object.(*v1alpha1.NodeScanConfiguration) != nil
			}), wait.WithTimeout(scanTimeout))
			require.NoError(t, err)

			// No NodeScanJobs should be created since no nodes match the selector
			jobs := &v1alpha1.NodeScanJobList{}
			err = cfg.Client().Resources().List(ctx, jobs,
				resources.WithLabelSelector(nodeScanLabelSelector),
			)
			require.NoError(t, err)
			assert.Empty(t, jobs.Items, "no NodeScanJobs should exist when NodeSelector matches no nodes")

			return ctx
		}).
		Assess("Final cleanup", func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			nodeScanConfig := &v1alpha1.NodeScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.NodeScanConfigurationName,
				},
			}
			_ = cfg.Client().Resources().Delete(ctx, nodeScanConfig)

			return ctx
		})

	testenv.Test(t, f.Feature())
}
