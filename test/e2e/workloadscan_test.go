package e2e

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

const (
	workloadScanNamespace1 = "workloadscan-1"
	workloadScanNamespace2 = "workloadscan-2"
	deploymentName         = "ws-test"
	nginxImage             = "ghcr.io/kubewarden/sbomscanner/test-assets/nginx:1.27.1"
	golangImage            = "ghcr.io/kubewarden/sbomscanner/test-assets/golang:1.12-alpine"
	scanTimeout            = 10 * time.Minute
)

func TestWorkloadScan(t *testing.T) {
	f := features.New("Workload Scan").
		Assess("Create WorkloadScanConfiguration", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			workloadScanConfiguration := &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					Enabled:            true,
					ArtifactsNamespace: namespace,
					ScanOnChange:       true,
					Platforms: []v1alpha1.Platform{
						{Architecture: "amd64", OS: "linux"},
						{Architecture: "arm64", OS: "linux"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
						},
					},
				},
			}
			err := cfg.Client().Resources().Create(ctx, workloadScanConfiguration)
			require.NoError(t, err, "failed to create WorkloadScanConfiguration")

			return ctx
		}).
		Assess("Create workload scan namespaces", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			createWorkloadScanNamespace(ctx, t, cfg, workloadScanNamespace1)
			createWorkloadScanNamespace(ctx, t, cfg, workloadScanNamespace2)

			return ctx
		}).
		Assess("Create deployment in first namespace", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			createWorkloadScanDeployment(ctx, t, cfg, workloadScanNamespace1)

			return ctx
		}).
		Assess("Wait for WorkloadScanReport in first namespace to reach ScanComplete", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			report := waitForReportScanComplete(t, cfg, workloadScanNamespace1)

			// Verify the report structure
			assert.Len(t, report.Spec.Containers, 2, "expected 2 containers (init + nginx)")
			assert.Len(t, report.Status.ContainerStatuses, 2, "expected 2 container statuses")

			for _, s := range report.Status.ContainerStatuses {
				assert.Equal(t, storagev1alpha1.ScanStatusScanComplete, s.ScanStatus,
					"container %s should be ScanComplete", s.Name)
			}

			// Verify summary has vulnerabilities
			totalVulns := report.Summary.Critical + report.Summary.High + report.Summary.Medium + report.Summary.Low
			assert.Positive(t, totalVulns, "expected non-zero vulnerability count in summary")

			// Verify containers field has vulnerability reports with platform info
			assert.Len(t, report.Containers, 2, "expected 2 container results")
			for _, c := range report.Containers {
				assert.NotEmpty(t, c.VulnerabilityReports, "container %s should have vulnerability reports", c.Name)
				for _, vr := range c.VulnerabilityReports {
					assert.NotEmpty(t, vr.ImageMetadata.Platform, "vulnerability report should have platform set")
				}
			}

			return ctx
		}).
		Assess("Verify managed Registry exists in artifacts namespace", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			registries := &v1alpha1.RegistryList{}
			err := wait.For(
				conditions.New(cfg.Client().Resources(namespace)).ResourceListN(
					registries, 1,
					resources.WithLabelSelector(labels.FormatLabels(map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue})),
				),
				wait.WithTimeout(scanTimeout),
			)
			require.NoError(t, err, "expected at least 1 managed Registry in %s namespace", namespace)

			return ctx
		}).
		Assess("Create deployment in second namespace and verify report", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			createWorkloadScanDeployment(ctx, t, cfg, workloadScanNamespace2)

			report := waitForReportScanComplete(t, cfg, workloadScanNamespace2)

			assert.Len(t, report.Spec.Containers, 2, "expected 2 containers in second namespace report")

			for _, s := range report.Status.ContainerStatuses {
				assert.Equal(t, storagev1alpha1.ScanStatusScanComplete, s.ScanStatus,
					"container %s in second namespace should be ScanComplete", s.Name)
			}

			totalVulns := report.Summary.Critical + report.Summary.High + report.Summary.Medium + report.Summary.Low
			assert.Positive(t, totalVulns, "expected non-zero vulnerability count in second namespace summary")

			return ctx
		}).
		Assess("Disable configuration and verify cleanup", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			workloadScanConfiguration := &v1alpha1.WorkloadScanConfiguration{}
			err := cfg.Client().Resources().Get(ctx, v1alpha1.WorkloadScanConfigurationName, "", workloadScanConfiguration)
			require.NoError(t, err)

			workloadScanConfiguration.Spec.Enabled = false
			err = cfg.Client().Resources().Update(ctx, workloadScanConfiguration)
			require.NoError(t, err, "failed to disable WorkloadScanConfiguration")

			err = wait.For(func(ctx context.Context) (bool, error) {
				registries := &v1alpha1.RegistryList{}
				if err := cfg.Client().Resources(namespace).List(ctx, registries,
					resources.WithLabelSelector(labels.FormatLabels(map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue}))); err != nil {
					return false, err
				}
				return len(registries.Items) == 0, nil
			}, wait.WithTimeout(scanTimeout))
			require.NoError(t, err, "managed Registries should be cleaned up after disabling")

			for _, namespace := range []string{workloadScanNamespace1, workloadScanNamespace2} {
				err = wait.For(func(ctx context.Context) (bool, error) {
					reports := &storagev1alpha1.WorkloadScanReportList{}
					if err := cfg.Client().Resources(namespace).List(ctx, reports); err != nil {
						return false, err
					}
					return len(reports.Items) == 0, nil
				}, wait.WithTimeout(scanTimeout))
				require.NoError(t, err, "WorkloadScanReports should be cleaned up in %s after disabling", namespace)
			}

			return ctx
		}).
		Assess("Switch to multi-tenancy mode and re-enable", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			workloadScanConfiguration := &v1alpha1.WorkloadScanConfiguration{}
			err := cfg.Client().Resources().Get(ctx, v1alpha1.WorkloadScanConfigurationName, "", workloadScanConfiguration)
			require.NoError(t, err)

			workloadScanConfiguration.Spec.ArtifactsNamespace = ""
			workloadScanConfiguration.Spec.Enabled = true
			err = cfg.Client().Resources().Update(ctx, workloadScanConfiguration)
			require.NoError(t, err, "failed to switch to multi-tenancy mode")

			return ctx
		}).
		Assess("Verify per-namespace Registries in multi-tenancy mode", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// Wait for WorkloadScanReports to come back in both namespaces
			waitForReportScanComplete(t, cfg, workloadScanNamespace1)
			waitForReportScanComplete(t, cfg, workloadScanNamespace2)

			// Verify managed Registries exist in workload namespaces, not in artifacts namespace
			for _, namespace := range []string{workloadScanNamespace1, workloadScanNamespace2} {
				registries := &v1alpha1.RegistryList{}
				err := wait.For(
					conditions.New(cfg.Client().Resources(namespace)).ResourceListN(
						registries, 1,
						resources.WithLabelSelector(labels.FormatLabels(map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue})),
					),
					wait.WithTimeout(scanTimeout),
				)
				require.NoError(t, err, "expected managed Registry in %s namespace", namespace)
			}

			// Verify no managed Registries remain in the central namespace
			registries := &v1alpha1.RegistryList{}
			err := cfg.Client().Resources(namespace).List(ctx, registries,
				resources.WithLabelSelector(labels.FormatLabels(map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue})))
			require.NoError(t, err)
			assert.Empty(t, registries.Items, "no managed Registries should be in central namespace in multi-tenancy mode")

			return ctx
		}).
		Assess("Delete WorkloadScanConfiguration and verify full cleanup", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			workloadScanConfiguration := &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
			}
			err := cfg.Client().Resources().Delete(ctx, workloadScanConfiguration)
			require.NoError(t, err, "failed to delete WorkloadScanConfiguration")

			// Wait for all managed resources to be cleaned up
			for _, namespace := range []string{workloadScanNamespace1, workloadScanNamespace2} {
				// Wait for managed Registries cleanup
				err = wait.For(func(ctx context.Context) (bool, error) {
					registries := &v1alpha1.RegistryList{}
					if err := cfg.Client().Resources(namespace).List(ctx, registries,
						resources.WithLabelSelector(labels.FormatLabels(map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue}))); err != nil {
						return false, err
					}
					return len(registries.Items) == 0, nil
				}, wait.WithTimeout(scanTimeout))
				require.NoError(t, err, "managed Registries should be cleaned up in %s", namespace)

				// Wait for WorkloadScanReports cleanup
				err = wait.For(func(ctx context.Context) (bool, error) {
					reports := &storagev1alpha1.WorkloadScanReportList{}
					if err := cfg.Client().Resources(namespace).List(ctx, reports); err != nil {
						return false, err
					}
					return len(reports.Items) == 0, nil
				}, wait.WithTimeout(scanTimeout))
				require.NoError(t, err, "WorkloadScanReports should be cleaned up in %s", namespace)
			}

			return ctx
		}).
		Teardown(func(ctx context.Context, _ *testing.T, cfg *envconf.Config) context.Context {
			// Clean up namespaces
			for _, namespace := range []string{workloadScanNamespace1, workloadScanNamespace2} {
				nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
				_ = cfg.Client().Resources().Delete(ctx, nsObj)
			}
			return ctx
		})

	testenv.Test(t, f.Feature())
}

func createWorkloadScanNamespace(ctx context.Context, t *testing.T, cfg *envconf.Config, name string) {
	t.Helper()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
			},
		},
	}
	err := cfg.Client().Resources().Create(ctx, namespace)
	require.NoError(t, err, "failed to create namespace %s", name)
}

func createWorkloadScanDeployment(ctx context.Context, t *testing.T, cfg *envconf.Config, namespace string) {
	t.Helper()
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": deploymentName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": deploymentName},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:    "init",
							Image:   golangImage,
							Command: []string{"go", "version"},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: nginxImage,
						},
					},
				},
			},
		},
	}
	err := cfg.Client().Resources().Create(ctx, deployment)
	require.NoError(t, err, "failed to create deployment in %s", namespace)
}

// waitForReportScanComplete waits for a WorkloadScanReport to exist in the given namespace
// and for all containers to reach ScanComplete status.
func waitForReportScanComplete(t *testing.T, cfg *envconf.Config, namespace string) *storagev1alpha1.WorkloadScanReport {
	t.Helper()

	var found *storagev1alpha1.WorkloadScanReport
	err := wait.For(func(ctx context.Context) (bool, error) {
		reports := &storagev1alpha1.WorkloadScanReportList{}
		if err := cfg.Client().Resources(namespace).List(ctx, reports); err != nil {
			return false, err
		}

		for i := range reports.Items {
			r := &reports.Items[i]
			if len(r.Status.ContainerStatuses) == 0 {
				continue
			}

			statusNotComplete := slices.ContainsFunc(r.Status.ContainerStatuses, func(s storagev1alpha1.ContainerStatus) bool {
				return s.ScanStatus != storagev1alpha1.ScanStatusScanComplete
			})
			if statusNotComplete {
				continue
			}

			found = r
			return true, nil
		}

		return false, nil
	}, wait.WithTimeout(scanTimeout))
	require.NoError(t, err, "timeout waiting for a WorkloadScanReport in %s to reach ScanComplete", namespace)

	return found
}
