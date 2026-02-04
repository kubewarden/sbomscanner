package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

func TestTransformStripImage(t *testing.T) {
	image := &storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{Name: "test-image"},
		Layers:     []storagev1alpha1.ImageLayer{{Digest: "sha256:abc"}},
	}

	result, err := TransformStripImage(image)
	require.NoError(t, err)

	resultImage := result.(*storagev1alpha1.Image)
	assert.Nil(t, resultImage.Layers)
	assert.Equal(t, "test-image", resultImage.Name)
}

func TestTransformStripSBOM(t *testing.T) {
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{Name: "test-sbom"},
		SPDX:       runtime.RawExtension{Raw: []byte(`{"test": "data"}`)},
	}

	result, err := TransformStripSBOM(sbom)
	require.NoError(t, err)

	resultSBOM := result.(*storagev1alpha1.SBOM)
	assert.Empty(t, resultSBOM.SPDX.Raw)
	assert.Equal(t, "test-sbom", resultSBOM.Name)
}

func TestTransformStripVulnerabilityReport(t *testing.T) {
	vuln := &storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{Name: "test-vuln"},
		Report: storagev1alpha1.Report{
			Results: []storagev1alpha1.Result{{Target: "test-target"}},
		},
	}

	result, err := TransformStripVulnerabilityReport(vuln)
	require.NoError(t, err)

	resultVuln := result.(*storagev1alpha1.VulnerabilityReport)
	assert.Nil(t, resultVuln.Report.Results)
	assert.Equal(t, "test-vuln", resultVuln.Name)
}

func TestTransformStripWorkloadScanReport(t *testing.T) {
	report := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "test-workloadscanreport"},
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: []storagev1alpha1.ContainerRef{
				{
					Name: "my-container",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "my-registry",
						Namespace:  "default",
						Repository: "nginx",
						Tag:        "latest",
					},
				},
			},
		},
		Status: storagev1alpha1.WorkloadScanReportStatus{
			ContainerStatuses: []storagev1alpha1.ContainerStatus{
				{
					Name:       "my-container",
					ScanStatus: storagev1alpha1.ScanStatusScanComplete,
				},
			},
		},
		Summary: storagev1alpha1.Summary{
			Critical: 1,
			High:     2,
		},
		Containers: []storagev1alpha1.ContainerResult{
			{
				Name: "my-container",
			},
		},
	}

	result, err := TransformStripWorkloadScanReport(report)
	require.NoError(t, err)

	resultReport := result.(*storagev1alpha1.WorkloadScanReport)
	assert.Empty(t, resultReport.Status.ContainerStatuses)
	assert.NotEmpty(t, resultReport.Summary)
	assert.Nil(t, resultReport.Containers)
	assert.Equal(t, "test-workloadscanreport", resultReport.Name)
	// Spec should be preserved
	assert.Len(t, resultReport.Spec.Containers, 1)
	assert.Equal(t, "my-container", resultReport.Spec.Containers[0].Name)
}
