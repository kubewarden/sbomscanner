package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

var workloadScanReportValidationTests = []struct {
	name           string
	report         *storagev1alpha1.WorkloadScanReport
	expectedErrors []string
}{
	{
		name: "valid report with empty read-only fields",
		report: &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Spec: storagev1alpha1.WorkloadScanReportSpec{
				Containers: []storagev1alpha1.ContainerRef{
					{Name: "app", ImageRef: storagev1alpha1.ImageRef{Registry: "docker.io"}},
				},
			},
		},
		expectedErrors: nil,
	},
	{
		name: "status field is not empty",
		report: &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: storagev1alpha1.WorkloadScanReportStatus{
				ContainerStatuses: []storagev1alpha1.ContainerStatus{
					{Name: "app", ScanStatus: storagev1alpha1.ScanStatusScanComplete},
				},
			},
		},
		expectedErrors: []string{"status"},
	},
	{
		name: "summary field is not empty",
		report: &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Summary: storagev1alpha1.Summary{
				Critical: 1,
			},
		},
		expectedErrors: []string{"summary"},
	},
	{
		name: "containers field is not empty",
		report: &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Containers: []storagev1alpha1.ContainerResult{
				{Name: "app"},
			},
		},
		expectedErrors: []string{"containers"},
	},
	{
		name: "multiple read-only fields set",
		report: &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: storagev1alpha1.WorkloadScanReportStatus{
				ContainerStatuses: []storagev1alpha1.ContainerStatus{
					{Name: "app"},
				},
			},
			Summary: storagev1alpha1.Summary{
				High: 5,
			},
			Containers: []storagev1alpha1.ContainerResult{
				{Name: "app"},
			},
		},
		expectedErrors: []string{"status", "summary", "containers"},
	},
}

func TestWorkloadScanReportStrategy_Validate(t *testing.T) {
	strategy := newWorkloadScanReportStrategy(nil)

	for _, test := range workloadScanReportValidationTests {
		t.Run(test.name, func(t *testing.T) {
			errs := strategy.Validate(context.Background(), test.report)

			if test.expectedErrors == nil {
				assert.Empty(t, errs)
				return
			}

			assert.Len(t, errs, len(test.expectedErrors))
			for i, expectedField := range test.expectedErrors {
				assert.Equal(t, expectedField, errs[i].Field)
			}
		})
	}
}

func TestWorkloadScanReportStrategy_ValidateUpdate(t *testing.T) {
	strategy := newWorkloadScanReportStrategy(nil)

	baseReport := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	for _, test := range workloadScanReportValidationTests {
		t.Run(test.name, func(t *testing.T) {
			errs := strategy.ValidateUpdate(context.Background(), test.report, baseReport)

			if test.expectedErrors == nil {
				assert.Empty(t, errs)
				return
			}

			assert.Len(t, errs, len(test.expectedErrors))
			for i, expectedField := range test.expectedErrors {
				assert.Equal(t, expectedField, errs[i].Field)
			}
		})
	}
}
