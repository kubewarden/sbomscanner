package storage

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			Name:      "test",
			Namespace: "default",
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
			Name:      "test",
			Namespace: "default",
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
			Name:      "test",
			Namespace: "default",
			Summary: storagev1alpha1.Summary{
				Critical: 1,
			},
		},
		expectedErrors: []string{"summary"},
	},
	{
		name: "containers field is not empty",
		report: &storagev1alpha1.WorkloadScanReport{
			Name:      "test",
			Namespace: "default",
			Containers: []storagev1alpha1.ContainerResult{
				{Name: "app"},
			},
		},
		expectedErrors: []string{"containers"},
	},
	{
		name: "multiple read-only fields set",
		report: &storagev1alpha1.WorkloadScanReport{
			Name:      "test",
			Namespace: "default",
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
		Name:      "test",
		Namespace: "default",
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

// newStoredWorkloadScanReport returns a report as the storage reads it:
// status, summary and containers are filled.
func newStoredWorkloadScanReport() *storagev1alpha1.WorkloadScanReport {
	return &storagev1alpha1.WorkloadScanReport{
		Name:      "test",
		Namespace: "default",
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: []storagev1alpha1.ContainerRef{
				{
					Name: "app",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "my-registry",
						Namespace:  "default",
						Repository: "library/app",
						Tag:        "v1.0.0",
					},
				},
				{
					Name: "sidecar",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "my-registry",
						Namespace:  "default",
						Repository: "library/sidecar",
						Tag:        "v1.0.0",
					},
				},
			},
		},
		Status: storagev1alpha1.WorkloadScanReportStatus{
			ContainerStatuses: []storagev1alpha1.ContainerStatus{
				{Name: "app", ScanStatus: storagev1alpha1.ScanStatusScanComplete},
				{Name: "sidecar", ScanStatus: storagev1alpha1.ScanStatusWaitingForScan},
			},
		},
		Summary: storagev1alpha1.Summary{
			Critical: 1,
		},
		Containers: []storagev1alpha1.ContainerResult{
			{
				Name: "app",
				VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
					{
						Name:      "app-report",
						Namespace: "default",
						ImageMetadata: storagev1alpha1.ImageMetadata{
							Registry:    "my-registry",
							RegistryURI: "registry.example.com",
							Repository:  "library/app",
							Tag:         "v1.0.0",
							Platform:    "linux/amd64",
							Digest:      "sha256:0000000000000000000000000000000000000000000000000000000000000001",
						},
						Report: storagev1alpha1.Report{
							Summary: storagev1alpha1.Summary{
								Critical: 1,
							},
							Results: []storagev1alpha1.Result{
								{
									Target: "app",
									Class:  storagev1alpha1.ClassOSPackages,
									Type:   "debian",
									Vulnerabilities: []storagev1alpha1.Vulnerability{
										{
											CVE:              "CVE-2026-0001",
											PURL:             "pkg:deb/debian/openssl@3.0.0",
											InstalledVersion: "3.0.0",
											DiffID:           "sha256:0000000000000000000000000000000000000000000000000000000000000002",
											Severity:         storagev1alpha1.SeverityCritical,
											CVSS: map[string]storagev1alpha1.CVSS{
												"nvd": {
													V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
													V3Score:  "9.8",
												},
											},
											VEXStatus: &storagev1alpha1.VEXStatus{
												Repository: "https://vex.example.com",
												Status:     "under_investigation",
												Statement:  "The vendor examines the vulnerability.",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Name: "sidecar",
				// The list is empty and not nil,
				// as buildContainerResult builds it for a container without vulnerability reports.
				VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{},
			},
		},
	}
}

// decodeFromJSON encodes the report to JSON and decodes it into a new report.
// The result has the shape of the object that the API server passes to the validation.
func decodeFromJSON(t *testing.T, report *storagev1alpha1.WorkloadScanReport) *storagev1alpha1.WorkloadScanReport {
	t.Helper()

	data, err := json.Marshal(report)
	require.NoError(t, err)

	decoded := &storagev1alpha1.WorkloadScanReport{}
	require.NoError(t, json.Unmarshal(data, decoded))

	return decoded
}

func TestWorkloadScanReportStrategy_ValidateUpdateStoredReport(t *testing.T) {
	strategy := newWorkloadScanReportStrategy(nil)

	tests := []struct {
		name           string
		mutate         func(report *storagev1alpha1.WorkloadScanReport)
		expectedErrors []string
	}{
		{
			name: "spec change with a container without vulnerability reports",
			mutate: func(report *storagev1alpha1.WorkloadScanReport) {
				report.Spec.Containers[1].ImageRef.Tag = "v2.0.0"
			},
			expectedErrors: nil,
		},
		{
			name: "status changed",
			mutate: func(report *storagev1alpha1.WorkloadScanReport) {
				report.Status.ContainerStatuses[1].ScanStatus = storagev1alpha1.ScanStatusScanComplete
			},
			expectedErrors: []string{"status"},
		},
		{
			name: "summary changed",
			mutate: func(report *storagev1alpha1.WorkloadScanReport) {
				report.Summary.Critical++
			},
			expectedErrors: []string{"summary"},
		},
		{
			name: "containers changed",
			mutate: func(report *storagev1alpha1.WorkloadScanReport) {
				report.Containers[0].VulnerabilityReports = nil
			},
			expectedErrors: []string{"containers"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldReport := newStoredWorkloadScanReport()
			newReport := decodeFromJSON(t, oldReport)

			require.NotNil(t, oldReport.Containers[1].VulnerabilityReports)
			require.Empty(t, oldReport.Containers[1].VulnerabilityReports)
			require.Nil(t, newReport.Containers[1].VulnerabilityReports)

			test.mutate(newReport)

			errs := strategy.ValidateUpdate(context.Background(), newReport, oldReport)

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
