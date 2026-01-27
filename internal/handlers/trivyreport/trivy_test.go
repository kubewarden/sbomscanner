package trivyreport

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/stretchr/testify/require"
)

func TestNewResultsFromTrivyReport(t *testing.T) {
	tests := []struct {
		name             string
		trivyReport      string
		sbombasticReport []storagev1alpha1.Result
		wantErr          bool
	}{
		{
			name:        "1 vulnerability 1 suppressed",
			trivyReport: filepath.Join("..", "..", "..", "test", "fixtures", "vulnerabilityreport", "trivy.report-with-vex.json"),
			sbombasticReport: []storagev1alpha1.Result{
				{
					Target: "nginx-ingress-controller",
					Class:  "binary",
					Type:   "gobinary",
					Vulnerabilities: []storagev1alpha1.Vulnerability{
						{
							CVE:              "CVE-2024-45336",
							Title:            "Lorem ipsum",
							PackageName:      "stdlib",
							PURL:             "pkg:golang/stdlib@v1.23.4",
							InstalledVersion: "v1.23.4",
							FixedVersions: []string{
								"1.22.11",
								"1.23.5",
								"1.24.0-rc.2",
							},
							DiffID:      "sha256:d37a3e42d123ca619ceab4bbe3c1e9a96d0a837e5e0e3052b33dbd0e842c5661",
							Description: "Lorem ipsum",
							Severity:    "MEDIUM",
							References: []string{
								"https://access.redhat.com/errata/RHSA-2025:3772",
								"https://access.redhat.com/security/cve/CVE-2024-45336",
								"https://bugzilla.redhat.com/2341750",
							},
							CVSS: map[string]storagev1alpha1.CVSS{
								"bitnami": {
									V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
									V3Score:  "6.1",
								},
								"redhat": {
									V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
									V3Score:  "5.9",
								},
							},
							Suppressed: false,
						},
						{
							CVE:              "CVE-2025-22870",
							Title:            "Lorem ipsum",
							PackageName:      "golang.org/x/net",
							PURL:             "pkg:golang/golang.org/x/net@v0.33.0",
							InstalledVersion: "v0.33.0",
							FixedVersions: []string{
								"0.36.0",
							},
							DiffID:      "sha256:d37a3e42d123ca619ceab4bbe3c1e9a96d0a837e5e0e3052b33dbd0e842c5661",
							Description: "Lorem ipsum",
							Severity:    "MEDIUM",
							References: []string{
								"http://www.openwall.com/lists/oss-security/2025/03/07/2",
								"https://access.redhat.com/security/cve/CVE-2025-22870",
								"https://github.com/golang/go/issues/71984",
							},
							CVSS: map[string]storagev1alpha1.CVSS{
								"ghsa": {
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L",
									V3Score:  "4.4",
								},
								"redhat": {
									V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L",
									V3Score:  "4.4",
								},
							},
							CWEs: []string{
								"CWE-115",
							},
							Suppressed: true,
							VEXStatus: &storagev1alpha1.VEXStatus{
								Repository: "https://github.com/kubewarden/vexhub",
								Status:     "not_affected",
								Statement:  "vulnerable_code_not_present",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:        "3 vulnerabilities from 2 different targets",
			trivyReport: filepath.Join("..", "..", "..", "test", "fixtures", "vulnerabilityreport", "trivy.report-without-vex.json"),
			sbombasticReport: []storagev1alpha1.Result{
				{
					Target: "nginx-ingress-controller",
					Class:  "binary",
					Type:   "gobinary",
					Vulnerabilities: []storagev1alpha1.Vulnerability{
						{
							CVE:              "CVE-2024-45336",
							Title:            "Lorem ipsum",
							PackageName:      "stdlib",
							PURL:             "pkg:golang/stdlib@v1.23.4",
							InstalledVersion: "v1.23.4",
							FixedVersions: []string{
								"1.22.11",
								"1.23.5",
								"1.24.0-rc.2",
							},
							DiffID:      "sha256:d37a3e42d123ca619ceab4bbe3c1e9a96d0a837e5e0e3052b33dbd0e842c5661",
							Description: "Lorem ipsum",
							Severity:    "MEDIUM",
							References: []string{
								"https://access.redhat.com/errata/RHSA-2025:3772",
								"https://access.redhat.com/security/cve/CVE-2024-45336",
								"https://bugzilla.redhat.com/2341750",
							},
							CVSS: map[string]storagev1alpha1.CVSS{
								"bitnami": {
									V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
									V3Score:  "6.1",
								},
								"redhat": {
									V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
									V3Score:  "5.9",
								},
							},
							Suppressed: false,
						},
					},
				},
				{
					Target: "dbg",
					Class:  "binary",
					Type:   "gobinary",
					Vulnerabilities: []storagev1alpha1.Vulnerability{
						{
							CVE:              "CVE-2024-45336",
							Title:            "Lorem ipsum",
							PackageName:      "stdlib",
							PURL:             "pkg:golang/stdlib@v1.23.4",
							InstalledVersion: "v1.23.4",
							FixedVersions: []string{
								"1.22.11",
								"1.23.5",
								"1.24.0-rc.2",
							},
							DiffID:      "sha256:6d134d3d7e8aa630874f7c4e9db3db48d1895c60f3e5ce73272412404a9b723b",
							Description: "Lorem ipsum",
							Severity:    "MEDIUM",
							References: []string{
								"https://access.redhat.com/errata/RHSA-2025:3772",
								"https://access.redhat.com/security/cve/CVE-2024-45336",
								"https://bugzilla.redhat.com/2341750",
							},
							CVSS: map[string]storagev1alpha1.CVSS{
								"bitnami": {
									V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
									V3Score:  "6.1",
								},
								"redhat": {
									V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
									V3Score:  "5.9",
								},
							},
							Suppressed: false,
						},
						{
							CVE:              "CVE-2024-45341",
							Title:            "Lorem ipsum",
							PackageName:      "stdlib",
							PURL:             "pkg:golang/stdlib@v1.23.4",
							InstalledVersion: "v1.23.4",
							FixedVersions: []string{
								"1.22.11",
								"1.23.5",
								"1.24.0-rc.2",
							},
							DiffID:      "sha256:6d134d3d7e8aa630874f7c4e9db3db48d1895c60f3e5ce73272412404a9b723b",
							Description: "Lorem ipsum",
							Severity:    "MEDIUM",
							References: []string{
								"https://access.redhat.com/errata/RHSA-2025:3772",
								"https://access.redhat.com/security/cve/CVE-2024-45341",
								"https://bugzilla.redhat.com/2341750",
							},
							CVSS: map[string]storagev1alpha1.CVSS{
								"bitnami": {
									V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
									V3Score:  "6.1",
								},
								"redhat": {
									V3Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
									V3Score:  "4.2",
								},
							},
							Suppressed: false,
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trivyReportFile, err := os.Open(tt.trivyReport)
			require.NoError(t, err)

			reportData, err := io.ReadAll(trivyReportFile)
			require.NoError(t, err)

			trivyReportData := &trivyTypes.Report{}
			err = json.Unmarshal(reportData, trivyReportData)
			require.NoError(t, err)

			got, err := NewResultsFromTrivyReport(*trivyReportData)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, got, tt.sbombasticReport)
		})
	}
}
