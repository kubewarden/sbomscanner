package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type ServerSuite struct {
	suite.Suite

	httpServer *httptest.Server
	session    *mcp.ClientSession
}

func TestServerSuite(t *testing.T) {
	suite.Run(t, new(ServerSuite))
}

func (s *ServerSuite) SetupSuite() {
	const (
		username = "admin"
		password = "secret"
	)

	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-registry",
			Namespace: "default",
		},
		Spec: v1alpha1.RegistrySpec{
			URI:         "https://registry.example.com",
			CatalogType: v1alpha1.CatalogTypeOCIDistribution,
		},
	}

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: "test-registry",
		},
	}

	workloadScanConfiguration := &v1alpha1.WorkloadScanConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: v1alpha1.WorkloadScanConfigurationName,
		},
		Spec: v1alpha1.WorkloadScanConfigurationSpec{
			Enabled: true,
		},
	}

	vexHub := &v1alpha1.VEXHub{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-vexhub",
		},
		Spec: v1alpha1.VEXHubSpec{
			URL: "https://vexhub.example.com",
		},
	}

	imageMetadata := storagev1alpha1.ImageMetadata{
		Registry:    "test-registry",
		RegistryURI: "https://registry.example.com",
		Repository:  "library/test",
		Tag:         "latest",
		Platform:    "linux/amd64",
		Digest:      "sha256:abc123",
	}

	vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vulnreport",
			Namespace: "default",
		},
		ImageMetadata: imageMetadata,
		Report: storagev1alpha1.Report{
			Summary: storagev1alpha1.Summary{
				Critical: 1,
				High:     1,
				Medium:   1,
			},
			Results: []storagev1alpha1.Result{
				{
					Target: "library/test (debian 12.0)",
					Class:  storagev1alpha1.ClassOSPackages,
					Type:   "debian",
					Vulnerabilities: []storagev1alpha1.Vulnerability{
						{
							CVE:              "CVE-2024-0001",
							Title:            "OpenSSL Buffer Overflow",
							Severity:         storagev1alpha1.SeverityCritical,
							PackageName:      "openssl",
							InstalledVersion: "1.1.1k-1",
							FixedVersions:    []string{"1.1.1l-1"},
							CVSS: map[string]storagev1alpha1.CVSS{
								"nvd": {V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: "9.8"},
							},
							References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
						},
						{
							CVE:              "CVE-2024-0002",
							Title:            "curl HTTP Header Injection",
							Severity:         storagev1alpha1.SeverityHigh,
							PackageName:      "curl",
							InstalledVersion: "7.74.0-1",
							FixedVersions:    []string{"7.74.0-2"},
							CVSS: map[string]storagev1alpha1.CVSS{
								"nvd":    {V3Vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", V3Score: "7.5"},
								"redhat": {V3Vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", V3Score: "8.1"},
							},
							References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0002"},
						},
						{
							CVE:              "CVE-2024-0003",
							Title:            "zlib Memory Corruption",
							Severity:         storagev1alpha1.SeverityMedium,
							PackageName:      "zlib",
							InstalledVersion: "1.2.11-4",
							CVSS: map[string]storagev1alpha1.CVSS{
								"nvd": {V3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", V3Score: "4.2"},
							},
							References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0003"},
						},
					},
				},
			},
		},
	}

	workloadScanReport := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-wsreport",
			Namespace: "default",
		},
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: []storagev1alpha1.ContainerRef{
				{
					Name: "app",
					ImageRef: storagev1alpha1.ImageRef{
						Registry:   "test-registry",
						Namespace:  "default",
						Repository: "library/test",
						Tag:        "latest",
					},
				},
			},
		},
		Summary: storagev1alpha1.Summary{
			Critical: 1,
			High:     1,
			Medium:   1,
		},
		Containers: []storagev1alpha1.ContainerResult{
			{
				Name: "app",
				VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
					{
						Name:          "test-vulnreport",
						Namespace:     "default",
						ImageMetadata: imageMetadata,
						Report: storagev1alpha1.Report{
							Summary: storagev1alpha1.Summary{
								Critical: 1,
								High:     1,
								Medium:   1,
							},
							Results: []storagev1alpha1.Result{
								{
									Target: "library/test (debian 12.0)",
									Class:  storagev1alpha1.ClassOSPackages,
									Type:   "debian",
									Vulnerabilities: []storagev1alpha1.Vulnerability{
										{
											CVE:              "CVE-2024-0001",
											Severity:         storagev1alpha1.SeverityCritical,
											PackageName:      "openssl",
											InstalledVersion: "1.1.1k-1",
											FixedVersions:    []string{"1.1.1l-1"},
											CVSS: map[string]storagev1alpha1.CVSS{
												"nvd": {V3Score: "9.8"},
											},
											References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
										},
										{
											CVE:              "CVE-2024-0002",
											Severity:         storagev1alpha1.SeverityHigh,
											PackageName:      "curl",
											InstalledVersion: "7.74.0-1",
											FixedVersions:    []string{"7.74.0-2"},
											CVSS: map[string]storagev1alpha1.CVSS{
												"nvd": {V3Score: "8.1"},
											},
											References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0002"},
											Suppressed: true,
										},
										{
											CVE:              "CVE-2024-0003",
											Severity:         storagev1alpha1.SeverityMedium,
											PackageName:      "zlib",
											InstalledVersion: "1.2.11-4",
											CVSS: map[string]storagev1alpha1.CVSS{
												"nvd": {V3Score: "4.2"},
											},
											References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0003"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	s.Require().NoError(v1alpha1.AddToScheme(scheme))
	s.Require().NoError(storagev1alpha1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(registry, scanJob, workloadScanConfiguration, vexHub, vulnerabilityReport, workloadScanReport).
		Build()

	server := NewServer(k8sClient, slog.Default(), false)

	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server.mcpServer },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	)

	s.httpServer = httptest.NewServer(requireBasicAuth(username, password, slog.Default())(handler))

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	session, err := mcpClient.Connect(s.T().Context(), &mcp.StreamableClientTransport{
		Endpoint: s.httpServer.URL,
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				r.SetBasicAuth(username, password)
				return http.DefaultTransport.RoundTrip(r)
			}),
		},
	}, nil)
	s.Require().NoError(err)
	s.session = session
}

func (s *ServerSuite) TearDownSuite() {
	if s.session != nil {
		s.session.Close()
	}
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

func (s *ServerSuite) TestCallTool_ListRegistries() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "list_registries",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)
	s.Require().Len(result.Content, 1)

	text := result.Content[0].(*mcp.TextContent).Text

	var list v1alpha1.RegistryList
	s.Require().NoError(json.Unmarshal([]byte(text), &list))
	s.Require().NotEmpty(list.Items)

	var found bool
	for _, item := range list.Items {
		if item.Name == "test-registry" {
			s.Require().Equal("https://registry.example.com", item.Spec.URI)
			found = true
			break
		}
	}
	s.Require().True(found, "test-registry not found in list")
}

func (s *ServerSuite) TestCallTool_GetRegistry() {
	result, err := s.session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_registry",
		Arguments: map[string]any{
			"name":      "test-registry",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got v1alpha1.Registry
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-registry", got.Name)
	s.Require().Equal("https://registry.example.com", got.Spec.URI)
}

func (s *ServerSuite) TestCallTool_GetRegistry_NotFound() {
	result, err := s.session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_registry",
		Arguments: map[string]any{
			"name":      "does-not-exist",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().True(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text
	s.Require().Contains(text, "not found")
}

func (s *ServerSuite) TestListTools() {
	result, err := s.session.ListTools(s.T().Context(), nil)
	s.Require().NoError(err)

	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}

	expected := []string{
		"list_registries", "get_registry",
		"create_registry", "update_registry", "delete_registry",
		"list_scanjobs", "get_scanjob",
		"create_scanjob", "delete_scanjob",
		"get_workloadscan_configuration",
		"list_vexhubs", "get_vexhub",
		"create_vexhub", "update_vexhub", "delete_vexhub",
		"list_images", "get_image_vulnerabilities", "get_image_vulnerability_summary",
		"list_workloads", "get_workload_vulnerability_summary", "get_workload_vulnerabilities",
	}
	s.Require().ElementsMatch(expected, names)
}

func (s *ServerSuite) TestCallTool_ListScanJobs() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "list_scanjobs",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)
	s.Require().Len(result.Content, 1)

	text := result.Content[0].(*mcp.TextContent).Text

	var list v1alpha1.ScanJobList
	s.Require().NoError(json.Unmarshal([]byte(text), &list))
	s.Require().NotEmpty(list.Items)

	var found bool
	for _, item := range list.Items {
		if item.Name == "test-scanjob" {
			found = true
			break
		}
	}
	s.Require().True(found, "test-scanjob not found in list")
}

func (s *ServerSuite) TestCallTool_GetScanJob() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_scanjob",
		Arguments: map[string]any{
			"name":      "test-scanjob",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got v1alpha1.ScanJob
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-scanjob", got.Name)
	s.Require().Equal("test-registry", got.Spec.Registry)
}

func (s *ServerSuite) TestCallTool_GetWorkloadScanConfiguration() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_workloadscan_configuration",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got v1alpha1.WorkloadScanConfiguration
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal(v1alpha1.WorkloadScanConfigurationName, got.Name)
	s.Require().True(got.Spec.Enabled)
}

func (s *ServerSuite) TestCallTool_ListVEXHubs() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "list_vexhubs",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)
	s.Require().Len(result.Content, 1)

	text := result.Content[0].(*mcp.TextContent).Text

	var list v1alpha1.VEXHubList
	s.Require().NoError(json.Unmarshal([]byte(text), &list))
	s.Require().NotEmpty(list.Items)

	var found bool
	for _, item := range list.Items {
		if item.Name == "test-vexhub" {
			s.Require().Equal("https://vexhub.example.com", item.Spec.URL)
			found = true
			break
		}
	}
	s.Require().True(found, "test-vexhub not found in list")
}

func (s *ServerSuite) TestCallTool_GetVEXHub() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_vexhub",
		Arguments: map[string]any{
			"name": "test-vexhub",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got v1alpha1.VEXHub
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-vexhub", got.Name)
	s.Require().Equal("https://vexhub.example.com", got.Spec.URL)
}

func (s *ServerSuite) TestCallTool_ListImages() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "list_images",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)
	s.Require().Len(result.Content, 1)

	text := result.Content[0].(*mcp.TextContent).Text

	var items []imageListItem
	s.Require().NoError(json.Unmarshal([]byte(text), &items))
	s.Require().Len(items, 1)
	s.Require().Equal("test-vulnreport", items[0].Name)
	s.Require().Equal("default", items[0].Namespace)
	s.Require().Equal("test-registry", items[0].Registry)
	s.Require().Equal("library/test", items[0].Repository)
	s.Require().Equal("latest", items[0].Tag)
	s.Require().Equal(3, items[0].Total)
	s.Require().Equal(1, items[0].Summary.Critical)
	s.Require().Equal(1, items[0].Summary.High)
	s.Require().Equal(1, items[0].Summary.Medium)
}

func (s *ServerSuite) TestCallTool_GetImageVulnerabilities() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_image_vulnerabilities",
		Arguments: map[string]any{
			"name":      "test-vulnreport",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got imageVulnerabilitiesResponse
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-registry", got.Registry)
	s.Require().Equal("library/test", got.Repository)
	s.Require().Equal("latest", got.Tag)
	s.Require().Len(got.Vulnerabilities, 3)

	// Should be sorted by CVSS score descending
	s.Require().Equal("CVE-2024-0001", got.Vulnerabilities[0].CVE)
	s.Require().InDelta(9.8, got.Vulnerabilities[0].CVSSScore, 0.01)
	s.Require().Equal(storagev1alpha1.SeverityCritical, got.Vulnerabilities[0].Severity)
	s.Require().True(got.Vulnerabilities[0].Critical)
	s.Require().True(got.Vulnerabilities[0].FixAvailable)
	s.Require().Equal("openssl", got.Vulnerabilities[0].Package)
	s.Require().Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-0001", got.Vulnerabilities[0].Link)

	// CVE-2024-0002 should use the highest CVSS score (8.1 from redhat, not 7.5 from nvd)
	s.Require().Equal("CVE-2024-0002", got.Vulnerabilities[1].CVE)
	s.Require().InDelta(8.1, got.Vulnerabilities[1].CVSSScore, 0.01)
	s.Require().False(got.Vulnerabilities[1].Critical)

	s.Require().Equal("CVE-2024-0003", got.Vulnerabilities[2].CVE)
	s.Require().InDelta(4.2, got.Vulnerabilities[2].CVSSScore, 0.01)
	s.Require().False(got.Vulnerabilities[2].FixAvailable)
}

func (s *ServerSuite) TestCallTool_GetImageVulnerabilities_NotFound() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_image_vulnerabilities",
		Arguments: map[string]any{
			"name":      "does-not-exist",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().True(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text
	s.Require().Contains(text, "not found")
}

func (s *ServerSuite) TestCallTool_GetImageVulnerabilitySummary() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_image_vulnerability_summary",
		Arguments: map[string]any{
			"name":      "test-vulnreport",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got imageVulnerabilitySummaryResponse
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-registry", got.Registry)
	s.Require().Equal("library/test", got.Repository)
	s.Require().Equal("latest", got.Tag)
	s.Require().Equal(1, got.Summary.Critical)
	s.Require().Equal(1, got.Summary.High)
	s.Require().Equal(1, got.Summary.Medium)
	s.Require().Equal(0, got.Summary.Low)
	s.Require().Equal(0, got.Summary.Unknown)
	s.Require().Equal(0, got.Summary.Suppressed)
	s.Require().Equal(3, got.Total)

	// Top vulnerabilities should be sorted by severity then CVSS score
	s.Require().Len(got.TopVulnerabilities, 3)
	s.Require().Equal("CVE-2024-0001", got.TopVulnerabilities[0].CVE)
	s.Require().Equal("CVE-2024-0002", got.TopVulnerabilities[1].CVE)
	s.Require().Equal("CVE-2024-0003", got.TopVulnerabilities[2].CVE)
}

func (s *ServerSuite) TestCallTool_ListWorkloads() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "list_workloads",
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)
	s.Require().Len(result.Content, 1)

	text := result.Content[0].(*mcp.TextContent).Text

	var items []workloadListItem
	s.Require().NoError(json.Unmarshal([]byte(text), &items))
	s.Require().Len(items, 1)
	s.Require().Equal("test-wsreport", items[0].ReportName)
	s.Require().Equal("default", items[0].Namespace)
	s.Require().Equal(3, items[0].Total)
	s.Require().Equal(1, items[0].Summary.Critical)
	s.Require().Equal(1, items[0].Summary.High)
	s.Require().Equal(1, items[0].Summary.Medium)
}

func (s *ServerSuite) TestCallTool_GetWorkloadVulnerabilitySummary() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_workload_vulnerability_summary",
		Arguments: map[string]any{
			"name":      "test-wsreport",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got workloadVulnerabilitySummaryResponse
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-wsreport", got.Workload)
	s.Require().Equal(3, got.Total)
	s.Require().Equal(1, got.Summary.Critical)
	s.Require().Equal(1, got.Summary.High)
	s.Require().Equal(1, got.Summary.Medium)

	s.Require().Len(got.Containers, 1)
	c := got.Containers[0]
	s.Require().Equal("app", c.Container)
	s.Require().Equal(2, c.Total) // CVE-0002 is suppressed, so only 2 non-suppressed
	s.Require().Equal(1, c.Summary.Critical)
	s.Require().Equal(0, c.Summary.High) // suppressed
	s.Require().Equal(1, c.Summary.Medium)
	s.Require().Equal(1, c.Summary.Suppressed)

	s.Require().Len(c.TopVulnerabilities, 3)
	s.Require().Equal("CVE-2024-0001", c.TopVulnerabilities[0].CVE)
	s.Require().True(c.TopVulnerabilities[1].Suppressed)
}

func (s *ServerSuite) TestCallTool_GetWorkloadVulnerabilities() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_workload_vulnerabilities",
		Arguments: map[string]any{
			"name":      "test-wsreport",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	text := result.Content[0].(*mcp.TextContent).Text

	var got workloadVulnerabilitiesResponse
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("test-wsreport", got.Workload)
	s.Require().Len(got.Containers, 1)
	s.Require().Equal("app", got.Containers[0].Container)
	s.Require().Len(got.Containers[0].Vulnerabilities, 3)
}

func (s *ServerSuite) TestCallTool_CreateRegistry() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_registry",
		Arguments: map[string]any{
			"name":        "new-registry",
			"namespace":   "default",
			"uri":         "https://new-registry.example.com",
			"catalogType": "OCIDistribution",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify via get
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_registry",
		Arguments: map[string]any{
			"name":      "new-registry",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(getResult.IsError)

	text := getResult.Content[0].(*mcp.TextContent).Text
	var got v1alpha1.Registry
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("new-registry", got.Name)
	s.Require().Equal("https://new-registry.example.com", got.Spec.URI)
	s.Require().Equal("OCIDistribution", got.Spec.CatalogType)
}

func (s *ServerSuite) TestCallTool_UpdateRegistry() {
	// Create a registry to update
	_, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_registry",
		Arguments: map[string]any{
			"name":        "update-target-registry",
			"namespace":   "default",
			"uri":         "https://before-update.example.com",
			"catalogType": "OCIDistribution",
		},
	})
	s.Require().NoError(err)

	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "update_registry",
		Arguments: map[string]any{
			"name":      "update-target-registry",
			"namespace": "default",
			"uri":       "https://after-update.example.com",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify via get
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_registry",
		Arguments: map[string]any{
			"name":      "update-target-registry",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(getResult.IsError)

	text := getResult.Content[0].(*mcp.TextContent).Text
	var got v1alpha1.Registry
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("https://after-update.example.com", got.Spec.URI)
	// CatalogType should remain unchanged
	s.Require().Equal(v1alpha1.CatalogTypeOCIDistribution, got.Spec.CatalogType)
}

func (s *ServerSuite) TestCallTool_DeleteRegistry() {
	// Create a registry to delete
	_, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_registry",
		Arguments: map[string]any{
			"name":        "delete-target-registry",
			"namespace":   "default",
			"uri":         "https://to-delete.example.com",
			"catalogType": "NoCatalog",
		},
	})
	s.Require().NoError(err)

	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "delete_registry",
		Arguments: map[string]any{
			"name":      "delete-target-registry",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify get returns not found
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_registry",
		Arguments: map[string]any{
			"name":      "delete-target-registry",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().True(getResult.IsError)
	text := getResult.Content[0].(*mcp.TextContent).Text
	s.Require().Contains(text, "not found")
}

func (s *ServerSuite) TestCallTool_CreateScanJob() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_scanjob",
		Arguments: map[string]any{
			"name":      "new-scanjob",
			"namespace": "default",
			"registry":  "test-registry",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify via get
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_scanjob",
		Arguments: map[string]any{
			"name":      "new-scanjob",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(getResult.IsError)

	text := getResult.Content[0].(*mcp.TextContent).Text
	var got v1alpha1.ScanJob
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("new-scanjob", got.Name)
	s.Require().Equal("test-registry", got.Spec.Registry)
}

func (s *ServerSuite) TestCallTool_DeleteScanJob() {
	// Create a scan job to delete
	_, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_scanjob",
		Arguments: map[string]any{
			"name":      "delete-target-scanjob",
			"namespace": "default",
			"registry":  "test-registry",
		},
	})
	s.Require().NoError(err)

	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "delete_scanjob",
		Arguments: map[string]any{
			"name":      "delete-target-scanjob",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify get returns not found
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_scanjob",
		Arguments: map[string]any{
			"name":      "delete-target-scanjob",
			"namespace": "default",
		},
	})
	s.Require().NoError(err)
	s.Require().True(getResult.IsError)
	text := getResult.Content[0].(*mcp.TextContent).Text
	s.Require().Contains(text, "not found")
}

// VEXHub write tool tests

func (s *ServerSuite) TestCallTool_CreateVEXHub() {
	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_vexhub",
		Arguments: map[string]any{
			"name":    "new-vexhub",
			"url":     "https://new-vexhub.example.com",
			"enabled": true,
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify via get
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_vexhub",
		Arguments: map[string]any{
			"name": "new-vexhub",
		},
	})
	s.Require().NoError(err)
	s.Require().False(getResult.IsError)

	text := getResult.Content[0].(*mcp.TextContent).Text
	var got v1alpha1.VEXHub
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("new-vexhub", got.Name)
	s.Require().Equal("https://new-vexhub.example.com", got.Spec.URL)
	s.Require().True(got.Spec.Enabled)
}

func (s *ServerSuite) TestCallTool_UpdateVEXHub() {
	// Create a VEXHub to update
	_, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_vexhub",
		Arguments: map[string]any{
			"name":    "update-target-vexhub",
			"url":     "https://before-update.example.com",
			"enabled": true,
		},
	})
	s.Require().NoError(err)

	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "update_vexhub",
		Arguments: map[string]any{
			"name": "update-target-vexhub",
			"url":  "https://after-update.example.com",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify via get
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_vexhub",
		Arguments: map[string]any{
			"name": "update-target-vexhub",
		},
	})
	s.Require().NoError(err)
	s.Require().False(getResult.IsError)

	text := getResult.Content[0].(*mcp.TextContent).Text
	var got v1alpha1.VEXHub
	s.Require().NoError(json.Unmarshal([]byte(text), &got))
	s.Require().Equal("https://after-update.example.com", got.Spec.URL)
	// Enabled should remain unchanged
	s.Require().True(got.Spec.Enabled)
}

func (s *ServerSuite) TestCallTool_DeleteVEXHub() {
	// Create a VEXHub to delete
	_, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "create_vexhub",
		Arguments: map[string]any{
			"name":    "delete-target-vexhub",
			"url":     "https://to-delete.example.com",
			"enabled": false,
		},
	})
	s.Require().NoError(err)

	result, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "delete_vexhub",
		Arguments: map[string]any{
			"name": "delete-target-vexhub",
		},
	})
	s.Require().NoError(err)
	s.Require().False(result.IsError)

	// Verify get returns not found
	getResult, err := s.session.CallTool(s.T().Context(), &mcp.CallToolParams{
		Name: "get_vexhub",
		Arguments: map[string]any{
			"name": "delete-target-vexhub",
		},
	})
	s.Require().NoError(err)
	s.Require().True(getResult.IsError)
	text := getResult.Content[0].(*mcp.TextContent).Text
	s.Require().Contains(text, "not found")
}

type ReadOnlyServerSuite struct {
	suite.Suite

	httpServer *httptest.Server
	session    *mcp.ClientSession
}

func TestReadOnlyServerSuite(t *testing.T) {
	suite.Run(t, new(ReadOnlyServerSuite))
}

func (s *ReadOnlyServerSuite) SetupSuite() {
	const (
		username = "admin"
		password = "secret"
	)

	scheme := runtime.NewScheme()
	s.Require().NoError(v1alpha1.AddToScheme(scheme))
	s.Require().NoError(storagev1alpha1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	server := NewServer(k8sClient, slog.Default(), true)

	handler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server.mcpServer },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	)

	s.httpServer = httptest.NewServer(requireBasicAuth(username, password, slog.Default())(handler))

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	session, err := mcpClient.Connect(s.T().Context(), &mcp.StreamableClientTransport{
		Endpoint: s.httpServer.URL,
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				r.SetBasicAuth(username, password)
				return http.DefaultTransport.RoundTrip(r)
			}),
		},
	}, nil)
	s.Require().NoError(err)
	s.session = session
}

func (s *ReadOnlyServerSuite) TearDownSuite() {
	if s.session != nil {
		s.session.Close()
	}
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

func (s *ReadOnlyServerSuite) TestListTools_ReadOnly() {
	result, err := s.session.ListTools(s.T().Context(), nil)
	s.Require().NoError(err)

	names := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}

	writeTools := []string{
		"create_registry", "update_registry", "delete_registry",
		"create_scanjob", "delete_scanjob",
		"create_vexhub", "update_vexhub", "delete_vexhub",
	}
	for _, wt := range writeTools {
		s.Require().NotContains(names, wt, "write tool %q should not be present in read-only mode", wt)
	}

	// Read tools should still be present
	readTools := []string{
		"list_registries", "get_registry",
		"list_scanjobs", "get_scanjob",
		"get_workloadscan_configuration",
		"list_vexhubs", "get_vexhub",
		"list_images", "get_image_vulnerabilities", "get_image_vulnerability_summary",
		"list_workloads", "get_workload_vulnerability_summary", "get_workload_vulnerabilities",
	}
	for _, rt := range readTools {
		s.Require().Contains(names, rt, "read tool %q should be present in read-only mode", rt)
	}
}
