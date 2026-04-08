package mcp

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func (s *Server) registerReadTools() {
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "list_registries",
		Description: "List Registry resources. Registries define container registries to scan for images. Each has a URI, a catalogType controlling image discovery, and optional repository filters with CEL-based tag matching.",
	}, s.listRegistries)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_registry",
		Description: "Get a specific Registry by name and namespace. Returns the registry spec (URI, catalogType, repositories with CEL match conditions, platforms) and status conditions (Discovering, Scanning, UpToDate).",
	}, s.getRegistry)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "list_scanjobs",
		Description: "List ScanJob resources. A ScanJob triggers a scan of all images in a Registry. Check status conditions to track progress: Scheduled, InProgress, Complete, or Failed. Status includes imagesCount and scannedImagesCount.",
	}, s.listScanJobs)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_scanjob",
		Description: "Get a specific ScanJob by name and namespace. Returns the target registry reference and status with conditions (Scheduled, InProgress, Complete, Failed), progress counters (imagesCount, scannedImagesCount), and timing (startTime, completionTime).",
	}, s.getScanJob)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_workloadscan_configuration",
		Description: `Get the cluster-scoped singleton WorkloadScanConfiguration (always named "default"). Controls automatic scanning of container images referenced by Kubernetes workloads.`,
	}, s.getWorkloadScanConfiguration)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "list_vexhubs",
		Description: "List VEXHub resources (cluster-scoped). VEX (Vulnerability Exploitability eXchange) declares whether known vulnerabilities are actually exploitable in a product. A VEXHub points to a repository of VEX documents used to enrich vulnerability reports with suppression data.",
	}, s.listVEXHubs)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_vexhub",
		Description: "Get a specific VEXHub by name. Returns the repository URL and enabled state. When enabled, vulnerability reports are enriched with VEX statuses: not_affected, fixed, or under_investigation.",
	}, s.getVEXHub)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "list_images",
		Description: "List scanned container images with vulnerability counts. Returns the image name, namespace, registry, repository, tag, total vulnerability count, and severity breakdown (critical, high, medium, low, unknown, suppressed). Use this to assess image security posture or find the most vulnerable images.",
	}, s.listImages)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_image_vulnerabilities",
		Description: "Advanced: Get the COMPLETE simplified CVE list for a container image (deduplicated by CVE ID, with top CVSS v3 score, severity, fix availability, and first reference link). WARNING: This returns a very large response that may exceed context limits. In most cases, use get_image_vulnerability_summary instead. Only use this tool if the user explicitly requests the full vulnerability list beyond the top 10.",
	}, s.getImageVulnerabilities)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_image_vulnerability_summary",
		Description: "Get vulnerabilities for a scanned container image by name and namespace. This is the DEFAULT tool for any vulnerability query. Use list_images first to find the image name and namespace. Returns severity counts (critical, high, medium, low, unknown, suppressed) and the top 10 most severe CVEs.",
	}, s.getImageVulnerabilitySummary)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "list_workloads",
		Description: "List scanned Kubernetes workloads with vulnerability counts. Returns for each workload: reportName (the identifier to pass as 'name' to get_workload_vulnerability_summary), namespace, workloadName (the Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod name), workloadKind, total vulnerability count, and severity breakdown. To query a workload's vulnerabilities, find it by workloadName/workloadKind, then use its reportName as the 'name' argument.",
	}, s.listWorkloads)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_workload_vulnerability_summary",
		Description: "Get vulnerabilities for a scanned workload. This is the DEFAULT tool for any workload vulnerability query. Use list_workloads first to find the workload by workloadName/workloadKind, then pass the reportName as 'name' and the namespace. Returns per-container severity counts and top 10 CVEs, plus an overall summary.",
	}, s.getWorkloadVulnerabilitySummary)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_workload_vulnerabilities",
		Description: "Advanced: Get the COMPLETE simplified CVE list for all containers in a workload (deduplicated by CVE ID per container, with top CVSS v3 score, severity, fix availability, and first reference link). Pass the reportName from list_workloads as the 'name' argument. WARNING: This returns a very large response that may exceed context limits. In most cases, use get_workload_vulnerability_summary instead. Only use this tool if the user explicitly requests the full vulnerability list beyond the top 10.",
	}, s.getWorkloadVulnerabilities)
}

func (s *Server) listRegistries(ctx context.Context, _ *mcp.CallToolRequest, args namespacedListArgs) (*mcp.CallToolResult, any, error) {
	return listNamespaced(ctx, s, &v1alpha1.RegistryList{}, args.Namespace)
}

func (s *Server) getRegistry(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	return getNamespaced(ctx, s, &v1alpha1.Registry{}, args.Name, args.Namespace)
}

func (s *Server) listScanJobs(ctx context.Context, _ *mcp.CallToolRequest, args namespacedListArgs) (*mcp.CallToolResult, any, error) {
	return listNamespaced(ctx, s, &v1alpha1.ScanJobList{}, args.Namespace)
}

func (s *Server) getScanJob(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	return getNamespaced(ctx, s, &v1alpha1.ScanJob{}, args.Name, args.Namespace)
}

func (s *Server) getWorkloadScanConfiguration(ctx context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
	return getClusterScoped(ctx, s, &v1alpha1.WorkloadScanConfiguration{}, v1alpha1.WorkloadScanConfigurationName)
}

func (s *Server) listVEXHubs(ctx context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
	list := &v1alpha1.VEXHubList{}
	if err := s.client.List(ctx, list); err != nil {
		return toolError("listing VEXHubs: %v", err)
	}
	return jsonResult(list)
}

func (s *Server) getVEXHub(ctx context.Context, _ *mcp.CallToolRequest, args clusterGetArgs) (*mcp.CallToolResult, any, error) {
	return getClusterScoped(ctx, s, &v1alpha1.VEXHub{}, args.Name)
}

func (s *Server) listImages(ctx context.Context, _ *mcp.CallToolRequest, args namespacedListArgs) (*mcp.CallToolResult, any, error) {
	list := &storagev1alpha1.VulnerabilityReportList{}
	opts := []client.ListOption{}
	if args.Namespace != "" {
		opts = append(opts, client.InNamespace(args.Namespace))
	}
	if err := s.client.List(ctx, list, opts...); err != nil {
		return toolError("listing vulnerability reports: %v", err)
	}

	items := make([]imageListItem, 0, len(list.Items))
	for _, report := range list.Items {
		sum := report.Report.Summary
		items = append(items, imageListItem{
			Name:       report.Name,
			Namespace:  report.Namespace,
			Registry:   report.ImageMetadata.Registry,
			Repository: report.ImageMetadata.Repository,
			Tag:        report.ImageMetadata.Tag,
			Total:      sum.Critical + sum.High + sum.Medium + sum.Low + sum.Unknown,
			Summary:    sum,
		})
	}
	return jsonResult(items)
}

func (s *Server) getImageVulnerabilities(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	report := &storagev1alpha1.VulnerabilityReport{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, report); err != nil {
		return toolError("getting vulnerability report: %v", err)
	}

	vulnerabilities, err := collectSimplifiedVulnerabilities(report)
	if err != nil {
		return toolError("collecting vulnerabilities: %v", err)
	}

	return jsonResult(imageVulnerabilitiesResponse{
		Registry:        report.ImageMetadata.Registry,
		Repository:      report.ImageMetadata.Repository,
		Tag:             report.ImageMetadata.Tag,
		Vulnerabilities: vulnerabilities,
	})
}

func (s *Server) getImageVulnerabilitySummary(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	report := &storagev1alpha1.VulnerabilityReport{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, report); err != nil {
		return toolError("getting vulnerability report: %v", err)
	}

	vulnerabilities, err := collectSimplifiedVulnerabilities(report)
	if err != nil {
		return toolError("collecting vulnerabilities: %v", err)
	}
	topVulnerabilities := vulnerabilities
	if len(topVulnerabilities) > 10 {
		topVulnerabilities = topVulnerabilities[:10]
	}

	sum := report.Report.Summary
	return jsonResult(imageVulnerabilitySummaryResponse{
		Registry:           report.ImageMetadata.Registry,
		Repository:         report.ImageMetadata.Repository,
		Tag:                report.ImageMetadata.Tag,
		Total:              sum.Critical + sum.High + sum.Medium + sum.Low + sum.Unknown,
		Summary:            sum,
		TopVulnerabilities: topVulnerabilities,
	})
}

func (s *Server) listWorkloads(ctx context.Context, _ *mcp.CallToolRequest, args namespacedListArgs) (*mcp.CallToolResult, any, error) {
	list := &storagev1alpha1.WorkloadScanReportList{}
	opts := []client.ListOption{}
	if args.Namespace != "" {
		opts = append(opts, client.InNamespace(args.Namespace))
	}
	if err := s.client.List(ctx, list, opts...); err != nil {
		return toolError("listing workload scan reports: %v", err)
	}

	items := make([]workloadListItem, 0, len(list.Items))
	for _, report := range list.Items {
		sum := report.Summary
		workloadName, workloadKind := ownerWorkload(&report)
		items = append(items, workloadListItem{
			ReportName:   report.Name,
			Namespace:    report.Namespace,
			WorkloadName: workloadName,
			WorkloadKind: workloadKind,
			Total:        sum.Critical + sum.High + sum.Medium + sum.Low + sum.Unknown,
			Summary:      sum,
		})
	}
	return jsonResult(items)
}

func (s *Server) getWorkloadVulnerabilitySummary(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	report := &storagev1alpha1.WorkloadScanReport{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, report); err != nil {
		return toolError("getting workload scan report: %v", err)
	}

	var containers []containerVulnerabilitySummary
	for _, container := range report.Containers {
		vulnerabilities, err := collectSimplifiedVulnerabilitiesFromWorkload(container.VulnerabilityReports)
		if err != nil {
			return toolError("collecting vulnerabilities: %v", err)
		}
		topVulnerabilities := vulnerabilities
		if len(topVulnerabilities) > 10 {
			topVulnerabilities = topVulnerabilities[:10]
		}

		summary := summaryFromSimplified(vulnerabilities)
		containers = append(containers, containerVulnerabilitySummary{
			Container:          container.Name,
			Total:              summary.Critical + summary.High + summary.Medium + summary.Low + summary.Unknown,
			Summary:            summary,
			TopVulnerabilities: topVulnerabilities,
		})
	}

	overallSum := report.Summary
	return jsonResult(workloadVulnerabilitySummaryResponse{
		Workload:   report.Name,
		Total:      overallSum.Critical + overallSum.High + overallSum.Medium + overallSum.Low + overallSum.Unknown,
		Summary:    overallSum,
		Containers: containers,
	})
}

func (s *Server) getWorkloadVulnerabilities(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	report := &storagev1alpha1.WorkloadScanReport{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, report); err != nil {
		return toolError("getting workload scan report: %v", err)
	}

	var containers []containerVulnerabilities
	for _, container := range report.Containers {
		vulnerabilities, err := collectSimplifiedVulnerabilitiesFromWorkload(container.VulnerabilityReports)
		if err != nil {
			return toolError("collecting vulnerabilities: %v", err)
		}
		containers = append(containers, containerVulnerabilities{
			Container:       container.Name,
			Vulnerabilities: vulnerabilities,
		})
	}

	return jsonResult(workloadVulnerabilitiesResponse{
		Workload:   report.Name,
		Containers: containers,
	})
}

func (s *Server) registerWriteTools() {
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name: "create_registry",
		Description: `Create a new Registry defining a container registry to scan. Set catalogType to "OCIDistribution" if the registry exposes the OCI _catalog endpoint, or "NoCatalog" if not (requires explicit repositories list).

Repositories optionally filter tags via matchConditions. Each condition has a "name" and a CEL "expression" evaluated against the "tag" variable. Use "matchOperator" on the repository to combine multiple conditions: "And" (default) or "Or". Do NOT combine logic with && or || inside a single expression — use separate matchConditions instead.

Complete YAML example — note that uri is ONLY the registry hostname, and each repository name is the path without the hostname:
apiVersion: sbomscanner.kubewarden.io/v1alpha1
kind: Registry
metadata:
  name: my-registry
  namespace: default
spec:
  uri: ghcr.io
  catalogType: NoCatalog
  insecure: false
  repositories:
  - name: my-org/my-app
    matchOperator: Or
    matchConditions:
    - name: latest-only
      expression: "tag == 'latest'"
    - name: semver-above-1
      expression: "semver(tag, true).isGreaterThan(semver('1.0.0'))"
  - name: my-org/other-app

CEL expression reference:
- Regex: tag.matches('^v[0-9]+')
- Negation: !tag.matches('-dev$')
- Exact: tag == 'latest'
- Semver: semver(tag, true).isGreaterThan(semver('1.27.0'))
- String: tag.startsWith('release-'), tag.endsWith('-amd64')`,
	}, s.createRegistry)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "update_registry",
		Description: "Update an existing Registry. Only provided fields are changed; omitted fields keep current values. The repositories list, if provided, replaces the existing list entirely.",
	}, s.updateRegistry)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "delete_registry",
		Description: "Delete a Registry. Previously discovered Images, SBOMs, and VulnerabilityReports are not deleted.",
	}, s.deleteRegistry)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "create_scanjob",
		Description: `Create a ScanJob to trigger a scan of all images in a Registry. The registry must exist in the same namespace. Monitor progress with get_scanjob: Scheduled → InProgress (CatalogCreationInProgress, SBOMGenerationInProgress, ImageScanInProgress) → Complete or Failed.`,
	}, s.createScanJob)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "delete_scanjob",
		Description: "Delete a ScanJob. Scan results (Images, SBOMs, VulnerabilityReports) produced by the job are not deleted.",
	}, s.deleteScanJob)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "create_vexhub",
		Description: "Create a new VEXHub (cluster-scoped). VEX (Vulnerability Exploitability eXchange) documents declare whether vulnerabilities are exploitable. Point it at a VEX document repository and set enabled to true to enrich vulnerability reports with suppression data (not_affected, fixed, under_investigation).",
	}, s.createVEXHub)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "update_vexhub",
		Description: "Update an existing VEXHub. Only provided fields are changed. Toggle enabled to start or stop VEX enrichment of vulnerability reports.",
	}, s.updateVEXHub)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "delete_vexhub",
		Description: "Delete a VEXHub. VEX annotations already applied to existing vulnerability reports are not removed.",
	}, s.deleteVEXHub)
}

func (s *Server) createRegistry(ctx context.Context, _ *mcp.CallToolRequest, args registryCreateArgs) (*mcp.CallToolResult, any, error) {
	registry := &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.Name,
			Namespace: args.Namespace,
		},
		Spec: v1alpha1.RegistrySpec{
			URI:          args.URI,
			CatalogType:  args.CatalogType,
			Insecure:     args.Insecure,
			Repositories: args.Repositories,
		},
	}
	if err := s.client.Create(ctx, registry); err != nil {
		return toolError("creating registry: %v", err)
	}
	return jsonResult(registry)
}

func (s *Server) updateRegistry(ctx context.Context, _ *mcp.CallToolRequest, args registryUpdateArgs) (*mcp.CallToolResult, any, error) {
	registry := &v1alpha1.Registry{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, registry); err != nil {
		return toolError("getting registry: %v", err)
	}
	if args.URI != nil {
		registry.Spec.URI = *args.URI
	}
	if args.CatalogType != nil {
		registry.Spec.CatalogType = *args.CatalogType
	}
	if args.Insecure != nil {
		registry.Spec.Insecure = *args.Insecure
	}
	if args.Repositories != nil {
		registry.Spec.Repositories = args.Repositories
	}
	if err := s.client.Update(ctx, registry); err != nil {
		return toolError("updating registry: %v", err)
	}
	return jsonResult(registry)
}

func (s *Server) deleteRegistry(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	registry := &v1alpha1.Registry{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, registry); err != nil {
		return toolError("getting registry: %v", err)
	}
	if err := s.client.Delete(ctx, registry); err != nil {
		return toolError("deleting registry: %v", err)
	}
	return jsonResult(registry)
}

func (s *Server) createScanJob(ctx context.Context, _ *mcp.CallToolRequest, args scanJobCreateArgs) (*mcp.CallToolResult, any, error) {
	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.Name,
			Namespace: args.Namespace,
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: args.Registry,
		},
	}
	if err := s.client.Create(ctx, scanJob); err != nil {
		return toolError("creating scan job: %v", err)
	}
	return jsonResult(scanJob)
}

func (s *Server) deleteScanJob(ctx context.Context, _ *mcp.CallToolRequest, args namespacedGetArgs) (*mcp.CallToolResult, any, error) {
	scanJob := &v1alpha1.ScanJob{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name, Namespace: args.Namespace}, scanJob); err != nil {
		return toolError("getting scan job: %v", err)
	}
	if err := s.client.Delete(ctx, scanJob); err != nil {
		return toolError("deleting scan job: %v", err)
	}
	return jsonResult(scanJob)
}

func (s *Server) createVEXHub(ctx context.Context, _ *mcp.CallToolRequest, args vexHubCreateArgs) (*mcp.CallToolResult, any, error) {
	vexHub := &v1alpha1.VEXHub{
		ObjectMeta: metav1.ObjectMeta{
			Name: args.Name,
		},
		Spec: v1alpha1.VEXHubSpec{
			URL:     args.URL,
			Enabled: args.Enabled,
		},
	}
	if err := s.client.Create(ctx, vexHub); err != nil {
		return toolError("creating VEXHub: %v", err)
	}
	return jsonResult(vexHub)
}

func (s *Server) updateVEXHub(ctx context.Context, _ *mcp.CallToolRequest, args vexHubUpdateArgs) (*mcp.CallToolResult, any, error) {
	vexHub := &v1alpha1.VEXHub{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name}, vexHub); err != nil {
		return toolError("getting VEXHub: %v", err)
	}
	if args.URL != nil {
		vexHub.Spec.URL = *args.URL
	}
	if args.Enabled != nil {
		vexHub.Spec.Enabled = *args.Enabled
	}
	if err := s.client.Update(ctx, vexHub); err != nil {
		return toolError("updating VEXHub: %v", err)
	}
	return jsonResult(vexHub)
}

func (s *Server) deleteVEXHub(ctx context.Context, _ *mcp.CallToolRequest, args clusterGetArgs) (*mcp.CallToolResult, any, error) {
	vexHub := &v1alpha1.VEXHub{}
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: args.Name}, vexHub); err != nil {
		return toolError("getting VEXHub: %v", err)
	}
	if err := s.client.Delete(ctx, vexHub); err != nil {
		return toolError("deleting VEXHub: %v", err)
	}
	return jsonResult(vexHub)
}
