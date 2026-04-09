package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// ownerWorkload extracts the workload name and kind from the first owner reference.
func ownerWorkload(report *storagev1alpha1.WorkloadScanReport) (string, string) {
	if len(report.OwnerReferences) > 0 {
		return report.OwnerReferences[0].Name, report.OwnerReferences[0].Kind
	}
	return report.Name, ""
}

// simplifyVulnerability converts a raw Vulnerability into a simplifiedVulnerability,
// picking the first reference link and the highest CVSS v3 score.
func simplifyVulnerability(vulnerability storagev1alpha1.Vulnerability) (simplifiedVulnerability, error) {
	var link string
	if len(vulnerability.References) > 0 {
		link = vulnerability.References[0]
	}

	var highestScore float64
	for _, cvssEntry := range vulnerability.CVSS {
		if cvssEntry.V3Score == "" {
			continue
		}
		score, err := strconv.ParseFloat(cvssEntry.V3Score, 64)
		if err != nil {
			return simplifiedVulnerability{}, fmt.Errorf("parsing CVSS v3 score %q for %s: %w", cvssEntry.V3Score, vulnerability.CVE, err)
		}
		if score > highestScore {
			highestScore = score
		}
	}

	return simplifiedVulnerability{
		CVE:          vulnerability.CVE,
		Link:         link,
		CVSSScore:    highestScore,
		Severity:     vulnerability.Severity,
		Critical:     vulnerability.Severity == storagev1alpha1.SeverityCritical,
		FixAvailable: len(vulnerability.FixedVersions) > 0,
		Suppressed:   vulnerability.Suppressed,
		Package:      vulnerability.PackageName,
	}, nil
}

// collectSimplifiedVulnerabilities flattens, deduplicates, and sorts vulnerabilities from a report.
func collectSimplifiedVulnerabilities(report *storagev1alpha1.VulnerabilityReport) ([]simplifiedVulnerability, error) {
	seen := make(map[string]simplifiedVulnerability)
	for _, result := range report.Report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if _, exists := seen[vulnerability.CVE]; exists {
				continue
			}
			simplified, err := simplifyVulnerability(vulnerability)
			if err != nil {
				return nil, err
			}
			seen[vulnerability.CVE] = simplified
		}
	}

	vulnerabilities := make([]simplifiedVulnerability, 0, len(seen))
	for _, vulnerability := range seen {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	sortVulnerabilities(vulnerabilities)

	return vulnerabilities, nil
}

// sortVulnerabilities sorts by severity first, then by CVSS score descending.
func sortVulnerabilities(vulnerabilities []simplifiedVulnerability) {
	slices.SortFunc(vulnerabilities, func(a, b simplifiedVulnerability) int {
		severityA := severityRank(a.Severity)
		severityB := severityRank(b.Severity)
		if severityA != severityB {
			return cmp.Compare(severityB, severityA)
		}
		return cmp.Compare(b.CVSSScore, a.CVSSScore)
	})
}

// summaryFromSimplified computes a Summary from a slice of simplified vulnerabilities.
func summaryFromSimplified(vulnerabilities []simplifiedVulnerability) storagev1alpha1.Summary {
	var summary storagev1alpha1.Summary
	for _, vulnerability := range vulnerabilities {
		if vulnerability.Suppressed {
			summary.Suppressed++
			continue
		}
		switch vulnerability.Severity {
		case storagev1alpha1.SeverityCritical:
			summary.Critical++
		case storagev1alpha1.SeverityHigh:
			summary.High++
		case storagev1alpha1.SeverityMedium:
			summary.Medium++
		case storagev1alpha1.SeverityLow:
			summary.Low++
		case storagev1alpha1.SeverityUnknown:
			summary.Unknown++
		default:
			summary.Unknown++
		}
	}
	return summary
}

// severityRank maps severity labels to a numeric rank (higher = more severe).
func severityRank(severity string) int {
	switch severity {
	case storagev1alpha1.SeverityCritical:
		return 4
	case storagev1alpha1.SeverityHigh:
		return 3
	case storagev1alpha1.SeverityMedium:
		return 2
	case storagev1alpha1.SeverityLow:
		return 1
	case storagev1alpha1.SeverityUnknown:
		return 0
	default:
		return 0
	}
}

// collectSimplifiedVulnerabilitiesFromWorkload flattens, deduplicates, and sorts
// vulnerabilities from a workload container's vulnerability reports.
func collectSimplifiedVulnerabilitiesFromWorkload(reports []storagev1alpha1.WorkloadScanVulnerabilityReport) ([]simplifiedVulnerability, error) {
	seen := make(map[string]simplifiedVulnerability)

	for _, report := range reports {
		for _, result := range report.Report.Results {
			for _, vulnerability := range result.Vulnerabilities {
				if _, exists := seen[vulnerability.CVE]; exists {
					continue
				}
				simplified, err := simplifyVulnerability(vulnerability)
				if err != nil {
					return nil, err
				}
				seen[vulnerability.CVE] = simplified
			}
		}
	}

	vulnerabilities := make([]simplifiedVulnerability, 0, len(seen))
	for _, vulnerability := range seen {
		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	sortVulnerabilities(vulnerabilities)

	return vulnerabilities, nil
}

// getClusterScoped retrieves a cluster-scoped resource by name and returns it as JSON.
func getClusterScoped[O client.Object](ctx context.Context, s *Server, obj O, name string) (*mcp.CallToolResult, any, error) {
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: name}, obj); err != nil {
		return toolError("getting resource: %v", err)
	}
	return jsonResult(obj)
}

// listNamespaced retrieves a list of namespaced resources, optionally filtered by namespace, and returns it as JSON.
func listNamespaced[L client.ObjectList](ctx context.Context, s *Server, list L, namespace string) (*mcp.CallToolResult, any, error) {
	opts := []client.ListOption{}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := s.client.List(ctx, list, opts...); err != nil {
		return toolError("listing resources: %v", err)
	}
	return jsonResult(list)
}

// getNamespaced retrieves a namespaced resource by name and namespace, returning it as JSON.
func getNamespaced[O client.Object](ctx context.Context, s *Server, obj O, name, namespace string) (*mcp.CallToolResult, any, error) {
	if err := s.client.Get(ctx, k8stypes.NamespacedName{Name: name, Namespace: namespace}, obj); err != nil {
		return toolError("getting resource: %v", err)
	}
	return jsonResult(obj)
}

// jsonResult serializes obj to JSON and returns it as a text content result.
func jsonResult(obj any) (*mcp.CallToolResult, any, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

// toolError returns a tool-level error.
func toolError(format string, args ...any) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf(format, args...)},
		},
		IsError: true,
	}, nil, nil
}
