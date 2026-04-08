package mcp

import (
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

type namespacedListArgs struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"optional namespace to filter by; if empty, list across all namespaces"`
}

type namespacedGetArgs struct {
	Name      string `json:"name" jsonschema:"name of the resource"`
	Namespace string `json:"namespace" jsonschema:"namespace of the resource"`
}

type clusterGetArgs struct {
	Name string `json:"name" jsonschema:"name of the resource"`
}

type registryCreateArgs struct {
	Name         string                `json:"name" jsonschema:"name of the registry"`
	Namespace    string                `json:"namespace" jsonschema:"namespace of the registry"`
	URI          string                `json:"uri" jsonschema:"registry host and optional port, no repository path (e.g. ghcr.io, registry-1.docker.io, myregistry.example.com:5000)"`
	CatalogType  string                `json:"catalogType" jsonschema:"catalog type (OCIDistribution or NoCatalog)"`
	Insecure     bool                  `json:"insecure,omitempty" jsonschema:"allow insecure connections to the registry"`
	Repositories []v1alpha1.Repository `json:"repositories,omitempty" jsonschema:"list of repositories to scan; each name is the path without the registry hostname (e.g. my-org/my-app)"`
}

type registryUpdateArgs struct {
	Name         string                `json:"name" jsonschema:"name of the registry to update"`
	Namespace    string                `json:"namespace" jsonschema:"namespace of the registry"`
	URI          *string               `json:"uri,omitempty" jsonschema:"new registry host and optional port, no repository path (e.g. ghcr.io, registry-1.docker.io, myregistry.example.com:5000)"`
	CatalogType  *string               `json:"catalogType,omitempty" jsonschema:"new catalog type (OCIDistribution or NoCatalog)"`
	Insecure     *bool                 `json:"insecure,omitempty" jsonschema:"allow insecure connections to the registry"`
	Repositories []v1alpha1.Repository `json:"repositories,omitempty" jsonschema:"list of repositories to scan; replaces existing list; each repository name is the path without the registry hostname"`
}

type scanJobCreateArgs struct {
	Name      string `json:"name" jsonschema:"name of the scan job"`
	Namespace string `json:"namespace" jsonschema:"namespace of the scan job"`
	Registry  string `json:"registry" jsonschema:"name of the registry to scan (must be in the same namespace)"`
}

type vexHubCreateArgs struct {
	Name    string `json:"name" jsonschema:"name of the VEXHub"`
	URL     string `json:"url" jsonschema:"URL of the VEXHub repository"`
	Enabled bool   `json:"enabled,omitempty" jsonschema:"whether the VEXHub is enabled for processing"`
}

type vexHubUpdateArgs struct {
	Name    string  `json:"name" jsonschema:"name of the VEXHub to update"`
	URL     *string `json:"url,omitempty" jsonschema:"new URL of the VEXHub repository"`
	Enabled *bool   `json:"enabled,omitempty" jsonschema:"whether the VEXHub is enabled for processing"`
}

type emptyArgs struct{}

type imageListItem struct {
	Name       string                  `json:"name"`
	Namespace  string                  `json:"namespace"`
	Registry   string                  `json:"registry"`
	Repository string                  `json:"repository"`
	Tag        string                  `json:"tag"`
	Total      int                     `json:"total"`
	Summary    storagev1alpha1.Summary `json:"summary"`
}

type workloadListItem struct {
	ReportName   string                  `json:"reportName"`
	Namespace    string                  `json:"namespace"`
	WorkloadName string                  `json:"workloadName"`
	WorkloadKind string                  `json:"workloadKind"`
	Total        int                     `json:"total"`
	Summary      storagev1alpha1.Summary `json:"summary"`
}

type simplifiedVulnerability struct {
	CVE          string  `json:"cve"`
	Link         string  `json:"link"`
	CVSSScore    float64 `json:"cvssScore"`
	Severity     string  `json:"severity"`
	Critical     bool    `json:"critical"`
	FixAvailable bool    `json:"fixAvailable"`
	Suppressed   bool    `json:"suppressed"`
	Package      string  `json:"package"`
}

type imageVulnerabilitiesResponse struct {
	Registry        string                    `json:"registry"`
	Repository      string                    `json:"repository"`
	Tag             string                    `json:"tag"`
	Vulnerabilities []simplifiedVulnerability `json:"vulnerabilities"`
}

type imageVulnerabilitySummaryResponse struct {
	Registry           string                    `json:"registry"`
	Repository         string                    `json:"repository"`
	Tag                string                    `json:"tag"`
	Total              int                       `json:"total"`
	Summary            storagev1alpha1.Summary   `json:"summary"`
	TopVulnerabilities []simplifiedVulnerability `json:"topVulnerabilities"`
}

type containerVulnerabilitySummary struct {
	Container          string                    `json:"container"`
	Total              int                       `json:"total"`
	Summary            storagev1alpha1.Summary   `json:"summary"`
	TopVulnerabilities []simplifiedVulnerability `json:"topVulnerabilities"`
}

type workloadVulnerabilitySummaryResponse struct {
	Workload   string                          `json:"workload"`
	Total      int                             `json:"total"`
	Summary    storagev1alpha1.Summary         `json:"summary"`
	Containers []containerVulnerabilitySummary `json:"containers"`
}

type containerVulnerabilities struct {
	Container       string                    `json:"container"`
	Vulnerabilities []simplifiedVulnerability `json:"vulnerabilities"`
}

type workloadVulnerabilitiesResponse struct {
	Workload   string                     `json:"workload"`
	Containers []containerVulnerabilities `json:"containers"`
}
