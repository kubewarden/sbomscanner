package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/storage"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// vulnerabilityKey is used to deduplicate vulnerabilities by CVE and suppression status.
type vulnerabilityKey struct {
	cve              string
	suppressed       bool
	pkgName          string
	installedVersion string
}

// WorkloadScanReportRepository handles storage for WorkloadScanReport objects.
// Create/Update/Delete operations store the object as JSONB.
// Get/List operations populate each container's VulnerabilityReports field
// by querying the vulnerability_reports table based on ImageRef.
//
// Expected table schema:
//
//	CREATE TABLE workloadscanreports (
//	    id BIGSERIAL PRIMARY KEY,
//	    name TEXT NOT NULL,
//	    namespace TEXT NOT NULL,
//	    object JSONB NOT NULL,
//	    UNIQUE (name, namespace)
//	);
//
// CREATE INDEX IF NOT EXISTS idx_workloadscanreports_id ON workloadscanreports(id);
// CREATE INDEX IF NOT EXISTS idx_workloadscanreports_containers_gin ON workloadscanreports USING GIN ((object->'spec'->'containers') jsonb_path_ops);
type WorkloadScanReportRepository struct {
	*GenericObjectRepository

	vulnerabilityReportsTable string
	imagesTable               string
}

var _ Repository = &WorkloadScanReportRepository{}

func NewWorkloadScanReportRepository(table, vulnerabilityReportsTable, imagesTable string) *WorkloadScanReportRepository {
	return &WorkloadScanReportRepository{
		GenericObjectRepository: NewGenericObjectRepository(table, func() runtime.Object {
			return &storagev1alpha1.WorkloadScanReport{}
		}),
		vulnerabilityReportsTable: vulnerabilityReportsTable,
		imagesTable:               imagesTable,
	}
}

// Get retrieves a WorkloadScanReport and populates its container results from related tables.
func (r *WorkloadScanReportRepository) Get(ctx context.Context, db Querier, name, namespace string) (runtime.Object, error) {
	obj, err := r.GenericObjectRepository.Get(ctx, db, name, namespace)
	if err != nil {
		return nil, err
	}

	report, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return nil, fmt.Errorf("expected WorkloadScanReport, got %T", obj)
	}
	if err := r.populateContainerResults(ctx, db, report); err != nil {
		return nil, err
	}

	return report, nil
}

// List retrieves WorkloadScanReports and populates container results for each.
func (r *WorkloadScanReportRepository) List(ctx context.Context, db Querier, namespace string, opts storage.ListOptions) ([]runtime.Object, string, error) {
	objects, continueToken, err := r.GenericObjectRepository.List(ctx, db, namespace, opts)
	if err != nil {
		return nil, "", err
	}

	reports := make([]*storagev1alpha1.WorkloadScanReport, 0, len(objects))
	for _, obj := range objects {
		report, ok := obj.(*storagev1alpha1.WorkloadScanReport)
		if !ok {
			return nil, "", fmt.Errorf("expected WorkloadScanReport, got %T", obj)
		}
		reports = append(reports, report)
	}
	if err := r.populateContainerResults(ctx, db, reports...); err != nil {
		return nil, "", err
	}

	return objects, continueToken, nil
}

// FindByImageRef finds all WorkloadScanReports that have a container referencing the given image.
// It does NOT populate container results since this is used for watch event propagation, not API responses.
func (r *WorkloadScanReportRepository) FindByImageRef(
	ctx context.Context,
	db Querier,
	ref storagev1alpha1.ImageRef,
) ([]storagev1alpha1.WorkloadScanReport, error) {
	// Query using JSONB containment operator to find WorkloadScanReports
	// where any container's imageRef matches. Containment only checks that
	// the specified fields exist and match, so the container's "name" field
	// is ignored.
	refJSON, err := json.Marshal([]imageRefQuery{{ImageRef: ref}})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ref for query: %w", err)
	}

	query, args, err := psql.Select(
		sm.Columns("object"),
		sm.From(psql.Quote(r.table)),
		sm.Where(psql.Raw("object->'spec'->'containers' @> ?", string(refJSON))),
	).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var reports []storagev1alpha1.WorkloadScanReport
	for rows.Next() {
		var objectBytes []byte
		if err := rows.Scan(&objectBytes); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		var report storagev1alpha1.WorkloadScanReport
		if err := json.Unmarshal(objectBytes, &report); err != nil {
			return nil, fmt.Errorf("failed to unmarshal WorkloadScanReport: %w", err)
		}

		reports = append(reports, report)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return reports, nil
}

// imageRefQuery is used to build JSONB containment queries against containers.
type imageRefQuery struct {
	ImageRef storagev1alpha1.ImageRef `json:"imageRef"`
}

// populateContainerResults fetches images and vulnerability reports, then populates Status, Containers and Summary.
func (r *WorkloadScanReportRepository) populateContainerResults(ctx context.Context, db Querier, reports ...*storagev1alpha1.WorkloadScanReport) error {
	var containers []storagev1alpha1.ContainerRef
	seen := sets.New[storagev1alpha1.ImageRef]()
	for _, report := range reports {
		for _, container := range report.Spec.Containers {
			if !seen.Has(container.ImageRef) {
				seen.Insert(container.ImageRef)
				containers = append(containers, container)
			}
		}
	}
	if len(containers) == 0 {
		return nil
	}

	imageCounts, err := r.fetchImageCounts(ctx, db, containers)
	if err != nil {
		return fmt.Errorf("failed to fetch image counts: %w", err)
	}

	vulnReports, err := r.fetchVulnerabilityReports(ctx, db, containers)
	if err != nil {
		return fmt.Errorf("failed to fetch vulnerability reports: %w", err)
	}

	for _, report := range reports {
		if len(report.Spec.Containers) == 0 {
			continue
		}
		report.Status.ContainerStatuses = make([]storagev1alpha1.ContainerStatus, len(report.Spec.Containers))
		report.Containers = make([]storagev1alpha1.ContainerResult, len(report.Spec.Containers))

		for i, container := range report.Spec.Containers {
			ref := container.ImageRef
			matches := vulnReports[ref]
			report.Status.ContainerStatuses[i] = storagev1alpha1.ContainerStatus{
				Name:       container.Name,
				ScanStatus: r.computeScanStatus(imageCounts[ref], len(matches)),
			}
			report.Containers[i] = r.buildContainerResult(container, matches)
		}
		r.calculateSummary(report)
	}

	return nil
}

// fetchImageCounts returns the count of Image records per ImageRef.
func (r *WorkloadScanReportRepository) fetchImageCounts(ctx context.Context, db Querier, containers []storagev1alpha1.ContainerRef) (map[storagev1alpha1.ImageRef]int, error) {
	result := make(map[storagev1alpha1.ImageRef]int)

	if len(containers) == 0 {
		return result, nil
	}

	qb := psql.Select(
		sm.Columns(
			psql.Raw("object->'imageMetadata'->>'registry'"),
			psql.Raw("object->'imageMetadata'->>'repository'"),
			psql.Raw("object->'imageMetadata'->>'tag'"),
			psql.Quote("namespace"),
			"COUNT(*)",
		),
		sm.From(psql.Quote(r.imagesTable)),
	)

	qb.Apply(
		sm.Where(psql.Or(r.buildImageRefConditions(containers)...)),
		sm.GroupBy(psql.Raw("object->'imageMetadata'->>'registry'")),
		sm.GroupBy(psql.Raw("object->'imageMetadata'->>'repository'")),
		sm.GroupBy(psql.Raw("object->'imageMetadata'->>'tag'")),
		sm.GroupBy(psql.Quote("namespace")),
	)

	query, args, err := qb.Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build images query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var registry, repository, tag, namespace string
		var count int
		if err := rows.Scan(&registry, &repository, &tag, &namespace, &count); err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}

		key := storagev1alpha1.ImageRef{
			Registry:   registry,
			Namespace:  namespace,
			Repository: repository,
			Tag:        tag,
		}
		result[key] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate images: %w", err)
	}

	return result, nil
}

// fetchVulnerabilityReports returns vulnerability reports grouped by ImageRef.
func (r *WorkloadScanReportRepository) fetchVulnerabilityReports(ctx context.Context, db Querier, containers []storagev1alpha1.ContainerRef) (map[storagev1alpha1.ImageRef][]storagev1alpha1.VulnerabilityReport, error) {
	result := make(map[storagev1alpha1.ImageRef][]storagev1alpha1.VulnerabilityReport)

	if len(containers) == 0 {
		return result, nil
	}

	qb := psql.Select(
		sm.Columns("object"),
		sm.From(psql.Quote(r.vulnerabilityReportsTable)),
	)

	qb.Apply(sm.Where(psql.Or(r.buildImageRefConditions(containers)...)))

	query, args, err := qb.Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build vulnerability reports query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability reports: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var bytes []byte
		if err := rows.Scan(&bytes); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability report: %w", err)
		}

		var vulnReport storagev1alpha1.VulnerabilityReport
		if err := json.Unmarshal(bytes, &vulnReport); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vulnerability report: %w", err)
		}

		key := storagev1alpha1.ImageRef{
			Registry:   vulnReport.ImageMetadata.Registry,
			Namespace:  vulnReport.Namespace,
			Repository: vulnReport.ImageMetadata.Repository,
			Tag:        vulnReport.ImageMetadata.Tag,
		}
		result[key] = append(result[key], vulnReport)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate vulnerability reports: %w", err)
	}

	return result, nil
}

// buildImageRefConditions matches complete references, including their namespaces.
// Each array holds one field. Entries at the same position form one image reference.
// PostgreSQL's unnest combines the four arrays into rows for the lookup.
// This uses four query parameters regardless of the number of references,
// so large lists without pagination do not exceed PostgreSQL's parameter limit.
// IN returns each matching row once, even if the input repeats a reference.
func (r *WorkloadScanReportRepository) buildImageRefConditions(containers []storagev1alpha1.ContainerRef) []bob.Expression {
	namespaces := make([]string, 0, len(containers))
	registries := make([]string, 0, len(containers))
	repositories := make([]string, 0, len(containers))
	tags := make([]string, 0, len(containers))
	for _, c := range containers {
		namespaces = append(namespaces, c.ImageRef.Namespace)
		registries = append(registries, c.ImageRef.Registry)
		repositories = append(repositories, c.ImageRef.Repository)
		tags = append(tags, c.ImageRef.Tag)
	}
	return []bob.Expression{psql.Raw(`
		(namespace, object->'imageMetadata'->>'registry',
		 object->'imageMetadata'->>'repository', object->'imageMetadata'->>'tag')
		IN (SELECT refs.namespace, refs.registry, refs.repository, refs.tag
		    FROM unnest(?::text[], ?::text[], ?::text[], ?::text[])
		    AS refs(namespace, registry, repository, tag))`,
		namespaces, registries, repositories, tags)}
}

// buildContainerResult builds a ContainerResult from a ContainerRef and its vulnerability reports.
func (r *WorkloadScanReportRepository) buildContainerResult(
	container storagev1alpha1.ContainerRef,
	vulnerabilityReports []storagev1alpha1.VulnerabilityReport,
) storagev1alpha1.ContainerResult {
	workloadReports := make([]storagev1alpha1.WorkloadScanVulnerabilityReport, 0, len(vulnerabilityReports))
	for _, vr := range vulnerabilityReports {
		workloadReports = append(workloadReports, storagev1alpha1.WorkloadScanVulnerabilityReport{
			Name:          vr.ObjectMeta.Name,
			Namespace:     vr.ObjectMeta.Namespace,
			ImageMetadata: vr.ImageMetadata,
			// Each result owns its nested slices and maps, even for shared references.
			Report: *vr.Report.DeepCopy(),
		})
	}

	return storagev1alpha1.ContainerResult{
		Name:                 container.Name,
		VulnerabilityReports: workloadReports,
	}
}

// computeScanStatus determines the scan status for a container.
func (r *WorkloadScanReportRepository) computeScanStatus(imageCount, vulnReportCount int) storagev1alpha1.ScanStatus {
	if imageCount == 0 {
		return storagev1alpha1.ScanStatusWaitingForScan
	}
	if vulnReportCount < imageCount {
		return storagev1alpha1.ScanStatusScanInProgress
	}
	return storagev1alpha1.ScanStatusScanComplete
}

// calculateSummary computes the aggregated vulnerability summary for the report.
// For each container, vulnerabilities are deduplicated by CVE (same CVE across platforms counts as 1).
// The counts are then summed across all containers.
// NOTE: PURL identfiers in VEX files can target specific platforms, so a CVE might be suppressed for one platform but not another.
// See: https://github.com/package-url/purl-spec/blob/5b81fb0b3c7acb17f8c32560f5d9f401fe2a6637/types-doc/otp-definition.md?plain=1#L47
func (r *WorkloadScanReportRepository) calculateSummary(report *storagev1alpha1.WorkloadScanReport) {
	report.Summary = storagev1alpha1.Summary{}

	for _, container := range report.Containers {
		seen := sets.New[vulnerabilityKey]()

		for _, vulnReport := range container.VulnerabilityReports {
			for _, result := range vulnReport.Report.Results {
				for _, vuln := range result.Vulnerabilities {
					key := vulnerabilityKey{
						cve:              vuln.CVE,
						suppressed:       vuln.Suppressed,
						pkgName:          vuln.PackageName,
						installedVersion: vuln.InstalledVersion,
					}
					if seen.Has(key) {
						continue
					}
					seen.Insert(key)
					report.Summary.Add(vuln)
				}
			}
		}
	}
}
