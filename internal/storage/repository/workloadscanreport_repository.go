package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/storage"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// WorkloadScanReportRepository handles storage for WorkloadScanReport objects.
// Create/Update/Delete operations store the object as JSONB.
// Get/List operations populate each container's VulnerabilityReports field
// by querying the vulnerability_reports table based on VulnerabilityReportRef.
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
type WorkloadScanReportRepository struct {
	table                     string
	vulnerabilityReportsTable string
	imagesTable               string
}

const (
	// imageLabelPrefix is the label prefix used to track image UIDs associated with a WorkloadScanReport.
	imageLabelPrefix = "images.sbomscanner.kubewarden.io"
	imageLabelValue  = "in-use"
)

var _ Repository = &WorkloadScanReportRepository{}

func NewWorkloadScanReportRepository(table, vulnerabilityReportsTable, imagesTable string) *WorkloadScanReportRepository {
	return &WorkloadScanReportRepository{
		table:                     table,
		vulnerabilityReportsTable: vulnerabilityReportsTable,
		imagesTable:               imagesTable,
	}
}

func (r *WorkloadScanReportRepository) Create(ctx context.Context, tx pgx.Tx, obj runtime.Object) error {
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get object metadata: %w", err)
	}

	report, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return fmt.Errorf("expected WorkloadScanReport, got %T", obj)
	}

	// Populate image labels before storing
	if err := r.populateImageLabels(ctx, tx, report); err != nil {
		return fmt.Errorf("failed to populate image labels: %w", err)
	}

	bytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	query, args, err := psql.Insert(
		im.Into(psql.Quote(r.table), "name", "namespace", "object"),
		im.Values(psql.Arg(objMeta.GetName()), psql.Arg(objMeta.GetNamespace()), psql.Arg(bytes)),
		im.OnConflict().DoNothing(),
	).Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build insert query: %w", err)
	}

	result, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute insert: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrAlreadyExists
	}

	return nil
}

func (r *WorkloadScanReportRepository) Delete(ctx context.Context, tx pgx.Tx, name, namespace string) (runtime.Object, error) {
	query, args, err := psql.Delete(
		dm.From(psql.Quote(r.table)),
		dm.Where(psql.Quote("name").EQ(psql.Arg(name))),
		dm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		dm.Returning("object"),
	).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build delete query: %w", err)
	}

	var bytes []byte
	err = tx.QueryRow(ctx, query, args...).Scan(&bytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to execute delete: %w", err)
	}

	var report storagev1alpha1.WorkloadScanReport
	if err := json.Unmarshal(bytes, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return &report, nil
}

func (r *WorkloadScanReportRepository) Get(ctx context.Context, db Querier, name, namespace string) (runtime.Object, error) {
	query, args, err := psql.Select(
		sm.Columns("object"),
		sm.From(psql.Quote(r.table)),
		sm.Where(psql.Quote("name").EQ(psql.Arg(name))),
		sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
	).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build select query: %w", err)
	}

	var bytes []byte
	err = db.QueryRow(ctx, query, args...).Scan(&bytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to execute select: %w", err)
	}

	var report storagev1alpha1.WorkloadScanReport
	if err := json.Unmarshal(bytes, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	// Populate VulnerabilityReports for each container
	if err := r.populateVulnerabilityReports(ctx, db, &report); err != nil {
		return nil, fmt.Errorf("failed to populate vulnerability reports: %w", err)
	}

	// Calculate summary from populated vulnerability reports
	r.calculateSummary(&report)

	return &report, nil
}

func (r *WorkloadScanReportRepository) List(ctx context.Context, db Querier, namespace string, opts storage.ListOptions) ([]runtime.Object, string, error) {
	qb := psql.Select(
		sm.From(psql.Quote(r.table)),
		sm.Columns("id", "object"),
		sm.OrderBy(psql.Quote("id")),
	)

	objects, continueToken, err := list(ctx, db, qb, namespace, opts, func() runtime.Object {
		return &storagev1alpha1.WorkloadScanReport{}
	})
	if err != nil {
		return nil, "", err
	}

	// Populate VulnerabilityReports for each WorkloadScanReport
	for _, obj := range objects {
		report := obj.(*storagev1alpha1.WorkloadScanReport)
		if err := r.populateVulnerabilityReports(ctx, db, report); err != nil {
			return nil, "", fmt.Errorf("failed to populate vulnerability reports: %w", err)
		}

		// Calculate summary from populated vulnerability reports
		r.calculateSummary(report)
	}

	return objects, continueToken, nil
}

func (r *WorkloadScanReportRepository) Update(ctx context.Context, tx pgx.Tx, name, namespace string, obj runtime.Object) error {
	report, ok := obj.(*storagev1alpha1.WorkloadScanReport)
	if !ok {
		return fmt.Errorf("expected WorkloadScanReport, got %T", obj)
	}

	// Populate image labels before storing
	if err := r.populateImageLabels(ctx, tx, report); err != nil {
		return fmt.Errorf("failed to populate image labels: %w", err)
	}

	bytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	query, args, err := psql.Update(
		um.Table(psql.Quote(r.table)),
		um.SetCol("object").To(psql.Arg(bytes)),
		um.Where(psql.Quote("name").EQ(psql.Arg(name))),
		um.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
	).Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build update query: %w", err)
	}

	result, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute update: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

func (r *WorkloadScanReportRepository) Count(ctx context.Context, db Querier, namespace string) (int64, error) {
	queryBuilder := psql.Select(
		sm.Columns("COUNT(*)"),
		sm.From(psql.Quote(r.table)),
	)

	if namespace != "" {
		queryBuilder.Apply(
			sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		)
	}

	query, args, err := queryBuilder.Build(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to build count query: %w", err)
	}

	var count int64
	if err := db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	return count, nil
}

// populateVulnerabilityReports queries the vulnerability_reports table and populates
// each container's VulnerabilityReports field based on matching VulnerabilityReportRef.
func (r *WorkloadScanReportRepository) populateVulnerabilityReports(ctx context.Context, db Querier, report *storagev1alpha1.WorkloadScanReport) error {
	if len(report.Containers) == 0 {
		return nil
	}

	// Collect unique refs to batch query
	type refKey struct {
		Registry   string
		Namespace  string
		Repository string
		Tag        string
	}
	refs := make(map[refKey]struct{})
	for _, container := range report.Containers {
		ref := container.VulnerabilityReportRef
		refs[refKey{
			Registry:   ref.Registry,
			Namespace:  ref.Namespace,
			Repository: ref.Repository,
			Tag:        ref.Tag,
		}] = struct{}{}
	}

	// Build a query that matches any of the refs using OR conditions
	// Each ref matches on: imageMetadata.registry, metadata.namespace, imageMetadata.repository, imageMetadata.tag
	qb := psql.Select(
		sm.Columns("object"),
		sm.From(psql.Quote(r.vulnerabilityReportsTable)),
	)

	var orConditions []bob.Expression
	for ref := range refs {
		condition := psql.And(
			psql.Raw("object->'imageMetadata'->>'registry' = ?", ref.Registry),
			psql.Raw("object->'metadata'->>'namespace' = ?", ref.Namespace),
			psql.Raw("object->'imageMetadata'->>'repository' = ?", ref.Repository),
			psql.Raw("object->'imageMetadata'->>'tag' = ?", ref.Tag),
		)
		orConditions = append(orConditions, condition)
	}

	if len(orConditions) > 0 {
		qb.Apply(sm.Where(psql.Or(orConditions...)))
	}

	query, args, err := qb.Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build vulnerability reports query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to query vulnerability reports: %w", err)
	}
	defer rows.Close()

	// Group vulnerability reports by ref
	vulnReportsByRef := make(map[refKey][]storagev1alpha1.VulnerabilityReport)
	for rows.Next() {
		var bytes []byte
		if err := rows.Scan(&bytes); err != nil {
			return fmt.Errorf("failed to scan vulnerability report: %w", err)
		}

		var vulnReport storagev1alpha1.VulnerabilityReport
		if err := json.Unmarshal(bytes, &vulnReport); err != nil {
			return fmt.Errorf("failed to unmarshal vulnerability report: %w", err)
		}

		key := refKey{
			Registry:   vulnReport.ImageMetadata.Registry,
			Namespace:  vulnReport.Namespace,
			Repository: vulnReport.ImageMetadata.Repository,
			Tag:        vulnReport.ImageMetadata.Tag,
		}
		vulnReportsByRef[key] = append(vulnReportsByRef[key], vulnReport)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iterate vulnerability reports: %w", err)
	}

	// Populate each container's VulnerabilityReports
	for i := range report.Containers {
		ref := report.Containers[i].VulnerabilityReportRef
		key := refKey{
			Registry:   ref.Registry,
			Namespace:  ref.Namespace,
			Repository: ref.Repository,
			Tag:        ref.Tag,
		}
		vulnReports := vulnReportsByRef[key]
		workloadVulnReports := make([]storagev1alpha1.WorkloadScanVulnerabilityReport, 0, len(vulnReports))
		for _, vr := range vulnReports {
			workloadVulnReports = append(workloadVulnReports, storagev1alpha1.WorkloadScanVulnerabilityReport{
				ImageMetadata: vr.ImageMetadata,
				Report:        vr.Report,
			})
		}
		report.Containers[i].VulnerabilityReports = workloadVulnReports
	}

	return nil
}

// populateImageLabels queries the images table and adds labels to the report
// in the format images.sbomscanner.kubewarden.io/<uid>=in-use for each matching image.
// This is called during Create/Update so labels are persisted and can be used with label selectors.
func (r *WorkloadScanReportRepository) populateImageLabels(ctx context.Context, db Querier, report *storagev1alpha1.WorkloadScanReport) error {
	if len(report.Containers) == 0 {
		return nil
	}

	// Clear existing image labels to avoid stale references
	if report.Labels != nil {
		prefix := fmt.Sprintf("%s/", imageLabelPrefix)
		for key := range report.Labels {
			if len(key) > len(prefix) && key[:len(prefix)] == prefix {
				delete(report.Labels, key)
			}
		}
	}

	// Collect unique refs to batch query
	type refKey struct {
		Registry   string
		Namespace  string
		Repository string
		Tag        string
	}
	refs := make(map[refKey]struct{})
	for _, container := range report.Containers {
		ref := container.VulnerabilityReportRef
		refs[refKey{
			Registry:   ref.Registry,
			Namespace:  ref.Namespace,
			Repository: ref.Repository,
			Tag:        ref.Tag,
		}] = struct{}{}
	}

	// Build a query that matches any of the refs using OR conditions
	// Only select the UID since that's all we need
	qb := psql.Select(
		sm.Columns(psql.Raw("object->'metadata'->>'uid'")),
		sm.From(psql.Quote(r.imagesTable)),
	)

	var orConditions []bob.Expression
	for ref := range refs {
		condition := psql.And(
			psql.Quote("namespace").EQ(psql.Arg(ref.Namespace)),
			psql.Raw("object->'imageMetadata'->>'registry' = ?", ref.Registry),
			psql.Raw("object->'imageMetadata'->>'repository' = ?", ref.Repository),
			psql.Raw("object->'imageMetadata'->>'tag' = ?", ref.Tag),
		)
		orConditions = append(orConditions, condition)
	}

	if len(orConditions) == 0 {
		return nil
	}

	qb.Apply(sm.Where(psql.Or(orConditions...)))

	query, args, err := qb.Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build images query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()

	// Collect image UIDs and add as labels
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return fmt.Errorf("failed to scan image uid: %w", err)
		}

		if uid != "" {
			if report.Labels == nil {
				report.Labels = make(map[string]string)
			}
			labelKey := fmt.Sprintf("%s/%s", imageLabelPrefix, uid)
			report.Labels[labelKey] = imageLabelValue
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iterate images: %w", err)
	}

	return nil
}

// calculateSummary computes the aggregated vulnerability summary for the report.
// For each container, vulnerabilities are deduplicated by CVE (same CVE across platforms counts as 1).
// The counts are then summed across all containers.
func (r *WorkloadScanReportRepository) calculateSummary(report *storagev1alpha1.WorkloadScanReport) {
	report.Summary = storagev1alpha1.Summary{}

	for _, container := range report.Containers {
		// Track seen CVEs for this container to deduplicate across platforms
		seen := sets.New[string]()

		for _, vulnReport := range container.VulnerabilityReports {
			for _, result := range vulnReport.Report.Results {
				for _, vuln := range result.Vulnerabilities {
					if seen.Has(vuln.CVE) {
						continue
					}
					seen.Insert(vuln.CVE)

					if vuln.Suppressed {
						report.Summary.Suppressed++
						continue
					}

					switch strings.ToUpper(vuln.Severity) {
					case "CRITICAL":
						report.Summary.Critical++
					case "HIGH":
						report.Summary.High++
					case "MEDIUM":
						report.Summary.Medium++
					case "LOW":
						report.Summary.Low++
					default:
						report.Summary.Unknown++
					}
				}
			}
		}
	}
}
