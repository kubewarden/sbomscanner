package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

type ScanArtifactRepository struct {
	table          string
	artifactsTable string
	newFunc        func() runtime.Object
}

var _ Repository = &ScanArtifactRepository{}

func NewScanArtifactRepository(table, artifactsTable string, newFunc func() runtime.Object) *ScanArtifactRepository {
	return &ScanArtifactRepository{
		table:          table,
		artifactsTable: artifactsTable,
		newFunc:        newFunc,
	}
}

func (r *ScanArtifactRepository) Create(ctx context.Context, tx pgx.Tx, obj runtime.Object) error {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get object metadata: %w", err)
	}

	imageAccessor, ok := obj.(v1alpha1.ImageMetadataAccessor)
	if !ok {
		return fmt.Errorf("expected object to implement ImageMetadataAccessor, got %T", obj)
	}
	sha := imageAccessor.GetImageMetadata().Digest

	bytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	// Insert the base artifact first (or do nothing if it already exists)
	artifactQuery, artifactArgs, err := psql.Insert(
		im.Into(psql.Quote(r.artifactsTable), "sha", "object"),
		im.Values(
			psql.Arg(sha),
			psql.Arg(bytes),
		),
		im.OnConflict("sha").DoNothing(),
	).Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build artifact insert query: %w", err)
	}

	_, err = tx.Exec(ctx, artifactQuery, artifactArgs...)
	if err != nil {
		return fmt.Errorf("failed to execute artifact insert: %w", err)
	}

	// Insert the scan artifact
	query, args, err := psql.Insert(
		im.Into(psql.Quote(r.table), "name", "namespace", "metadata", "image_metadata", "sha"),
		im.Values(
			psql.Arg(accessor.GetName()),
			psql.Arg(accessor.GetNamespace()),
			psql.Raw("?::jsonb->'metadata'", bytes),
			psql.Raw("?::jsonb->'imageMetadata'", bytes),
			psql.Arg(sha),
		),
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

func (r *ScanArtifactRepository) Delete(ctx context.Context, tx pgx.Tx, name, namespace string) (runtime.Object, error) {
	// First get the object with joined data
	obj, err := r.Get(ctx, tx, name, namespace)
	if err != nil {
		return nil, err
	}

	imageAccessor, ok := obj.(v1alpha1.ImageMetadataAccessor)
	if !ok {
		return nil, fmt.Errorf("expected object to implement ImageMetadataAccessor, got %T", obj)
	}
	sha := imageAccessor.GetImageMetadata().Digest

	// Delete the scan artifact
	query, args, err := psql.Delete(
		dm.From(psql.Quote(r.table)),
		dm.Where(psql.Quote("name").EQ(psql.Arg(name))),
		dm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
	).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build delete query: %w", err)
	}

	_, err = tx.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute delete: %w", err)
	}

	// Check if any other scan artifacts reference this sha
	countQuery, countArgs, err := psql.Select(
		sm.Columns("COUNT(*)"),
		sm.From(psql.Quote(r.table)),
		sm.Where(psql.Quote("sha").EQ(psql.Arg(sha))),
	).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build count query: %w", err)
	}

	var count int64
	if err := tx.QueryRow(ctx, countQuery, countArgs...).Scan(&count); err != nil {
		return nil, fmt.Errorf("failed to count remaining references: %w", err)
	}

	// If no more references, delete the artifact
	if count == 0 {
		deleteArtifactQuery, deleteArtifactArgs, err := psql.Delete(
			dm.From(psql.Quote(r.artifactsTable)),
			dm.Where(psql.Quote("sha").EQ(psql.Arg(sha))),
		).Build(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to build artifact delete query: %w", err)
		}

		_, err = tx.Exec(ctx, deleteArtifactQuery, deleteArtifactArgs...)
		if err != nil {
			return nil, fmt.Errorf("failed to delete unreferenced artifact: %w", err)
		}
	}

	return obj, nil
}

func (r *ScanArtifactRepository) Get(ctx context.Context, db Querier, name, namespace string) (runtime.Object, error) {
	query, args, err := psql.Select(
		sm.Columns(r.objectColumn()),
		sm.From(psql.Quote(r.table)),
		sm.InnerJoin(psql.Quote(r.artifactsTable)).On(
			psql.Quote(r.table, "sha").EQ(psql.Quote(r.artifactsTable, "sha")),
		),
		sm.Where(psql.Quote(r.table, "name").EQ(psql.Arg(name))),
		sm.Where(psql.Quote(r.table, "namespace").EQ(psql.Arg(namespace))),
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

	obj := r.newFunc()
	if err := json.Unmarshal(bytes, obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return obj, nil
}

func (r *ScanArtifactRepository) List(ctx context.Context, db Querier, namespace string, opts storage.ListOptions) ([]runtime.Object, string, error) {
	qb := psql.Select(
		sm.Columns(fmt.Sprintf("%s.id", r.table)),
		sm.Columns(r.objectColumn()),
		sm.From(psql.Quote(r.table)),
		sm.InnerJoin(psql.Quote(r.artifactsTable)).On(
			psql.Quote(r.table, "sha").EQ(psql.Quote(r.artifactsTable, "sha")),
		),
		sm.OrderBy(psql.Quote(r.table, "id")),
	)

	return list(ctx, db, qb, namespace, opts, r.newFunc)
}

func (r *ScanArtifactRepository) Update(ctx context.Context, tx pgx.Tx, name, namespace string, obj runtime.Object) error {
	imageAccessor, ok := obj.(v1alpha1.ImageMetadataAccessor)
	if !ok {
		return fmt.Errorf("expected object to implement ImageMetadataAccessor, got %T", obj)
	}
	sha := imageAccessor.GetImageMetadata().Digest

	bytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	// Update the scan artifact metadata first to check existence
	query, args, err := psql.Update(
		um.Table(psql.Quote(r.table)),
		um.SetCol("metadata").To(psql.Raw("?::jsonb->'metadata'", bytes)),
		um.SetCol("image_metadata").To(psql.Raw("?::jsonb->'imageMetadata'", bytes)),
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

	// Update the artifact object
	artifactQuery, artifactArgs, err := psql.Update(
		um.Table(psql.Quote(r.artifactsTable)),
		um.SetCol("object").To(psql.Arg(bytes)),
		um.Where(psql.Quote("sha").EQ(psql.Arg(sha))),
	).Build(ctx)
	if err != nil {
		return fmt.Errorf("failed to build artifact update query: %w", err)
	}

	_, err = tx.Exec(ctx, artifactQuery, artifactArgs...)
	if err != nil {
		return fmt.Errorf("failed to execute artifact update: %w", err)
	}

	return nil
}

func (r *ScanArtifactRepository) Count(ctx context.Context, db Querier, namespace string) (int64, error) {
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

// objectColumn returns the SQL expression that reconstructs the full Kubernetes
// object by merging data from the artifacts table with metadata from the scan table.
func (r *ScanArtifactRepository) objectColumn() string {
	return fmt.Sprintf(`%s.object || jsonb_build_object(
		'metadata', (%s.object->'metadata') || %s.metadata || jsonb_build_object('resourceVersion', %s.object->'metadata'->>'resourceVersion'),
		'imageMetadata', %s.image_metadata
	) AS object`,
		r.artifactsTable,
		r.artifactsTable, r.table, r.artifactsTable,
		r.table,
	)
}
