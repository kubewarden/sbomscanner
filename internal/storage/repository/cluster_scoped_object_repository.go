package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

// ClusterScopedObjectRepository is a repository for cluster-scoped Kubernetes objects.
// Unlike GenericObjectRepository, it does not use a namespace column.
//
// Expected table schema:
//
//	CREATE TABLE <table_name> (
//	    id BIGSERIAL,
//	    name TEXT NOT NULL,
//	    object JSONB NOT NULL,
//	    PRIMARY KEY (name)
//	);
type ClusterScopedObjectRepository struct {
	table   string
	newFunc func() runtime.Object
}

var _ Repository = &ClusterScopedObjectRepository{}

func NewClusterScopedObjectRepository(table string, newFunc func() runtime.Object) *ClusterScopedObjectRepository {
	return &ClusterScopedObjectRepository{
		table,
		newFunc,
	}
}

func (r *ClusterScopedObjectRepository) Create(ctx context.Context, tx pgx.Tx, obj runtime.Object) error {
	meta, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get object metadata: %w", err)
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	query, args, err := psql.Insert(
		im.Into(psql.Quote(r.table), "name", "object"),
		im.Values(psql.Arg(meta.GetName()), psql.Arg(bytes)),
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

func (r *ClusterScopedObjectRepository) Delete(ctx context.Context, tx pgx.Tx, name, _ string) (runtime.Object, error) {
	query, args, err := psql.Delete(
		dm.From(psql.Quote(r.table)),
		dm.Where(psql.Quote("name").EQ(psql.Arg(name))),
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

	obj := r.newFunc()
	if err := json.Unmarshal(bytes, obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return obj, nil
}

func (r *ClusterScopedObjectRepository) Get(ctx context.Context, db Querier, name, _ string) (runtime.Object, error) {
	query, args, err := psql.Select(
		sm.Columns("object"),
		sm.From(psql.Quote(r.table)),
		sm.Where(psql.Quote("name").EQ(psql.Arg(name))),
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

func (r *ClusterScopedObjectRepository) List(ctx context.Context, db Querier, _ string, opts storage.ListOptions) ([]runtime.Object, string, error) {
	qb := psql.Select(
		sm.From(psql.Quote(r.table)),
		sm.Columns("id", "object"),
		sm.OrderBy(psql.Quote("id")),
	)

	// Pass empty namespace so the list helper does not filter by namespace.
	return list(ctx, db, qb, "", opts, r.newFunc)
}

func (r *ClusterScopedObjectRepository) Update(ctx context.Context, tx pgx.Tx, name, _ string, obj runtime.Object) error {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	query, args, err := psql.Update(
		um.Table(psql.Quote(r.table)),
		um.SetCol("object").To(psql.Arg(bytes)),
		um.Where(psql.Quote("name").EQ(psql.Arg(name))),
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

func (r *ClusterScopedObjectRepository) Count(ctx context.Context, db Querier, _ string) (int64, error) {
	query, args, err := psql.Select(
		sm.Columns("COUNT(*)"),
		sm.From(psql.Quote(r.table)),
	).Build(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to build count query: %w", err)
	}

	var count int64
	if err := db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to execute count query: %w", err)
	}

	return count, nil
}
