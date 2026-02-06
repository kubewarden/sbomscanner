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

// GenericObjectRepository is a generic implementation of Repository for any Kubernetes object.
// It uses a single table to store objects as JSONB.
//
// Expected table schema:
//
//	CREATE TABLE <table_name> (
//	    id BIGSERIAL PRIMARY KEY,
//	    name TEXT NOT NULL,
//	    namespace TEXT NOT NULL,
//	    object JSONB NOT NULL,
//	    UNIQUE (name, namespace)
//	);
//
// The object column stores the full Kubernetes object including metadata.
// The id column is used for cursor-based pagination in list operations.
type GenericObjectRepository struct {
	table   string
	newFunc func() runtime.Object
}

var _ Repository = &GenericObjectRepository{}

func NewGenericObjectRepository(table string, newFunc func() runtime.Object) *GenericObjectRepository {
	return &GenericObjectRepository{
		table,
		newFunc,
	}
}

func (r *GenericObjectRepository) Create(ctx context.Context, tx pgx.Tx, obj runtime.Object) error {
	meta, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get object metadata: %w", err)
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %w", err)
	}

	query, args, err := psql.Insert(
		im.Into(psql.Quote(r.table), "name", "namespace", "object"),
		im.Values(psql.Arg(meta.GetName()), psql.Arg(meta.GetNamespace()), psql.Arg(bytes)),
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

func (r *GenericObjectRepository) Delete(ctx context.Context, tx pgx.Tx, name, namespace string) (runtime.Object, error) {
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

	obj := r.newFunc()
	if err := json.Unmarshal(bytes, obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return obj, nil
}

func (r *GenericObjectRepository) Get(ctx context.Context, db Querier, name, namespace string) (runtime.Object, error) {
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

	obj := r.newFunc()
	if err := json.Unmarshal(bytes, obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return obj, nil
}

func (r *GenericObjectRepository) List(ctx context.Context, db Querier, namespace string, opts storage.ListOptions) ([]runtime.Object, string, error) {
	qb := psql.Select(
		sm.From(psql.Quote(r.table)),
		sm.Columns("id", "object"),
		sm.OrderBy(psql.Quote("id")),
	)

	return list(ctx, db, qb, namespace, opts, r.newFunc)
}

func (r *GenericObjectRepository) Update(ctx context.Context, tx pgx.Tx, name, namespace string, obj runtime.Object) error {
	bytes, err := json.Marshal(obj)
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

func (r *GenericObjectRepository) Count(ctx context.Context, db Querier, namespace string) (int64, error) {
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
