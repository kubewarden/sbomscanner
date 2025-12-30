package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"
)

var (
	// ErrAlreadyExists is returned when an object already exists in storage.
	ErrAlreadyExists = errors.New("object already exists")
	// ErrNotFound is returned when an object is not found in storage.
	ErrNotFound = errors.New("object not found")
)

// Querier provides a common interface over pgxpool.Pool and pgx.Tx for executing queries.
// This abstraction is not provided by pgx by design; see https://github.com/jackc/pgx/issues/1188
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository handles raw object storage operations.
type Repository interface {
	// Create creates the given object in storage.
	// Returns an error if the object already exists.
	// Requires a transaction.
	Create(ctx context.Context, tx pgx.Tx, obj runtime.Object) error
	// Delete deletes the object with the given name and namespace from storage.
	// Returns an error if the object does not exist.
	// Requires a transaction.
	Delete(ctx context.Context, tx pgx.Tx, name, namespace string) (runtime.Object, error)
	// Get retrieves the object with the given name and namespace from storage.
	// Returns an error if the object does not exist.
	Get(ctx context.Context, db Querier, name, namespace string) (runtime.Object, error)
	// List lists objects in the given namespace with the provided list options.
	// It also returns a continue token for pagination.
	List(ctx context.Context, db Querier, namespace string, opts storage.ListOptions) ([]runtime.Object, string, error)
	// Update updates the given object in storage.
	// Returns an error if the object does not exist. Requires a transaction.
	Update(ctx context.Context, tx pgx.Tx, name, namespace string, obj runtime.Object) error
	// Count returns the number of objects.
	// If namespace is not empty, it counts only objects in that namespace.
	Count(ctx context.Context, db Querier, namespace string) (int64, error)
}
