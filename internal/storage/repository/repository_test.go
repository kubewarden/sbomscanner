package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

type repositoryTestSuite struct {
	suite.Suite
	pgContainer       *postgres.PostgresContainer
	db                *pgxpool.Pool
	genericObjectRepo *GenericObjectRepository
}

func TestRepositoryTestSuite(t *testing.T) {
	suite.Run(t, &repositoryTestSuite{})
}

func (suite *repositoryTestSuite) SetupSuite() {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpassword"),
		postgres.BasicWaitStrategies(),
	)
	suite.Require().NoError(err, "failed to start postgres container")
	suite.pgContainer = pgContainer

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	suite.Require().NoError(err, "failed to get connection string")

	db, err := pgxpool.New(ctx, connStr)
	suite.Require().NoError(err, "failed to create connection pool")
	suite.db = db

	_, err = suite.db.Exec(ctx, `
		CREATE TABLE generic_objects (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			object JSONB NOT NULL,
			UNIQUE (name, namespace)
		);
		CREATE TABLE sbom_artifacts (
			digest TEXT PRIMARY KEY,
			object JSONB NOT NULL
		);
		CREATE TABLE sboms (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			metadata JSONB NOT NULL,
			image_metadata JSONB NOT NULL,
			digest TEXT NOT NULL REFERENCES sbom_artifacts(digest),
			UNIQUE (name, namespace)
		);
	`)
	suite.Require().NoError(err)

	suite.genericObjectRepo = NewGenericObjectRepository("generic_objects", func() runtime.Object {
		return &storagev1alpha1.SBOM{}
	})
}

func (suite *repositoryTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}

	if suite.pgContainer != nil {
		err := suite.pgContainer.Terminate(context.Background())
		suite.Require().NoError(err, "failed to terminate postgres container")
	}
}

func (suite *repositoryTestSuite) SetupTest() {
	_, err := suite.db.Exec(context.Background(), "TRUNCATE TABLE generic_objects, sboms, sbom_artifacts CASCADE")
	suite.Require().NoError(err)
}

func (suite *repositoryTestSuite) TestCreate() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			sbom := testSBOMFactory("create-test", "default", "sha256:create-test")

			err := suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().NoError(err)

			// Verify it was created
			got, err := r.repo.Get(ctx, suite.db, "create-test", "default")
			suite.Require().NoError(err)
			suite.Equal("create-test", got.(metav1.Object).GetName())

			// Duplicate should fail
			err = suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().ErrorIs(err, ErrAlreadyExists)
		})
	}
}

func (suite *repositoryTestSuite) TestGet() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			_, err := r.repo.Get(ctx, suite.db, "get-notfound", "default")
			suite.Require().ErrorIs(err, ErrNotFound)

			sbom := testSBOMFactory("get-test", "default", "sha256:get-test")
			sbom.Labels = map[string]string{"app": "test"}

			err = suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().NoError(err)

			got, err := r.repo.Get(ctx, suite.db, "get-test", "default")
			suite.Require().NoError(err)

			gotSBOM := got.(*storagev1alpha1.SBOM)
			suite.Equal("get-test", gotSBOM.Name)
			suite.Equal("default", gotSBOM.Namespace)
			suite.Equal(map[string]string{"app": "test"}, gotSBOM.Labels)
		})
	}
}

func (suite *repositoryTestSuite) TestUpdate() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			// Update not found
			sbom := testSBOMFactory("update-notfound", "default", "sha256:update-notfound")
			err := suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Update(ctx, tx, "update-notfound", "default", sbom)
			})
			suite.Require().ErrorIs(err, ErrNotFound)

			// Create, update, verify
			sbom = testSBOMFactory("update-test", "default", "sha256:update-test")
			err = suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().NoError(err)

			sbom.Labels = map[string]string{"updated": "true"}
			err = suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Update(ctx, tx, "update-test", "default", sbom)
			})
			suite.Require().NoError(err)

			got, err := r.repo.Get(ctx, suite.db, "update-test", "default")
			suite.Require().NoError(err)
			suite.Equal(map[string]string{"updated": "true"}, got.(metav1.Object).GetLabels())
		})
	}
}

func (suite *repositoryTestSuite) TestDelete() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			_, err := suite.withTxReturn(ctx, func(tx pgx.Tx) (runtime.Object, error) {
				return r.repo.Delete(ctx, tx, "delete-notfound", "default")
			})
			suite.Require().ErrorIs(err, ErrNotFound)

			sbom := testSBOMFactory("delete-test", "default", "sha256:delete-test")
			err = suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().NoError(err)

			deleted, err := suite.withTxReturn(ctx, func(tx pgx.Tx) (runtime.Object, error) {
				return r.repo.Delete(ctx, tx, "delete-test", "default")
			})
			suite.Require().NoError(err)
			suite.Equal("delete-test", deleted.(metav1.Object).GetName())

			_, err = r.repo.Get(ctx, suite.db, "delete-test", "default")
			suite.Require().ErrorIs(err, ErrNotFound)
		})
	}
}

func (suite *repositoryTestSuite) TestList() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			// Create test data
			sbom1 := testSBOMFactory("list-test1", "default", "sha256:list-test1")
			sbom1.Labels = map[string]string{"env": "prod"}

			sbom2 := testSBOMFactory("list-test2", "default", "sha256:list-test2")
			sbom2.Labels = map[string]string{"env": "dev"}

			sbom3 := testSBOMFactory("list-test3", "other", "sha256:list-test3")

			for _, sbom := range []*storagev1alpha1.SBOM{sbom1, sbom2, sbom3} {
				err := suite.withTx(ctx, func(tx pgx.Tx) error {
					return r.repo.Create(ctx, tx, sbom)
				})
				suite.Require().NoError(err)
			}

			// List by namespace
			items, continueToken, err := r.repo.List(ctx, suite.db, "default", storage.ListOptions{})
			suite.Require().NoError(err)
			suite.Len(items, 2)
			suite.Empty(continueToken)

			// List all namespaces
			items, _, err = r.repo.List(ctx, suite.db, "", storage.ListOptions{})
			suite.Require().NoError(err)
			suite.Len(items, 3)

			// List with label selector
			labelSelector, err := labels.Parse("env=prod")
			suite.Require().NoError(err)

			items, _, err = r.repo.List(ctx, suite.db, "default", storage.ListOptions{
				Predicate: storage.SelectionPredicate{
					Label: labelSelector,
				},
			})
			suite.Require().NoError(err)
			suite.Len(items, 1)
			suite.Equal("list-test1", items[0].(metav1.Object).GetName())

			// List with field selector
			items, _, err = r.repo.List(ctx, suite.db, "default", storage.ListOptions{
				Predicate: storage.SelectionPredicate{
					Field: fields.ParseSelectorOrDie("metadata.name=list-test1"),
				},
			})
			suite.Require().NoError(err)
			suite.Len(items, 1)
			suite.Equal("list-test1", items[0].(metav1.Object).GetName())

			// List with pagination
			items, continueToken, err = r.repo.List(ctx, suite.db, "", storage.ListOptions{
				Predicate: storage.SelectionPredicate{
					Limit: 2,
				},
			})
			suite.Require().NoError(err)
			suite.Len(items, 2)
			suite.NotEmpty(continueToken)

			items, continueToken, err = r.repo.List(ctx, suite.db, "", storage.ListOptions{
				Predicate: storage.SelectionPredicate{
					Limit:    2,
					Continue: continueToken,
				},
			})
			suite.Require().NoError(err)
			suite.Len(items, 1)
			suite.Empty(continueToken)
		})
	}
}

func (suite *repositoryTestSuite) TestCount() {
	repos := []struct {
		name string
		repo Repository
	}{
		{"GenericObjectRepository", suite.genericObjectRepo},
	}

	for _, r := range repos {
		suite.Run(r.name, func() {
			ctx := context.Background()

			for i := 1; i <= 3; i++ {
				sbom := testSBOMFactory(fmt.Sprintf("count-test%d", i), "default", fmt.Sprintf("sha256:count-test%d", i))
				err := suite.withTx(ctx, func(tx pgx.Tx) error {
					return r.repo.Create(ctx, tx, sbom)
				})
				suite.Require().NoError(err)
			}

			sbom := testSBOMFactory("count-other", "other", "sha256:count-other")
			err := suite.withTx(ctx, func(tx pgx.Tx) error {
				return r.repo.Create(ctx, tx, sbom)
			})
			suite.Require().NoError(err)

			// Count by namespace
			count, err := r.repo.Count(ctx, suite.db, "default")
			suite.Require().NoError(err)
			suite.Equal(int64(3), count)

			// Count all
			count, err = r.repo.Count(ctx, suite.db, "")
			suite.Require().NoError(err)
			suite.Equal(int64(4), count)
		})
	}
}

func (suite *repositoryTestSuite) withTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := suite.db.Begin(ctx)
	if err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

func (suite *repositoryTestSuite) withTxReturn(ctx context.Context, fn func(tx pgx.Tx) (runtime.Object, error)) (runtime.Object, error) {
	tx, err := suite.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	obj, err := fn(tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}

	return obj, tx.Commit(ctx)
}

func testSBOMFactory(name, namespace, digest string) *storagev1alpha1.SBOM {
	return &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    "test-registry",
			RegistryURI: "registry-1.docker.io:5000",
			Repository:  "kubewarden/" + name,
			Tag:         "v1.0.0",
			Platform:    "linux/amd64",
			Digest:      digest,
		},
		SPDX: runtime.RawExtension{Raw: []byte(`{"test": true}`)},
	}
}
