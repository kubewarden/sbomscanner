package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

const (
	sbomResourceSingularName = "sbom"
	sbomResourcePluralName   = "sboms"
)

// TODO: ID is a sequential column used for stable pagination cursors.
// We keep (name, namespace) as primary key to avoid a breaking schema change.
// Consider switching to ID as primary key when we break the schema for the deduplication feature.
const createSBOMTableSQL = `
CREATE TABLE IF NOT EXISTS sboms (
    name VARCHAR(253) NOT NULL,
    namespace VARCHAR(253) NOT NULL,
    object JSONB NOT NULL,
    PRIMARY KEY (name, namespace)
);

ALTER TABLE sboms ADD COLUMN IF NOT EXISTS id BIGSERIAL;
CREATE INDEX IF NOT EXISTS idx_sboms_id ON sboms(id);
`

// NewSBOMStore returns a store registry that will work against API services.
func NewSBOMStore(
	scheme *runtime.Scheme,
	optsGetter generic.RESTOptionsGetter,
	db *pgxpool.Pool,
	nc *nats.Conn,
	logger *slog.Logger,
) (*registry.Store, []manager.Runnable, error) {
	strategy := newSBOMStrategy(scheme)
	newFunc := func() runtime.Object { return &storagev1alpha1.SBOM{} }
	newListFunc := func() runtime.Object { return &storagev1alpha1.SBOMList{} }

	watchBroadcaster := watch.NewBroadcaster(1000, watch.WaitIfChannelFull)
	natsBroadcaster := newNatsBroadcaster(nc, sbomResourcePluralName, watchBroadcaster, TransformStripSBOM, logger)

	repo := repository.NewGenericObjectRepository(sbomResourcePluralName, newFunc)

	store := &store{
		db:          db,
		repository:  repo,
		broadcaster: natsBroadcaster,
		newFunc:     newFunc,
		newListFunc: newListFunc,
		logger:      logger.With("store", sbomResourceSingularName),
	}

	natsWatcher := newNatsWatcher(nc, sbomResourcePluralName, watchBroadcaster, store, logger)

	registryStore := &registry.Store{
		NewFunc:                   newFunc,
		NewListFunc:               newListFunc,
		PredicateFunc:             matcher,
		DefaultQualifiedResource:  storagev1alpha1.Resource(sbomResourcePluralName),
		SingularQualifiedResource: storagev1alpha1.Resource(sbomResourceSingularName),
		Storage: registry.DryRunnableStorage{
			Storage: store,
		},
		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,
		TableConvertor: &sbomTableConvertor{},
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: getAttrs}
	if err := registryStore.CompleteWithOptions(options); err != nil {
		return nil, nil, fmt.Errorf("unable to complete store with options: %w", err)
	}

	return registryStore, []manager.Runnable{natsWatcher}, nil
}

type sbomTableConvertor struct{}

func (c *sbomTableConvertor) ConvertToTable(_ context.Context, obj runtime.Object, _ runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: imageMetadataTableColumns(),
		Rows:              []metav1.TableRow{},
	}

	// Handle both single object and list
	var sboms []storagev1alpha1.SBOM
	switch t := obj.(type) {
	case *storagev1alpha1.SBOMList:
		sboms = t.Items
	case *storagev1alpha1.SBOM:
		sboms = []storagev1alpha1.SBOM{*t}
	default:
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	for _, sbom := range sboms {
		row := metav1.TableRow{
			Object: runtime.RawExtension{Object: &sbom},
			Cells:  imageMetadataTableRowCells(sbom.Name, &sbom),
		}
		table.Rows = append(table.Rows, row)
	}

	return table, nil
}
