package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	apistorage "k8s.io/apiserver/pkg/storage"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

const (
	nodeSBOMResourceSingularName = "nodesbom"
	nodeSBOMResourcePluralName   = "nodesboms"
)

const createNodeSBOMTableSQL = `
CREATE TABLE IF NOT EXISTS nodesboms (
    name VARCHAR(253) NOT NULL,
    namespace VARCHAR(253) NOT NULL,
    object JSONB NOT NULL,
    PRIMARY KEY (name, namespace)
);

ALTER TABLE nodesboms ADD COLUMN IF NOT EXISTS id BIGSERIAL;
CREATE INDEX IF NOT EXISTS idx_nodesboms_id ON nodesboms(id);
`

// NewNodeSBOMStore returns a store registry that will work against API services.
func NewNodeSBOMStore(
	scheme *runtime.Scheme,
	optsGetter generic.RESTOptionsGetter,
	db *pgxpool.Pool,
	nc *nats.Conn,
	logger *slog.Logger,
) (*registry.Store, []manager.Runnable, error) {
	strategy := newNodeSBOMStrategy(scheme)
	newFunc := func() runtime.Object { return &storagev1alpha1.NodeSBOM{} }
	newListFunc := func() runtime.Object { return &storagev1alpha1.NodeSBOMList{} }

	watchBroadcaster := watch.NewBroadcaster(1000, watch.WaitIfChannelFull)
	natsBroadcaster := newNatsBroadcaster(nc, nodeSBOMResourcePluralName, watchBroadcaster, TransformStripNodeSBOM, logger)

	repo := repository.NewGenericObjectRepository(nodeSBOMResourcePluralName, newFunc)

	store := &store{
		db:          db,
		repository:  repo,
		broadcaster: natsBroadcaster,
		newFunc:     newFunc,
		newListFunc: newListFunc,
		logger:      logger.With("store", nodeSBOMResourceSingularName),
	}

	natsWatcher := newNatsWatcher(nc, nodeSBOMResourcePluralName, watchBroadcaster, store, logger)

	registryStore := &registry.Store{
		NewFunc:                   newFunc,
		NewListFunc:               newListFunc,
		PredicateFunc:             nodeSBOMMatcher,
		DefaultQualifiedResource:  storagev1alpha1.Resource(nodeSBOMResourcePluralName),
		SingularQualifiedResource: storagev1alpha1.Resource(nodeSBOMResourceSingularName),
		Storage: registry.DryRunnableStorage{
			Storage: store,
		},
		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,
		TableConvertor: &nodeSBOMTableConvertor{},
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: getNodeSBOMAttrs}
	if err := registryStore.CompleteWithOptions(options); err != nil {
		return nil, nil, fmt.Errorf("unable to complete store with options: %w", err)
	}

	return registryStore, []manager.Runnable{natsWatcher}, nil
}

// nodeSBOMMatcher returns a storage.SelectionPredicate that matches the given label and field selectors.
func nodeSBOMMatcher(label labels.Selector, field fields.Selector) apistorage.SelectionPredicate {
	return apistorage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: getNodeSBOMAttrs,
	}
}

// getNodeSBOMAttrs returns labels and fields that can be used in a selection.
func getNodeSBOMAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get metadata: %w", err)
	}

	nodeMetadataAccessor, ok := obj.(storagev1alpha1.NodeMetadataAccessor)
	if !ok {
		return nil, nil, errors.New("object does not implement NodeMetadataAccessor")
	}

	selectableMetadata := fields.Set{
		"metadata.name":      objMeta.GetName(),
		"metadata.namespace": objMeta.GetNamespace(),
	}

	selectableFields := fields.Set{
		"nodeMetadata.platform": nodeMetadataAccessor.GetNodeMetadata().Platform,
	}

	return labels.Set(objMeta.GetLabels()), generic.MergeFieldsSets(selectableMetadata, selectableFields), nil
}

type nodeSBOMTableConvertor struct{}

func (c *nodeSBOMTableConvertor) ConvertToTable(_ context.Context, obj runtime.Object, _ runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: nodeMetadataTableColumns(),
		Rows:              []metav1.TableRow{},
	}

	var nodeSBOMs []storagev1alpha1.NodeSBOM
	switch t := obj.(type) {
	case *storagev1alpha1.NodeSBOMList:
		nodeSBOMs = t.Items
	case *storagev1alpha1.NodeSBOM:
		nodeSBOMs = []storagev1alpha1.NodeSBOM{*t}
	default:
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	for _, nodeSBOM := range nodeSBOMs {
		row := metav1.TableRow{
			Object: runtime.RawExtension{Object: &nodeSBOM},
			Cells:  nodeMetadataTableRowCells(nodeSBOM.Name, &nodeSBOM),
		}
		table.Rows = append(table.Rows, row)
	}

	return table, nil
}

func nodeMetadataTableColumns() []metav1.TableColumnDefinition {
	return []metav1.TableColumnDefinition{
		{Name: "Name", Type: "string", Description: "Name"},
		{Name: "Platform", Type: "string", Description: "Node platform"},
	}
}

func nodeMetadataTableRowCells(name string, obj storagev1alpha1.NodeMetadataAccessor) []interface{} {
	nodeMeta := obj.GetNodeMetadata()
	return []interface{}{
		name,
		nodeMeta.Platform,
	}
}
