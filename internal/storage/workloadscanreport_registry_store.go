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
	workloadScanReportResourceSingularName = "workloadscanreport"
	workloadScanReportResourcePluralName   = "workloadscanreports"
)

const createWorkloadScanReportTableSQL = `
CREATE TABLE IF NOT EXISTS workloadscanreports (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(253) NOT NULL,
    namespace VARCHAR(253) NOT NULL,
    object JSONB NOT NULL,
    UNIQUE (name, namespace)
);
CREATE INDEX IF NOT EXISTS idx_workloadscanreports_id ON workloadscanreports(id);
CREATE INDEX IF NOT EXISTS idx_workloadscanreports_containers_gin ON workloadscanreports USING GIN ((object->'spec'->'containers') jsonb_path_ops);
`

func NewWorkloadScanReportStore(
	scheme *runtime.Scheme,
	optsGetter generic.RESTOptionsGetter,
	db *pgxpool.Pool,
	nc *nats.Conn,
	logger *slog.Logger,
) (*RegistryStoreWithWatchers, error) {
	strategy := newWorkloadScanReportStrategy(scheme)

	newFunc := func() runtime.Object { return &storagev1alpha1.WorkloadScanReport{} }
	newListFunc := func() runtime.Object { return &storagev1alpha1.WorkloadScanReportList{} }

	repo := repository.NewWorkloadScanReportRepository(workloadScanReportResourcePluralName, vulnerabilityReportResourcePluralName, imageResourcePluralName)

	watchBroadcaster := watch.NewBroadcaster(1000, watch.WaitIfChannelFull)
	natsBroadcaster := newNatsBroadcaster(nc, workloadScanReportResourcePluralName, watchBroadcaster, func(obj any) (any, error) {
		return obj, nil
	}, logger)

	store := &store{
		db:          db,
		repository:  repo,
		broadcaster: natsBroadcaster,
		newFunc:     newFunc,
		newListFunc: newListFunc,
		logger:      logger.With("store", workloadScanReportResourceSingularName),
	}

	natsWatcher := newNatsWatcher(nc, workloadScanReportResourcePluralName, watchBroadcaster, store, logger)

	workloadScanReportWatcher := newWorkloadScanReportWatcher(
		nc,
		db,
		workloadScanReportResourcePluralName,
		natsBroadcaster,
		store,
		logger,
	)

	registryStore := &registry.Store{
		NewFunc:                   newFunc,
		NewListFunc:               newListFunc,
		PredicateFunc:             matcher,
		DefaultQualifiedResource:  storagev1alpha1.Resource(workloadScanReportResourcePluralName),
		SingularQualifiedResource: storagev1alpha1.Resource(workloadScanReportResourceSingularName),
		Storage: registry.DryRunnableStorage{
			Storage: store,
		},
		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,
		TableConvertor: &workloadScanReportTableConvertor{},
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: getAttrs}
	if err := registryStore.CompleteWithOptions(options); err != nil {
		return nil, fmt.Errorf("unable to complete store with options: %w", err)
	}

	return &RegistryStoreWithWatchers{
		Store:    registryStore,
		Watchers: []manager.Runnable{natsWatcher, workloadScanReportWatcher},
	}, nil
}

type workloadScanReportTableConvertor struct{}

func (c *workloadScanReportTableConvertor) ConvertToTable(_ context.Context, obj runtime.Object, _ runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Description: "Name of the workload scan report", Format: "name"},
			{Name: "Namespace", Type: "string", Description: "Namespace of the workload scan report"},
			{Name: "Containers", Type: "integer", Description: "Number of containers in the workload"},
			{Name: "Age", Type: "string", Description: "Age of the resource"},
		},
		Rows: []metav1.TableRow{},
	}

	var reports []storagev1alpha1.WorkloadScanReport
	switch t := obj.(type) {
	case *storagev1alpha1.WorkloadScanReportList:
		reports = t.Items
	case *storagev1alpha1.WorkloadScanReport:
		reports = []storagev1alpha1.WorkloadScanReport{*t}
	default:
		return nil, fmt.Errorf("unexpected type %T", obj)
	}

	for _, report := range reports {
		row := metav1.TableRow{
			Object: runtime.RawExtension{Object: &report},
			Cells: []interface{}{
				report.Name,
				report.Namespace,
				len(report.Containers),
				report.CreationTimestamp,
			},
		}
		table.Rows = append(table.Rows, row)
	}

	return table, nil
}
