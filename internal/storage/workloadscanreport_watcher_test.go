package storage

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

type workloadScanReportWatcherTestSuite struct {
	suite.Suite
	db                  *pgxpool.Pool
	pgContainer         *postgres.PostgresContainer
	natsServer          *server.Server
	nc                  *nats.Conn
	repo                *repository.WorkloadScanReportRepository
	workloadBroadcaster *natsBroadcaster
	workloadStore       *store
	localBroadcaster    *watch.Broadcaster
	natsWatcher         *natsWatcher
}

func (suite *workloadScanReportWatcherTestSuite) SetupSuite() {
	pgContainer, err := postgres.Run(suite.T().Context(),
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpassword"),
		postgres.BasicWaitStrategies(),
	)
	suite.Require().NoError(err, "failed to start postgres container")
	suite.pgContainer = pgContainer

	connStr, err := pgContainer.ConnectionString(suite.T().Context(), "sslmode=disable")
	suite.Require().NoError(err, "failed to get connection string")

	db, err := pgxpool.New(suite.T().Context(), connStr)
	suite.Require().NoError(err, "failed to create connection pool")
	suite.db = db

	err = RunMigrations(suite.T().Context(), suite.db)
	suite.Require().NoError(err, "failed to run migrations")

	opts := test.DefaultTestOptions
	opts.Port = -1
	opts.JetStream = true
	opts.StoreDir = suite.T().TempDir()
	suite.natsServer = test.RunServer(&opts)

	nc, err := nats.Connect(suite.natsServer.ClientURL())
	suite.Require().NoError(err, "failed to connect to NATS")
	suite.nc = nc
}

func (suite *workloadScanReportWatcherTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}

	if suite.pgContainer != nil {
		err := suite.pgContainer.Terminate(suite.T().Context())
		suite.Require().NoError(err, "failed to terminate postgres container")
	}

	if suite.nc != nil {
		suite.nc.Close()
	}

	if suite.natsServer != nil {
		suite.natsServer.Shutdown()
	}
}

func (suite *workloadScanReportWatcherTestSuite) SetupTest() {
	_, err := suite.db.Exec(suite.T().Context(), "TRUNCATE TABLE workloadscanreports, vulnerabilityreports, images CASCADE")
	suite.Require().NoError(err, "failed to truncate tables")

	_, err = suite.db.Exec(suite.T().Context(), "ALTER SEQUENCE resource_version_seq RESTART WITH 1")
	suite.Require().NoError(err, "failed to reset resource version sequence")

	suite.repo = repository.NewWorkloadScanReportRepository(
		"workloadscanreports",
		"vulnerabilityreports",
		"images",
	)

	suite.localBroadcaster = watch.NewBroadcaster(1000, watch.WaitIfChannelFull)

	suite.workloadBroadcaster = newNatsBroadcaster(
		suite.nc,
		"workloadscanreports",
		suite.localBroadcaster,
		TransformStripWorkloadScanReport,
		slog.Default(),
	)

	suite.workloadStore = &store{
		db:          suite.db,
		repository:  suite.repo,
		broadcaster: suite.workloadBroadcaster,
		newFunc:     func() runtime.Object { return &storagev1alpha1.WorkloadScanReport{} },
		newListFunc: func() runtime.Object { return &storagev1alpha1.WorkloadScanReportList{} },
		logger:      slog.Default(),
	}

	suite.natsWatcher = newNatsWatcher(
		suite.nc,
		"workloadscanreports",
		suite.localBroadcaster,
		suite.workloadStore,
		slog.Default(),
	)
}

func (suite *workloadScanReportWatcherTestSuite) TearDownTest() {
	if suite.localBroadcaster != nil {
		suite.localBroadcaster.Shutdown()
	}
}

func TestWorkloadScanReportWatcherTestSuite(t *testing.T) {
	suite.Run(t, &workloadScanReportWatcherTestSuite{})
}

func (suite *workloadScanReportWatcherTestSuite) TestNoMatchingWorkloadScanReports() {
	ctx, cancel := context.WithCancel(suite.T().Context())
	defer cancel()

	w, err := suite.localBroadcaster.Watch()
	suite.Require().NoError(err)
	defer w.Stop()

	go suite.natsWatcher.Start(ctx)

	watcher := newWorkloadScanReportWatcher(
		suite.nc,
		suite.db,
		suite.repo,
		suite.workloadBroadcaster,
		suite.workloadStore,
		slog.Default(),
	)
	go watcher.Start(ctx)

	// Flush NATS connection to ensure watcher is subscribed before publishing events
	suite.Require().NoError(suite.nc.Flush())

	vulnReport := storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphan-vuln-report",
			Namespace: "default",
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:   "docker.io",
			Repository: "library/redis",
			Tag:        "7",
		},
	}

	suite.publishVulnerabilityReportEvent(watch.Modified, &vulnReport)

	select {
	case evt := <-w.ResultChan():
		suite.Failf("unexpected event received", "got event type %v", evt.Type)
	case <-time.After(200 * time.Millisecond):
		// Expected: no events
	}
}

func (suite *workloadScanReportWatcherTestSuite) TestMultipleWorkloadScanReportsMatch() {
	ctx, cancel := context.WithCancel(suite.T().Context())
	defer cancel()

	for _, name := range []string{"workload-1", "workload-2"} {
		report := &storagev1alpha1.WorkloadScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: storagev1alpha1.WorkloadScanReportSpec{
				Containers: []storagev1alpha1.ContainerRef{
					{
						Name: "app",
						ImageRef: storagev1alpha1.ImageRef{
							Registry:   "ghcr.io",
							Namespace:  "default",
							Repository: "myorg/myapp",
							Tag:        "v1.0.0",
						},
					},
				},
			},
		}

		err := suite.runInTx(ctx, func(tx pgx.Tx) error {
			return suite.repo.Create(ctx, tx, report)
		})
		suite.Require().NoError(err)
	}

	w, err := suite.localBroadcaster.Watch()
	suite.Require().NoError(err)
	defer w.Stop()

	go suite.natsWatcher.Start(ctx)

	watcher := newWorkloadScanReportWatcher(
		suite.nc,
		suite.db,
		suite.repo,
		suite.workloadBroadcaster,
		suite.workloadStore,
		slog.Default(),
	)
	go watcher.Start(ctx)

	// Flush NATS connection to ensure watcher is subscribed before publishing events
	suite.Require().NoError(suite.nc.Flush())

	vulnReport := storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "myapp-vuln-report",
			Namespace: "default",
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:   "ghcr.io",
			Repository: "myorg/myapp",
			Tag:        "v1.0.0",
		},
	}

	suite.publishVulnerabilityReportEvent(watch.Modified, &vulnReport)

	events := mustReadEvents(suite.T(), w, 2)

	names := make([]string, 0, 2)
	for _, evt := range events {
		suite.Equal(watch.Modified, evt.Type)
		report, ok := evt.Object.(*storagev1alpha1.WorkloadScanReport)
		suite.Require().True(ok)
		names = append(names, report.Name)
	}
	suite.ElementsMatch([]string{"workload-1", "workload-2"}, names)
}

func (suite *workloadScanReportWatcherTestSuite) runInTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
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

func (suite *workloadScanReportWatcherTestSuite) publishVulnerabilityReportEvent(
	eventType watch.EventType,
	vulnReport *storagev1alpha1.VulnerabilityReport,
) {
	vulnReportBytes, err := json.Marshal(vulnReport)
	suite.Require().NoError(err)

	evt := event{
		EventType: eventType,
		Object:    runtime.RawExtension{Raw: vulnReportBytes},
	}
	eventBytes, err := json.Marshal(evt)
	suite.Require().NoError(err)

	err = suite.nc.Publish("watch."+vulnerabilityReportResourcePluralName, eventBytes)
	suite.Require().NoError(err)
	suite.Require().NoError(suite.nc.Flush())
}
