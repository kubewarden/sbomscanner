package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8sstorage "k8s.io/apiserver/pkg/storage"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

// storeTestCase parameterises storeTestSuite over a resource type.
// Each case (namespaced SBOM, cluster-scoped NodeSBOM) brings up its own store, repository, watcher and broadcaster,
// but shares the test bodies.
// Concrete-type construction and field access are passed in as function pointers so the suite never type-switches.
type storeTestCase struct {
	resource      string
	keyPrefix     string
	clusterScoped bool
	newFunc       func() runtime.Object
	newListFunc   func() runtime.Object
	truncateTable string
	predicateFunc func(labels.Selector, fields.Selector) k8sstorage.SelectionPredicate
	transform     cache.TransformFunc

	// newObj builds an object of this case's resource type.
	// For cluster-scoped resources the namespace argument is ignored.
	newObj func(name, namespace string, labels map[string]string, spdx []byte) runtime.Object
	// setUID sets the UID on an object of this case's resource type.
	setUID func(obj runtime.Object, uid types.UID)
	// objSPDX extracts the SPDX raw bytes from an object of this case's resource type.
	objSPDX func(obj runtime.Object) []byte
	// setSPDX overwrites the SPDX raw bytes on an object of this case's resource type.
	setSPDX func(obj runtime.Object, raw []byte)
}

type storeTestSuite struct {
	suite.Suite

	test        storeTestCase
	store       *store
	db          *pgxpool.Pool
	broadcaster *watch.Broadcaster
	watcher     *natsWatcher
	pgContainer *postgres.PostgresContainer
	natsServer  *server.Server
	nc          *nats.Conn
}

func (suite *storeTestSuite) SetupSuite() {
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

	// Setup NATS
	opts := test.DefaultTestOptions
	opts.Port = -1 // Use a random port
	opts.JetStream = true
	opts.StoreDir = suite.T().TempDir()
	suite.natsServer = test.RunServer(&opts)

	nc, err := nats.Connect(suite.natsServer.ClientURL())
	suite.Require().NoError(err, "failed to connect to NATS")
	suite.nc = nc
}

func (suite *storeTestSuite) TearDownSuite() {
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

func (suite *storeTestSuite) SetupTest() {
	_, err := suite.db.Exec(suite.T().Context(), fmt.Sprintf("TRUNCATE TABLE %s", suite.test.truncateTable))
	suite.Require().NoError(err, "failed to truncate table")

	_, err = suite.db.Exec(suite.T().Context(), "ALTER SEQUENCE resource_version_seq RESTART WITH 1")
	suite.Require().NoError(err, "failed to reset resource version sequence")

	repo := repository.NewGenericObjectRepository(suite.test.resource, suite.test.newFunc)

	watchBroadcaster := watch.NewBroadcaster(1000, watch.WaitIfChannelFull)
	natsBroadcaster := newNatsBroadcaster(suite.nc, suite.test.resource, watchBroadcaster, suite.test.transform, slog.Default())

	store := &store{
		db:            suite.db,
		repository:    repo,
		broadcaster:   natsBroadcaster,
		newFunc:       suite.test.newFunc,
		newListFunc:   suite.test.newListFunc,
		logger:        slog.Default(),
		clusterScoped: suite.test.clusterScoped,
	}
	natsWatcher := newNatsWatcher(suite.nc, suite.test.resource, watchBroadcaster, store, slog.Default())

	suite.store = store
	suite.broadcaster = watchBroadcaster
	suite.watcher = natsWatcher
}

func TestStoreTestSuite(t *testing.T) {
	tests := []storeTestCase{
		{
			resource:      "sboms",
			keyPrefix:     "/storage.sbomscanner.kubewarden.io/sboms",
			clusterScoped: false,
			newFunc:       func() runtime.Object { return &storagev1alpha1.SBOM{} },
			newListFunc:   func() runtime.Object { return &storagev1alpha1.SBOMList{} },
			truncateTable: "sboms",
			predicateFunc: matcher,
			transform:     TransformStripSBOM,
			newObj: func(name, namespace string, objLabels map[string]string, spdx []byte) runtime.Object {
				return &storagev1alpha1.SBOM{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: objLabels},
					SPDX:       runtime.RawExtension{Raw: spdx},
				}
			},
			setUID:  func(obj runtime.Object, uid types.UID) { obj.(*storagev1alpha1.SBOM).UID = uid },
			objSPDX: func(obj runtime.Object) []byte { return obj.(*storagev1alpha1.SBOM).SPDX.Raw },
			setSPDX: func(obj runtime.Object, raw []byte) { obj.(*storagev1alpha1.SBOM).SPDX.Raw = raw },
		},
		{
			resource:      "nodesboms",
			keyPrefix:     "/storage.sbomscanner.kubewarden.io/nodesboms",
			clusterScoped: true,
			newFunc:       func() runtime.Object { return &storagev1alpha1.NodeSBOM{} },
			newListFunc:   func() runtime.Object { return &storagev1alpha1.NodeSBOMList{} },
			truncateTable: "nodesboms",
			predicateFunc: nodeSBOMMatcher,
			transform:     TransformStripNodeSBOM,
			newObj: func(name, _ string, objLabels map[string]string, spdx []byte) runtime.Object {
				return &storagev1alpha1.NodeSBOM{
					ObjectMeta:   metav1.ObjectMeta{Name: name, Labels: objLabels},
					NodeMetadata: storagev1alpha1.NodeMetadata{Name: name, Platform: "linux/amd64"},
					SPDX:         runtime.RawExtension{Raw: spdx},
				}
			},
			setUID:  func(obj runtime.Object, uid types.UID) { obj.(*storagev1alpha1.NodeSBOM).UID = uid },
			objSPDX: func(obj runtime.Object) []byte { return obj.(*storagev1alpha1.NodeSBOM).SPDX.Raw },
			setSPDX: func(obj runtime.Object, raw []byte) { obj.(*storagev1alpha1.NodeSBOM).SPDX.Raw = raw },
		},
	}

	for _, test := range tests {
		t.Run(test.resource, func(t *testing.T) {
			suite.Run(t, &storeTestSuite{test: test})
		})
	}
}

func (suite *storeTestSuite) TestCreate() {
	obj := suite.test.newObj("test", "default", nil, []byte(`{"test": true}`))

	key := suite.keyFor("test", "default")
	out := suite.test.newFunc()
	err := suite.store.Create(suite.T().Context(), key, obj, out, 0)
	suite.Require().NoError(err)

	outMeta, ok := out.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal("test", outMeta.GetName())
	suite.Equal(suite.expectedNamespace("default"), outMeta.GetNamespace())
	suite.NotEmpty(outMeta.GetResourceVersion())
	suite.Equal([]byte(`{"test": true}`), suite.test.objSPDX(out))

	got := suite.test.newFunc()
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, got)
	suite.Require().NoError(err)
	suite.Equal(out, got)

	// Duplicate create should fail
	err = suite.store.Create(suite.T().Context(), key, obj, out, 0)
	suite.Require().Equal(k8sstorage.NewKeyExistsError(key, 0).Error(), err.Error())
}

func (suite *storeTestSuite) TestGet() {
	key := suite.keyFor("test", "default")

	out := suite.test.newFunc()
	err := suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, out)
	suite.True(k8sstorage.IsNotFound(err))

	out = suite.test.newFunc()
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{IgnoreNotFound: true}, out)
	suite.Require().NoError(err)
	suite.Equal(suite.test.newFunc(), out)

	obj := suite.test.newObj("test", "default", map[string]string{"app": "test"}, []byte(`{"test": true}`))
	err = suite.store.Create(suite.T().Context(), key, obj, nil, 0)
	suite.Require().NoError(err)

	out = suite.test.newFunc()
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, out)
	suite.Require().NoError(err)
	outMeta, ok := out.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal("test", outMeta.GetName())
	suite.Equal(suite.expectedNamespace("default"), outMeta.GetNamespace())
	suite.Equal(map[string]string{"app": "test"}, outMeta.GetLabels())
	suite.NotEmpty(outMeta.GetResourceVersion())
	suite.Equal([]byte(`{"test": true}`), suite.test.objSPDX(out))
}

func (suite *storeTestSuite) TestDelete() {
	key := suite.keyFor("test", "default")

	tests := []struct {
		name             string
		preconditions    *k8sstorage.Preconditions
		validateDeletion k8sstorage.ValidateObjectFunc
		expectedError    error
	}{
		{
			name:          "happy path",
			preconditions: &k8sstorage.Preconditions{},
			validateDeletion: func(_ context.Context, _ runtime.Object) error {
				return nil
			},
			expectedError: nil,
		},
		{
			name:          "deletion fails with incorrect UID precondition",
			preconditions: &k8sstorage.Preconditions{UID: ptr.To(types.UID("incorrect-uid"))},
			validateDeletion: func(_ context.Context, _ runtime.Object) error {
				return nil
			},
			expectedError: k8sstorage.NewInvalidObjError(
				key,
				"Precondition failed: UID in precondition: incorrect-uid, UID in object meta: ",
			),
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			obj := suite.test.newObj("test", "default", nil, nil)
			err := suite.store.Create(suite.T().Context(), key, obj, suite.test.newFunc(), 0)
			suite.Require().NoError(err)

			out := suite.test.newFunc()
			err = suite.store.Delete(
				suite.T().Context(),
				key,
				out,
				test.preconditions,
				test.validateDeletion,
				nil,
				k8sstorage.DeleteOptions{},
			)

			if test.expectedError != nil {
				suite.Require().Error(err)
				suite.Equal(test.expectedError.Error(), err.Error())
			} else {
				suite.Require().NoError(err)
				suite.Equal(obj, out)

				err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, suite.test.newFunc())
				suite.True(k8sstorage.IsNotFound(err))
			}
		})
	}
}

func (suite *storeTestSuite) TestDeleteNotFound() {
	key := suite.keyFor("notfound", "default")
	out := suite.test.newFunc()
	err := suite.store.Delete(
		suite.T().Context(),
		key,
		out,
		&k8sstorage.Preconditions{},
		func(_ context.Context, _ runtime.Object) error { return nil },
		nil,
		k8sstorage.DeleteOptions{},
	)
	suite.True(k8sstorage.IsNotFound(err))
}

func (suite *storeTestSuite) TestWatchEmptyResourceVersion() {
	key := suite.keyFor("test", "default")
	opts := k8sstorage.ListOptions{ResourceVersion: ""}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	suite.broadcaster.Shutdown()

	suite.Require().Empty(w.ResultChan())
}

func (suite *storeTestSuite) TestWatchResourceVersionZero() {
	key := suite.keyFor("test", "default")
	obj := suite.test.newObj("test", "default", nil, nil)
	err := suite.store.Create(suite.T().Context(), key, obj, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	opts := k8sstorage.ListOptions{ResourceVersion: "0"}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	suite.Require().NoError(suite.watcher.Setup(suite.T().Context()))
	go suite.watcher.Start(suite.T().Context())

	validateDeletion := func(_ context.Context, _ runtime.Object) error {
		return nil
	}
	err = suite.store.Delete(
		suite.T().Context(),
		key,
		suite.test.newFunc(),
		&k8sstorage.Preconditions{},
		validateDeletion,
		nil,
		k8sstorage.DeleteOptions{},
	)
	suite.Require().NoError(err)

	events := mustReadEvents(suite.T(), w, 2)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(obj, events[0].Object)
	suite.Equal(watch.Deleted, events[1].Type)
	suite.Equal(obj, events[1].Object)
}

func (suite *storeTestSuite) TestWatchSpecificResourceVersion() {
	key := suite.keyFor("test", "default")
	obj := suite.test.newObj("test", "default", nil, nil)
	suite.Require().NoError(suite.store.Create(suite.T().Context(), key, obj, suite.test.newFunc(), 0))

	opts := k8sstorage.ListOptions{
		ResourceVersion: "1",
		Predicate:       suite.test.predicateFunc(labels.Everything(), fields.Everything()),
	}

	w, err := suite.store.Watch(suite.T().Context(), suite.defaultNamespaceKey(), opts)
	suite.Require().NoError(err)

	suite.Require().NoError(suite.watcher.Setup(suite.T().Context()))
	go suite.watcher.Start(suite.T().Context())

	tryUpdate := func(input runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
		return input, new(uint64), nil
	}
	updatedObj := suite.test.newFunc()
	err = suite.store.GuaranteedUpdate(
		suite.T().Context(),
		key,
		updatedObj,
		false,
		&k8sstorage.Preconditions{},
		tryUpdate,
		nil,
	)
	suite.Require().NoError(err)

	events := mustReadEvents(suite.T(), w, 2)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(obj, events[0].Object)
	addedMeta, ok := events[0].Object.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal("1", addedMeta.GetResourceVersion(), "expected resource version 1 for the added event")
	suite.Equal(watch.Modified, events[1].Type)
	suite.Equal(updatedObj, events[1].Object)
}

func (suite *storeTestSuite) TestWatchWithLabelSelector() {
	obj1 := suite.test.newObj("test1", "default", map[string]string{
		"sbomscanner.kubewarden.io/test": "true",
	}, nil)
	err := suite.store.Create(suite.T().Context(), suite.keyFor("test1", "default"), obj1, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	obj2 := suite.test.newObj("test2", "default", map[string]string{}, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"), obj2, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	opts := k8sstorage.ListOptions{
		ResourceVersion: "1",
		Predicate: suite.test.predicateFunc(labels.SelectorFromSet(labels.Set{
			"sbomscanner.kubewarden.io/test": "true",
		}), fields.Everything()),
	}
	w, err := suite.store.Watch(suite.T().Context(), suite.defaultNamespaceKey(), opts)
	suite.Require().NoError(err)

	suite.Require().NoError(suite.watcher.Setup(suite.T().Context()))
	go suite.watcher.Start(suite.T().Context())

	events := mustReadEvents(suite.T(), w, 1)
	suite.Require().Len(events, 1)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(obj1, events[0].Object)
}

func (suite *storeTestSuite) TestWatchList() {
	obj1 := suite.test.newObj("test1", "default", nil, nil)
	err := suite.store.Create(suite.T().Context(), suite.keyFor("test1", "default"), obj1, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	obj2 := suite.test.newObj("test2", "default", nil, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"), obj2, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	predicate := suite.test.predicateFunc(labels.Everything(), fields.Everything())
	predicate.AllowWatchBookmarks = true

	opts := k8sstorage.ListOptions{
		SendInitialEvents: new(true),
		Predicate:         predicate,
		Recursive:         true,
	}

	w, err := suite.store.Watch(suite.T().Context(), suite.defaultNamespaceKey(), opts)
	suite.Require().NoError(err)

	// Should receive ADDED events for existing items + BOOKMARK
	events := mustReadEvents(suite.T(), w, 3)

	// First two events should be ADDED for existing items
	addedEvents := events[:2]
	for _, evt := range addedEvents {
		suite.Equal(watch.Added, evt.Type)
	}

	// Verify both items were sent (order may vary)
	addedNames := make([]string, 0, 2)
	for _, evt := range addedEvents {
		objMeta, ok := evt.Object.(metav1.Object)
		suite.Require().True(ok)
		addedNames = append(addedNames, objMeta.GetName())
	}
	suite.ElementsMatch([]string{"test1", "test2"}, addedNames)

	// Last event should be BOOKMARK with the initial-events-end annotation
	bookmarkEvent := events[2]
	suite.Equal(watch.Bookmark, bookmarkEvent.Type)

	bookmarkMeta, ok := bookmarkEvent.Object.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal("true", bookmarkMeta.GetAnnotations()["k8s.io/initial-events-end"])
	suite.NotEmpty(bookmarkMeta.GetResourceVersion())
}

// When a non-Deleted event arrives for an object the store no longer holds,
// the watcher must still broadcast the payload.
func (suite *storeTestSuite) TestHandleMessageNotFoundStillBroadcasts() {
	ctx, cancel := context.WithCancel(suite.T().Context())
	defer cancel()

	w, err := suite.broadcaster.Watch()
	suite.Require().NoError(err)
	defer w.Stop()

	suite.Require().NoError(suite.watcher.Setup(ctx))
	go suite.watcher.Start(ctx)

	ghost := suite.test.newObj("ghost", "default", nil, nil)
	ghostBytes, err := json.Marshal(ghost)
	suite.Require().NoError(err)

	payload, err := json.Marshal(event{
		EventType: watch.Added,
		Object:    runtime.RawExtension{Raw: ghostBytes},
	})
	suite.Require().NoError(err)

	suite.Require().NoError(suite.nc.Publish(suite.natsSubject(), payload))
	suite.Require().NoError(suite.nc.Flush())

	events := mustReadEvents(suite.T(), w, 1)
	suite.Equal(watch.Added, events[0].Type)

	gotMeta, ok := events[0].Object.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal("ghost", gotMeta.GetName())
	suite.Equal(suite.expectedNamespace("default"), gotMeta.GetNamespace())
}

// When the store holds a different object at the same namespace/name,
// the watcher must broadcast the payload, not the refetched object.
func (suite *storeTestSuite) TestHandleMessageUIDMismatchBroadcastsPayload() {
	ctx, cancel := context.WithCancel(suite.T().Context())
	defer cancel()

	w, err := suite.broadcaster.Watch()
	suite.Require().NoError(err)
	defer w.Stop()

	suite.Require().NoError(suite.watcher.Setup(ctx))
	go suite.watcher.Start(ctx)

	// Populate the store at <ns>/collide.
	// The stale event published next will carry a different UID for the same namespace/name.
	storedUID := types.UID("stored-uid")
	stored := suite.test.newObj("collide", "default", nil, []byte(`{"stored": true}`))
	suite.test.setUID(stored, storedUID)
	key := suite.keyFor("collide", "default")
	err = suite.store.Create(ctx, key, stored, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	// Drain the ADDED event produced by the Create above
	created := mustReadEvents(suite.T(), w, 1)
	suite.Equal(watch.Added, created[0].Type)
	createdMeta, ok := created[0].Object.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal(storedUID, createdMeta.GetUID())

	// Publish a stale ADDED carrying a different UID at the same namespace/name
	staleUID := types.UID("stale-uid")
	suite.Require().NotEqual(storedUID, staleUID)

	stale := suite.test.newObj("collide", "default", nil, nil)
	suite.test.setUID(stale, staleUID)
	staleBytes, err := json.Marshal(stale)
	suite.Require().NoError(err)

	payload, err := json.Marshal(event{
		EventType: watch.Added,
		Object:    runtime.RawExtension{Raw: staleBytes},
	})
	suite.Require().NoError(err)

	suite.Require().NoError(suite.nc.Publish(suite.natsSubject(), payload))
	suite.Require().NoError(suite.nc.Flush())

	events := mustReadEvents(suite.T(), w, 1)
	suite.Equal(watch.Added, events[0].Type)

	gotMeta, ok := events[0].Object.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal(staleUID, gotMeta.GetUID(), "expected payload UID, not stored UID")

	// Stored object should still be intact and retrievable with its own UID
	fetched := suite.test.newFunc()
	err = suite.store.Get(ctx, key, k8sstorage.GetOptions{}, fetched)
	suite.Require().NoError(err)
	fetchedMeta, ok := fetched.(metav1.Object)
	suite.Require().True(ok)
	suite.Equal(storedUID, fetchedMeta.GetUID())
}

func (suite *storeTestSuite) TestGetList() {
	obj1 := suite.test.newObj("test1", "default", map[string]string{
		"sbomscanner.kubewarden.io/env": "test",
	}, nil)
	err := suite.store.Create(suite.T().Context(), suite.keyFor("test1", "default"), obj1, nil, 0)
	suite.Require().NoError(err)

	obj2 := suite.test.newObj("test2", "default", map[string]string{
		"sbomscanner.kubewarden.io/env": "dev",
	}, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"), obj2, nil, 0)
	suite.Require().NoError(err)

	obj3 := suite.test.newObj("test3", "default", map[string]string{
		"sbomscanner.kubewarden.io/env":      "prod",
		"sbomscanner.kubewarden.io/critical": "true",
	}, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test3", "default"), obj3, nil, 0)
	suite.Require().NoError(err)

	tests := []struct {
		name          string
		listOptions   k8sstorage.ListOptions
		expectedNames []string
	}{
		{
			name:          "list all",
			expectedNames: []string{"test1", "test2", "test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(labels.Everything(), fields.Everything()),
			},
		},
		{
			name:          "list label selector (=)",
			expectedNames: []string{"test1"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("sbomscanner.kubewarden.io/env=test"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (!=)",
			expectedNames: []string{"test2", "test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("sbomscanner.kubewarden.io/env!=test"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (in)",
			expectedNames: []string{"test2", "test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("sbomscanner.kubewarden.io/env in (dev,prod)"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (notin)",
			expectedNames: []string{"test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("sbomscanner.kubewarden.io/env notin (test,dev)"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (exists)",
			expectedNames: []string{"test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("sbomscanner.kubewarden.io/critical"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (does not exist)",
			expectedNames: []string{"test1", "test2"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(mustParseLabelSelector("!sbomscanner.kubewarden.io/critical"), fields.Everything()),
			},
		},
		{
			name:          "list field selector (=)",
			expectedNames: []string{"test1"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(labels.Everything(), mustParseFieldSelector("metadata.name=test1")),
			},
		},
		{
			name:          "list field selector (!=)",
			expectedNames: []string{"test2", "test3"},
			listOptions: k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(labels.Everything(), mustParseFieldSelector("metadata.name!=test1")),
			},
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			listObj := suite.test.newListFunc()
			err = suite.store.GetList(suite.T().Context(), suite.defaultNamespaceKey(), test.listOptions, listObj)
			suite.Require().NoError(err)
			suite.ElementsMatch(test.expectedNames, suite.listNames(listObj))
		})
	}
}

func (suite *storeTestSuite) TestGetListWithPagination() {
	for i := 1; i <= 5; i++ {
		obj := suite.test.newObj(
			fmt.Sprintf("test%d", i),
			"default",
			map[string]string{
				"sbomscanner.kubewarden.io/env": map[bool]string{true: "prod", false: "dev"}[i%2 == 0],
			},
			nil,
		)
		err := suite.store.Create(suite.T().Context(), suite.keyFor(fmt.Sprintf("test%d", i), "default"), obj, nil, 0)
		suite.Require().NoError(err)
	}

	tests := []struct {
		name          string
		limit         int64
		labelSelector labels.Selector
		fieldSelector fields.Selector
		expectedPages [][]string
	}{
		{
			name:          "paginate through all items",
			limit:         2,
			labelSelector: labels.Everything(),
			fieldSelector: fields.Everything(),
			expectedPages: [][]string{{"test1", "test2"}, {"test3", "test4"}, {"test5"}},
		},
		{
			name:          "no continue token when under limit",
			limit:         10,
			labelSelector: labels.Everything(),
			fieldSelector: fields.Everything(),
			expectedPages: [][]string{{"test1", "test2", "test3", "test4", "test5"}},
		},
		{
			name:          "paginate with label selector",
			limit:         1,
			labelSelector: mustParseLabelSelector("sbomscanner.kubewarden.io/env=prod"),
			fieldSelector: fields.Everything(),
			expectedPages: [][]string{{"test2"}, {"test4"}},
		},
		{
			name:          "paginate with field selector",
			limit:         2,
			labelSelector: labels.Everything(),
			fieldSelector: mustParseFieldSelector("metadata.name!=test3"),
			expectedPages: [][]string{{"test1", "test2"}, {"test4", "test5"}},
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			opts := k8sstorage.ListOptions{
				Predicate: suite.test.predicateFunc(test.labelSelector, test.fieldSelector),
			}
			opts.Predicate.Limit = test.limit

			for i, expectedNames := range test.expectedPages {
				listObj := suite.test.newListFunc()
				err := suite.store.GetList(suite.T().Context(), suite.defaultNamespaceKey(), opts, listObj)
				suite.Require().NoError(err)

				suite.Equal(expectedNames, suite.listNames(listObj), "page %d", i+1)

				listMeta, ok := listObj.(metav1.ListInterface)
				suite.Require().True(ok)

				isLastPage := i == len(test.expectedPages)-1
				if isLastPage {
					suite.Empty(listMeta.GetContinue())
				} else {
					suite.NotEmpty(listMeta.GetContinue())
				}

				opts.Predicate.Continue = listMeta.GetContinue()
			}
		})
	}
}

func (suite *storeTestSuite) TestGetListResourceVersionSemanntics() {
	// Create some objects to get different RVs
	obj1 := suite.test.newObj("test1", "default", nil, nil)
	err := suite.store.Create(suite.T().Context(), suite.keyFor("test1", "default"), obj1, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	obj2 := suite.test.newObj("test2", "default", nil, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"), obj2, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	obj3 := suite.test.newObj("test3", "default", nil, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test3", "default"), obj3, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	tests := []struct {
		name            string
		resourceVersion string
		expectedNames   []string
		expectNewRV     bool
		expectedListRV  string
	}{
		{
			name:            "empty RV returns all objects and generates new RV",
			resourceVersion: "",
			expectedNames:   []string{"test1", "test2", "test3"},
			expectNewRV:     true,
		},
		{
			name:            "RV 0 returns all objects and generates new RV",
			resourceVersion: "0",
			expectedNames:   []string{"test1", "test2", "test3"},
			expectNewRV:     true,
		},
		{
			name:            "specific RV filters objects with NotOlderThan semantics",
			resourceVersion: "2",
			expectedNames:   []string{"test2", "test3"},
			expectedListRV:  "2",
		},
		{
			name:            "RV higher than all objects returns empty list",
			resourceVersion: "100",
			expectedNames:   []string{},
			expectedListRV:  "100",
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			opts := k8sstorage.ListOptions{
				ResourceVersion: test.resourceVersion,
				Predicate:       suite.test.predicateFunc(labels.Everything(), fields.Everything()),
			}

			listObj := suite.test.newListFunc()
			err := suite.store.GetList(suite.T().Context(), suite.defaultNamespaceKey(), opts, listObj)
			suite.Require().NoError(err)

			suite.ElementsMatch(test.expectedNames, suite.listNames(listObj))

			listMeta, ok := listObj.(metav1.ListInterface)
			suite.Require().True(ok)

			if test.expectNewRV {
				suite.NotEmpty(listMeta.GetResourceVersion())
				listRV, err := strconv.ParseUint(listMeta.GetResourceVersion(), 10, 64)
				suite.Require().NoError(err)
				suite.Greater(listRV, uint64(3), "list RV should be a newly generated value")
			}

			if test.expectedListRV != "" {
				suite.Equal(test.expectedListRV, listMeta.GetResourceVersion())
			}
		})
	}
}

func (suite *storeTestSuite) TestGuaranteedUpdate() {
	// seedObj is built lazily via a factory,
	// so each subtest gets a fresh object built from the per-case newObj.
	type seedFn func() runtime.Object

	uidSeed := func(name string, uid types.UID, spdx []byte) seedFn {
		return func() runtime.Object {
			obj := suite.test.newObj(name, "default", nil, spdx)
			suite.test.setUID(obj, uid)
			return obj
		}
	}

	expectedUpdated := func(name string, uid types.UID, spdx []byte, rv string) runtime.Object {
		obj := suite.test.newObj(name, "default", nil, spdx)
		suite.test.setUID(obj, uid)
		obj.(metav1.Object).SetResourceVersion(rv)
		return obj
	}

	tests := []struct {
		name               string
		key                string
		ignoreNotFound     bool
		preconditions      *k8sstorage.Preconditions
		tryUpdate          k8sstorage.UpdateFunc
		seed               seedFn
		expectedUpdatedObj runtime.Object
		expectedError      error
	}{
		{
			name:          "happy path",
			key:           suite.keyFor("test1", "default"),
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(input runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.test.setSPDX(input, []byte(`{"foo": "bar"}`))
				return input, new(uint64), nil
			},
			seed:               uidSeed("test1", types.UID("test1-uid"), []byte("{}")),
			expectedUpdatedObj: expectedUpdated("test1", types.UID("test1-uid"), []byte(`{"foo": "bar"}`), "2"),
		},
		{
			name: "preconditions failed",
			key:  suite.keyFor("test2", "default"),
			preconditions: &k8sstorage.Preconditions{
				UID: ptr.To(types.UID("incorrect-uid")),
			},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when preconditions fail")
				return nil, nil, nil
			},
			seed: uidSeed("test2", types.UID("test2-uid"), []byte("{}")),
			expectedError: k8sstorage.NewInvalidObjError(suite.keyFor("test2", "default"),
				"Precondition failed: UID in precondition: incorrect-uid, UID in object meta: test2-uid"),
		},
		{
			name:          "tryUpdate failed with a non-conflict error",
			key:           suite.keyFor("test3", "default"),
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				return nil, nil, k8sstorage.NewInternalError(errors.New("tryUpdate failed"))
			},
			seed:          uidSeed("test3", types.UID("test3-uid"), []byte("{}")),
			expectedError: k8sstorage.NewInternalError(errors.New("tryUpdate failed")),
		},
		{
			name:          "not found",
			key:           suite.keyFor("notfound", "default"),
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when object is not found")
				return nil, nil, nil
			},
			expectedError: k8sstorage.NewKeyNotFoundError(suite.keyFor("notfound", "default"), 0),
		},
		{
			name:          "not found with ignore not found",
			key:           suite.keyFor("notfound", "default"),
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when object is not found")
				return nil, nil, nil
			},
			ignoreNotFound:     true,
			expectedUpdatedObj: suite.test.newFunc(),
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			var seeded runtime.Object
			if test.seed != nil {
				seeded = test.seed()
				err := suite.store.Create(suite.T().Context(), test.key, seeded, suite.test.newFunc(), 0)
				suite.Require().NoError(err)
			}

			destination := suite.test.newFunc()
			err := suite.store.GuaranteedUpdate(
				suite.T().Context(),
				test.key,
				destination,
				test.ignoreNotFound,
				test.preconditions,
				test.tryUpdate,
				nil,
			)

			if test.expectedError != nil {
				suite.Require().Error(err)
				suite.Require().Equal(test.expectedError.Error(), err.Error())

				if seeded != nil {
					// If there is an error, the original object should not be updated.
					current := suite.test.newFunc()
					err = suite.store.Get(suite.T().Context(), test.key, k8sstorage.GetOptions{}, current)
					suite.Require().NoError(err)
					suite.Equal(seeded, current)
				}
			} else {
				suite.Require().NoError(err)
				suite.Require().Equal(test.expectedUpdatedObj, destination)

				if !test.ignoreNotFound {
					// Verify the object was updated in the store.
					current := suite.test.newFunc()
					err = suite.store.Get(suite.T().Context(), test.key, k8sstorage.GetOptions{}, current)
					suite.Require().NoError(err)
					suite.Equal(test.expectedUpdatedObj, current)
				}
			}
		})
	}
}

func (suite *storeTestSuite) TestCount() {
	err := suite.store.Create(suite.T().Context(), suite.keyFor("test1", "default"),
		suite.test.newObj("test1", "default", nil, nil), suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"),
		suite.test.newObj("test2", "default", nil, nil), suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	// For namespaced resources, drop a third object into a different namespace,
	// so the per-namespace count differs from the total.
	// For cluster-scoped resources just use a third distinct name.
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test4", "other"),
		suite.test.newObj("test4", "other", nil, nil), suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	type countCase struct {
		name          string
		key           string
		expectedCount int64
	}

	tests := []countCase{
		{
			name:          "count all entries",
			key:           suite.test.keyPrefix,
			expectedCount: 3,
		},
	}
	if !suite.test.clusterScoped {
		// extractKeyNamespace returns "" for cluster-scoped stores,
		// and repository.Count drops the namespace WHERE in that case,
		// so the per-namespace sub-case is only meaningful for namespaced resources.
		tests = append(tests, countCase{
			name:          "count entries in default namespace",
			key:           suite.defaultNamespaceKey(),
			expectedCount: 2,
		})
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			var count int64
			count, err = suite.store.Count(test.key)
			suite.Require().NoError(err)
			suite.Require().Equal(test.expectedCount, count)
		})
	}
}

func (suite *storeTestSuite) TestGetCurrentResourceVersion() {
	rv, err := suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(1), rv, "first call should initialize sequence to 1")

	rv, err = suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(1), rv, "second call should return same value")

	obj := suite.test.newObj("test", "default", nil, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test", "default"), obj, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	rv, err = suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(2), rv, "resource version should be 2 after creating one object")

	obj2 := suite.test.newObj("test2", "default", nil, nil)
	err = suite.store.Create(suite.T().Context(), suite.keyFor("test2", "default"), obj2, suite.test.newFunc(), 0)
	suite.Require().NoError(err)

	rv, err = suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(3), rv, "resource version should be 3 after creating two objects")
}

// keyFor builds a storage key appropriate for the configured scope.
// Namespaced resources produce `<prefix>/<namespace>/<name>`;
// cluster-scoped resources produce `<prefix>/<name>`.
func (suite *storeTestSuite) keyFor(name, namespace string) string {
	if suite.test.clusterScoped {
		return suite.test.keyPrefix + "/" + name
	}
	return suite.test.keyPrefix + "/" + namespace + "/" + name
}

// defaultNamespaceKey builds the list/count key for the "default" namespace.
// Cluster-scoped resources collapse to just the prefix.
func (suite *storeTestSuite) defaultNamespaceKey() string {
	if suite.test.clusterScoped {
		return suite.test.keyPrefix
	}
	return suite.test.keyPrefix + "/default"
}

// expectedNamespace is the namespace value that round-trips through storage.
// Cluster-scoped resources persist with empty namespace regardless of input.
func (suite *storeTestSuite) expectedNamespace(namespace string) string {
	if suite.test.clusterScoped {
		return ""
	}
	return namespace
}

// listItems returns each element of an object list as a runtime.Object,
// via the same reflection helper the store uses internally.
func (suite *storeTestSuite) listItems(listObj runtime.Object) []runtime.Object {
	itemsValue, err := getItems(listObj)
	suite.Require().NoError(err)

	out := make([]runtime.Object, 0, itemsValue.Len())
	for i := range itemsValue.Len() {
		item, ok := itemsValue.Index(i).Addr().Interface().(runtime.Object)
		suite.Require().True(ok, "list element does not implement runtime.Object")
		out = append(out, item)
	}
	return out
}

// listNames returns metadata.name for each item in the list.
func (suite *storeTestSuite) listNames(listObj runtime.Object) []string {
	items := suite.listItems(listObj)
	names := make([]string, 0, len(items))
	for _, item := range items {
		obj, ok := item.(metav1.Object)
		suite.Require().True(ok, "list element does not implement metav1.Object")
		names = append(names, obj.GetName())
	}
	return names
}

// natsSubject returns the NATS subject used by the configured resource.
func (suite *storeTestSuite) natsSubject() string {
	return "watch." + suite.test.resource
}

func mustParseLabelSelector(selector string) labels.Selector {
	labelSelector, err := labels.Parse(selector)
	if err != nil {
		panic("failed to parse label selector: " + err.Error())
	}

	return labelSelector
}

func mustParseFieldSelector(selector string) fields.Selector {
	fieldSelector, err := fields.ParseSelector(selector)
	if err != nil {
		panic("failed to parse field selector: " + err.Error())
	}
	return fieldSelector
}
