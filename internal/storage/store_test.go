package storage

import (
	"context"
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
	"k8s.io/utils/ptr"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

const keyPrefix = "/storage.sbomscanner.kubewarden.io/sboms"

type storeTestSuite struct {
	suite.Suite
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
	_, err := suite.db.Exec(suite.T().Context(), "TRUNCATE TABLE sboms")
	suite.Require().NoError(err, "failed to truncate table")

	_, err = suite.db.Exec(suite.T().Context(), "ALTER SEQUENCE resource_version_seq RESTART WITH 1")
	suite.Require().NoError(err, "failed to reset resource version sequence")

	repo := repository.NewGenericObjectRepository("sboms", func() runtime.Object { return &storagev1alpha1.SBOM{} })

	watchBroadcaster := watch.NewBroadcaster(1000, watch.WaitIfChannelFull)
	natsBroadcaster := newNatsBroadcaster(suite.nc, "sboms", watchBroadcaster, TransformStripSBOM, slog.Default())

	store := &store{
		db:          suite.db,
		repository:  repo,
		broadcaster: natsBroadcaster,
		newFunc:     func() runtime.Object { return &storagev1alpha1.SBOM{} },
		newListFunc: func() runtime.Object { return &storagev1alpha1.SBOMList{} },
		logger:      slog.Default(),
	}
	natsWatcher := newNatsWatcher(suite.nc, "sboms", watchBroadcaster, store, slog.Default())

	suite.store = store
	suite.broadcaster = watchBroadcaster
	suite.watcher = natsWatcher
}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, &storeTestSuite{})
}

func (suite *storeTestSuite) TestCreate() {
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		SPDX: runtime.RawExtension{Raw: []byte(`{"test": true}`)},
	}

	key := keyPrefix + "/default/test"
	out := &storagev1alpha1.SBOM{}
	err := suite.store.Create(suite.T().Context(), key, sbom, out, 0)
	suite.Require().NoError(err)

	suite.Equal("test", out.Name)
	suite.Equal("default", out.Namespace)
	suite.NotEmpty(out.ResourceVersion)
	suite.Equal([]byte(`{"test": true}`), out.SPDX.Raw)

	got := &storagev1alpha1.SBOM{}
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, got)
	suite.Require().NoError(err)
	suite.Equal(out, got)

	// Duplicate create should fail
	err = suite.store.Create(suite.T().Context(), key, sbom, out, 0)
	suite.Require().Equal(k8sstorage.NewKeyExistsError(key, 0).Error(), err.Error())
}

func (suite *storeTestSuite) TestGet() {
	key := keyPrefix + "/default/test"

	out := &storagev1alpha1.SBOM{}
	err := suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, out)
	suite.True(k8sstorage.IsNotFound(err))

	out = &storagev1alpha1.SBOM{}
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{IgnoreNotFound: true}, out)
	suite.Require().NoError(err)
	suite.Equal(&storagev1alpha1.SBOM{}, out)

	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		SPDX: runtime.RawExtension{Raw: []byte(`{"test": true}`)},
	}
	err = suite.store.Create(suite.T().Context(), key, sbom, nil, 0)
	suite.Require().NoError(err)

	out = &storagev1alpha1.SBOM{}
	err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, out)
	suite.Require().NoError(err)
	suite.Equal("test", out.Name)
	suite.Equal("default", out.Namespace)
	suite.Equal(map[string]string{"app": "test"}, out.Labels)
	suite.NotEmpty(out.ResourceVersion)
	suite.Equal([]byte(`{"test": true}`), out.SPDX.Raw)
}

func (suite *storeTestSuite) TestDelete() {
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	key := keyPrefix + "/default/test"

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
			err := suite.store.Create(suite.T().Context(), key, sbom, &storagev1alpha1.SBOM{}, 0)
			suite.Require().NoError(err)

			out := &storagev1alpha1.SBOM{}
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
				suite.Equal(sbom, out)

				err = suite.store.Get(suite.T().Context(), key, k8sstorage.GetOptions{}, &storagev1alpha1.SBOM{})
				suite.True(k8sstorage.IsNotFound(err))
			}
		})
	}
}

func (suite *storeTestSuite) TestDeleteNotFound() {
	key := keyPrefix + "/default/notfound"
	out := &storagev1alpha1.SBOM{}
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
	key := keyPrefix + "/default/test"
	opts := k8sstorage.ListOptions{ResourceVersion: ""}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	suite.broadcaster.Shutdown()

	suite.Require().Empty(w.ResultChan())
}

func (suite *storeTestSuite) TestWatchResourceVersionZero() {
	key := keyPrefix + "/default/test"
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}
	err := suite.store.Create(suite.T().Context(), key, sbom, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	opts := k8sstorage.ListOptions{ResourceVersion: "0"}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	go suite.watcher.Start(suite.T().Context())

	validateDeletion := func(_ context.Context, _ runtime.Object) error {
		return nil
	}
	err = suite.store.Delete(
		suite.T().Context(),
		key,
		&storagev1alpha1.SBOM{},
		&k8sstorage.Preconditions{},
		validateDeletion,
		nil,
		k8sstorage.DeleteOptions{},
	)
	suite.Require().NoError(err)

	events := mustReadEvents(suite.T(), w, 2)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(sbom, events[0].Object)
	suite.Equal(watch.Deleted, events[1].Type)
	suite.Equal(sbom, events[1].Object)
}

func (suite *storeTestSuite) TestWatchSpecificResourceVersion() {
	key := keyPrefix + "/default"
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}
	suite.Require().NoError(suite.store.Create(suite.T().Context(), key+"/test", sbom, &storagev1alpha1.SBOM{}, 0))

	opts := k8sstorage.ListOptions{
		ResourceVersion: "1",
		Predicate:       matcher(labels.Everything(), fields.Everything()),
	}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	go suite.watcher.Start(suite.T().Context())

	tryUpdate := func(input runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
		return input, ptr.To(uint64(0)), nil
	}
	updatedSBOM := &storagev1alpha1.SBOM{}
	err = suite.store.GuaranteedUpdate(
		suite.T().Context(),
		key+"/test",
		updatedSBOM,
		false,
		&k8sstorage.Preconditions{},
		tryUpdate,
		nil,
	)
	suite.Require().NoError(err)

	events := mustReadEvents(suite.T(), w, 2)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(sbom, events[0].Object)
	suite.Equal("1", sbom.ResourceVersion, "expected resource version 1 for the added event")
	suite.Equal(watch.Modified, events[1].Type)
	suite.Equal(updatedSBOM, events[1].Object)
}

func (suite *storeTestSuite) TestWatchWithLabelSelector() {
	key := keyPrefix + "/default"
	sbom1 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
			Labels: map[string]string{
				"sbomscanner.kubewarden.io/test": "true",
			},
		},
	}
	err := suite.store.Create(suite.T().Context(), key+"/test1", sbom1, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	sbom2 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
			Labels:    map[string]string{},
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test2", sbom2, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	opts := k8sstorage.ListOptions{
		ResourceVersion: "1",
		Predicate: matcher(labels.SelectorFromSet(labels.Set{
			"sbomscanner.kubewarden.io/test": "true",
		}), fields.Everything()),
	}
	w, err := suite.store.Watch(suite.T().Context(), key, opts)
	suite.Require().NoError(err)

	go suite.watcher.Start(suite.T().Context())

	events := mustReadEvents(suite.T(), w, 1)
	suite.Require().Len(events, 1)
	suite.Equal(watch.Added, events[0].Type)
	suite.Equal(sbom1, events[0].Object)
}

func (suite *storeTestSuite) TestWatchList() {
	key := keyPrefix + "/default"

	sbom1 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
		},
	}
	err := suite.store.Create(suite.T().Context(), key+"/test1", sbom1, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	sbom2 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test2", sbom2, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	predicate := matcher(labels.Everything(), fields.Everything())
	predicate.AllowWatchBookmarks = true

	opts := k8sstorage.ListOptions{
		SendInitialEvents: ptr.To(true),
		Predicate:         predicate,
		Recursive:         true,
	}

	w, err := suite.store.Watch(suite.T().Context(), key, opts)
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
		sbom, ok := evt.Object.(*storagev1alpha1.SBOM)
		suite.Require().True(ok)
		addedNames = append(addedNames, sbom.Name)
	}
	suite.ElementsMatch([]string{"test1", "test2"}, addedNames)

	// Last event should be BOOKMARK with the initial-events-end annotation
	bookmarkEvent := events[2]
	suite.Equal(watch.Bookmark, bookmarkEvent.Type)

	bookmarkObj, ok := bookmarkEvent.Object.(*storagev1alpha1.SBOM)
	suite.Require().True(ok)
	suite.Equal("true", bookmarkObj.Annotations["k8s.io/initial-events-end"])
	suite.NotEmpty(bookmarkObj.ResourceVersion)
}

func (suite *storeTestSuite) TestGetList() {
	key := keyPrefix + "/default"
	sbom1 := storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
			Labels: map[string]string{
				"sbomscanner.kubewarden.io/env": "test",
			},
		},
	}
	err := suite.store.Create(suite.T().Context(), key+"/test1", &sbom1, nil, 0)
	suite.Require().NoError(err)

	sbom2 := storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
			Labels: map[string]string{
				"sbomscanner.kubewarden.io/env": "dev",
			},
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test2", &sbom2, nil, 0)
	suite.Require().NoError(err)

	sbom3 := storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test3",
			Namespace: "default",
			Labels: map[string]string{
				"sbomscanner.kubewarden.io/env":      "prod",
				"sbomscanner.kubewarden.io/critical": "true",
			},
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test3", &sbom3, nil, 0)
	suite.Require().NoError(err)

	tests := []struct {
		name          string
		listOptions   k8sstorage.ListOptions
		expectedItems []storagev1alpha1.SBOM
	}{
		{
			name:          "list all",
			expectedItems: []storagev1alpha1.SBOM{sbom1, sbom2, sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(labels.Everything(), fields.Everything()),
			},
		},
		{
			name:          "list label selector (=)",
			expectedItems: []storagev1alpha1.SBOM{sbom1},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("sbomscanner.kubewarden.io/env=test"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (!=)",
			expectedItems: []storagev1alpha1.SBOM{sbom2, sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("sbomscanner.kubewarden.io/env!=test"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (in)",
			expectedItems: []storagev1alpha1.SBOM{sbom2, sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("sbomscanner.kubewarden.io/env in (dev,prod)"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (notin)",
			expectedItems: []storagev1alpha1.SBOM{sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("sbomscanner.kubewarden.io/env notin (test,dev)"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (exists)",
			expectedItems: []storagev1alpha1.SBOM{sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("sbomscanner.kubewarden.io/critical"), fields.Everything()),
			},
		},
		{
			name:          "list label selector (does not exist)",
			expectedItems: []storagev1alpha1.SBOM{sbom1, sbom2},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(mustParseLabelSelector("!sbomscanner.kubewarden.io/critical"), fields.Everything()),
			},
		},
		{
			name:          "list field selector (=)",
			expectedItems: []storagev1alpha1.SBOM{sbom1},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(labels.Everything(), mustParseFieldSelector("metadata.name=test1")),
			},
		},
		{
			name:          "list field selector (!=)",
			expectedItems: []storagev1alpha1.SBOM{sbom2, sbom3},
			listOptions: k8sstorage.ListOptions{
				Predicate: matcher(labels.Everything(), mustParseFieldSelector("metadata.name!=test1")),
			},
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			sbomList := &storagev1alpha1.SBOMList{}
			err = suite.store.GetList(suite.T().Context(), key, test.listOptions, sbomList)
			suite.Require().NoError(err)
			suite.ElementsMatch(test.expectedItems, sbomList.Items)
		})
	}
}

func (suite *storeTestSuite) TestGetListWithPagination() {
	key := keyPrefix + "/default"

	for i := 1; i <= 5; i++ {
		sbom := &storagev1alpha1.SBOM{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test%d", i),
				Namespace: "default",
				Labels: map[string]string{
					"sbomscanner.kubewarden.io/env": map[bool]string{true: "prod", false: "dev"}[i%2 == 0],
				},
			},
		}
		err := suite.store.Create(suite.T().Context(), fmt.Sprintf("%s/test%d", key, i), sbom, nil, 0)
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
				Predicate: matcher(test.labelSelector, test.fieldSelector),
			}
			opts.Predicate.Limit = test.limit

			for i, expectedNames := range test.expectedPages {
				sbomList := &storagev1alpha1.SBOMList{}
				err := suite.store.GetList(suite.T().Context(), key, opts, sbomList)
				suite.Require().NoError(err)

				var names []string
				for _, item := range sbomList.Items {
					names = append(names, item.Name)
				}
				suite.Equal(expectedNames, names, "page %d", i+1)

				isLastPage := i == len(test.expectedPages)-1
				if isLastPage {
					suite.Empty(sbomList.Continue)
				} else {
					suite.NotEmpty(sbomList.Continue)
				}

				opts.Predicate.Continue = sbomList.Continue
			}
		})
	}
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

func (suite *storeTestSuite) TestGetListResourceVersionSemanntics() {
	key := keyPrefix + "/default"

	// Create some objects to get different RVs
	sbom1 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
		},
	}
	err := suite.store.Create(suite.T().Context(), key+"/test1", sbom1, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	sbom2 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test2", sbom2, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	sbom3 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test3",
			Namespace: "default",
		},
	}
	err = suite.store.Create(suite.T().Context(), key+"/test3", sbom3, &storagev1alpha1.SBOM{}, 0)
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
				Predicate:       matcher(labels.Everything(), fields.Everything()),
			}

			sbomList := &storagev1alpha1.SBOMList{}
			err := suite.store.GetList(suite.T().Context(), key, opts, sbomList)
			suite.Require().NoError(err)

			var names []string
			for _, item := range sbomList.Items {
				names = append(names, item.Name)
			}
			suite.ElementsMatch(test.expectedNames, names)

			if test.expectNewRV {
				suite.NotEmpty(sbomList.ResourceVersion)
				listRV, err := strconv.ParseUint(sbomList.ResourceVersion, 10, 64)
				suite.Require().NoError(err)
				suite.Greater(listRV, uint64(3), "list RV should be a newly generated value")
			}

			if test.expectedListRV != "" {
				suite.Equal(test.expectedListRV, sbomList.ResourceVersion)
			}
		})
	}
}

func (suite *storeTestSuite) TestGuaranteedUpdate() {
	tests := []struct {
		name                string
		key                 string
		ignoreNotFound      bool
		preconditions       *k8sstorage.Preconditions
		tryUpdate           k8sstorage.UpdateFunc
		sbom                *storagev1alpha1.SBOM
		expectedUpdatedSBOM *storagev1alpha1.SBOM
		expectedError       error
	}{
		{
			name:          "happy path",
			key:           keyPrefix + "/default/test1",
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(input runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				sbom, ok := input.(*storagev1alpha1.SBOM)
				if !ok {
					return nil, ptr.To(uint64(0)), errors.New("input is not of type *v1alpha1.SBOM")
				}

				sbom.SPDX.Raw = []byte(`{"foo": "bar"}`)

				return input, ptr.To(uint64(0)), nil
			},
			sbom: &storagev1alpha1.SBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test1",
					Namespace: "default",
					UID:       "test1-uid",
				},
				SPDX: runtime.RawExtension{
					Raw: []byte("{}"),
				},
			},
			expectedUpdatedSBOM: &storagev1alpha1.SBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test1",
					Namespace:       "default",
					UID:             "test1-uid",
					ResourceVersion: "2",
				},
				SPDX: runtime.RawExtension{
					Raw: []byte(`{"foo": "bar"}`),
				},
			},
		},
		{
			name: "preconditions failed",
			key:  keyPrefix + "/default/test2",
			preconditions: &k8sstorage.Preconditions{
				UID: ptr.To(types.UID("incorrect-uid")),
			},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when preconditions fail")
				return nil, nil, nil
			},
			sbom: &storagev1alpha1.SBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test2",
					Namespace: "default",
					UID:       "test2-uid",
				},
				SPDX: runtime.RawExtension{
					Raw: []byte("{}"),
				},
			},
			expectedError: k8sstorage.NewInvalidObjError(keyPrefix+"/default/test2",
				"Precondition failed: UID in precondition: incorrect-uid, UID in object meta: test2-uid"),
		},
		{
			name:          "tryUpdate failed with a non-conflict error",
			key:           keyPrefix + "/default/test3",
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				return nil, nil, k8sstorage.NewInternalError(errors.New("tryUpdate failed"))
			},
			sbom: &storagev1alpha1.SBOM{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test3",
					Namespace: "default",
					UID:       "test3-uid",
				},
				SPDX: runtime.RawExtension{
					Raw: []byte("{}"),
				},
			},
			expectedError: k8sstorage.NewInternalError(errors.New("tryUpdate failed")),
		},
		{
			name:          "not found",
			key:           keyPrefix + "/default/notfound",
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when object is not found")
				return nil, nil, nil
			},
			expectedError: k8sstorage.NewKeyNotFoundError(keyPrefix+"/default/notfound", 0),
		},
		{
			name:          "not found with ignore not found",
			key:           keyPrefix + "/default/notfound",
			preconditions: &k8sstorage.Preconditions{},
			tryUpdate: func(_ runtime.Object, _ k8sstorage.ResponseMeta) (runtime.Object, *uint64, error) {
				suite.Fail("tryUpdate should not be called when object is not found")
				return nil, nil, nil
			},
			ignoreNotFound:      true,
			expectedUpdatedSBOM: &storagev1alpha1.SBOM{},
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			if test.sbom != nil {
				err := suite.store.Create(suite.T().Context(), test.key, test.sbom, &storagev1alpha1.SBOM{}, 0)
				suite.Require().NoError(err)
			}

			destinationSBOM := &storagev1alpha1.SBOM{}
			err := suite.store.GuaranteedUpdate(
				suite.T().Context(),
				test.key,
				destinationSBOM,
				test.ignoreNotFound,
				test.preconditions,
				test.tryUpdate,
				nil,
			)

			currentSBOM := &storagev1alpha1.SBOM{}
			if test.expectedError != nil {
				suite.Require().Error(err)
				suite.Require().Equal(test.expectedError.Error(), err.Error())

				if test.sbom != nil {
					// If there is an error, the original object should not be updated.
					err = suite.store.Get(suite.T().Context(), test.key, k8sstorage.GetOptions{}, currentSBOM)
					suite.Require().NoError(err)
					suite.Equal(test.sbom, currentSBOM)
				}
			} else {
				suite.Require().NoError(err)
				suite.Require().Equal(test.expectedUpdatedSBOM, destinationSBOM)

				if !test.ignoreNotFound {
					// Verify the object was updated in the store.
					err = suite.store.Get(suite.T().Context(), test.key, k8sstorage.GetOptions{}, currentSBOM)
					suite.Require().NoError(err)
					suite.Equal(test.expectedUpdatedSBOM, currentSBOM)
				}
			}
		})
	}
}

func (suite *storeTestSuite) TestCount() {
	err := suite.store.Create(suite.T().Context(), keyPrefix+"/default/test1", &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
		},
	}, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	err = suite.store.Create(suite.T().Context(), keyPrefix+"/default/test2", &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
		},
	}, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	err = suite.store.Create(suite.T().Context(), keyPrefix+"/other/test4", &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test4",
			Namespace: "other",
		},
	}, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	tests := []struct {
		name          string
		key           string
		expectedCount int64
	}{
		{
			name:          "count entries in default namespace",
			key:           keyPrefix + "/default",
			expectedCount: 2,
		},
		{
			name:          "count all entries",
			key:           keyPrefix,
			expectedCount: 3,
		},
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

	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    "test-registry",
			RegistryURI: "registry-1.docker.io:5000",
			Repository:  "kubewarden/rv-test",
			Tag:         "v1.0.0",
			Platform:    "linux/amd64",
			Digest:      "sha256:rv-test",
		},
	}
	err = suite.store.Create(suite.T().Context(), keyPrefix+"/default/test", sbom, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	rv, err = suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(2), rv, "resource version should be 2 after creating one object")

	sbom2 := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    "test-registry",
			RegistryURI: "registry-1.docker.io:5000",
			Repository:  "kubewarden/rv-test-2",
			Tag:         "v1.0.0",
			Platform:    "linux/amd64",
			Digest:      "sha256:rv-test-2",
		},
	}
	err = suite.store.Create(suite.T().Context(), keyPrefix+"/default/test2", sbom2, &storagev1alpha1.SBOM{}, 0)
	suite.Require().NoError(err)

	rv, err = suite.store.GetCurrentResourceVersion(suite.T().Context())
	suite.Require().NoError(err)
	suite.Equal(uint64(3), rv, "resource version should be 3 after creating two objects")
}
