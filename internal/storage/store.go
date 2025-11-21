//nolint:wrapcheck // We want to return the errors from k8s.io/apiserver/pkg/storage as they are.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
)

// objectSchema is the schema of an object in the database.
// Note: the struct fields must be exported in order to work.
type objectSchema struct {
	Name      string `db:"name"`
	Namespace string `db:"namespace"`
	Object    []byte `db:"object"`
}

var _ storage.Interface = &store{}

type store struct {
	db          *pgxpool.Pool
	broadcaster *natsBroadcaster
	table       string
	newFunc     func() runtime.Object
	newListFunc func() runtime.Object
	logger      *slog.Logger
}

// Versioner returns API object versioner associated with this interface.
func (s *store) Versioner() storage.Versioner {
	return storage.APIObjectVersioner{}
}

// Create adds a new object at a key unless it already exists. 'ttl' is time-to-live
// in seconds (0 means forever). If no error is returned and out is not nil, out will be
// set to the read value from database.
func (s *store) Create(ctx context.Context, key string, obj, out runtime.Object, _ uint64) error {
	s.logger.DebugContext(ctx, "Creating object", "key", key, "object", obj)

	name, namespace := extractNameAndNamespace(key)
	if name == "" || namespace == "" {
		return storage.NewInternalError(fmt.Errorf("invalid key: %s", key))
	}

	if err := s.Versioner().UpdateObject(obj, 1); err != nil {
		return storage.NewInternalError(err)
	}

	bytes, err := json.Marshal(obj)
	if err != nil {
		return storage.NewInternalError(err)
	}

	query, args, err := psql.Insert(
		im.Into(psql.Quote(s.table)),
		im.Values(psql.Arg(name), psql.Arg(namespace), psql.Arg(bytes)),
		im.OnConflict().DoNothing(),
	).Build(ctx)
	if err != nil {
		return storage.NewInternalError(err)
	}

	result, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return storage.NewInternalError(err)
	}

	if result.RowsAffected() == 0 {
		return storage.NewKeyExistsError(key, 0)
	}

	if err = s.broadcaster.Action(watch.Added, obj); err != nil {
		return storage.NewInternalError(err)
	}

	if out != nil {
		if err = setValue(obj, out); err != nil {
			return err
		}
	}

	return nil
}

// Delete removes the specified key and returns the value that existed at that spot.
// If key didn't exist, it will return NotFound storage error.
// If 'cachedExistingObject' is non-nil, it can be used as a suggestion about the
// current version of the object to avoid read operation from storage to get it.
// However, the implementations have to retry in case suggestion is stale.
func (s *store) Delete(
	ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions,
	validateDeletion storage.ValidateObjectFunc, _ runtime.Object, _ storage.DeleteOptions,
) error {
	s.logger.DebugContext(ctx, "Deleting object", "key", key)

	name, namespace := extractNameAndNamespace(key)
	if name == "" || namespace == "" {
		return storage.NewInternalError(fmt.Errorf("invalid key: %s", key))
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return storage.NewInternalError(err)
	}
	defer func() {
		if err = tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			s.logger.ErrorContext(ctx, "failed to rollback transaction", "error", err)
		}
	}()

	query, args, err := psql.Delete(
		dm.From(psql.Quote(s.table)),
		dm.Where(psql.Quote("name").EQ(psql.Arg(name))),
		dm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		dm.Returning("name", "namespace", "object"),
	).Build(ctx)

	var objectRecord objectSchema
	err = tx.QueryRow(ctx, query, args...).Scan(
		&objectRecord.Name,
		&objectRecord.Namespace,
		&objectRecord.Object,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.NewKeyNotFoundError(key, 0)
		}
		return storage.NewInternalError(err)
	}

	if err = json.Unmarshal(objectRecord.Object, out); err != nil {
		return storage.NewInternalError(err)
	}

	if err = preconditions.Check(key, out); err != nil {
		return err
	}

	if err = validateDeletion(ctx, out); err != nil {
		return err
	}

	if err = tx.Commit(ctx); err != nil {
		return storage.NewInternalError(err)
	}

	if err = s.broadcaster.Action(watch.Deleted, out); err != nil {
		return storage.NewInternalError(err)
	}

	return nil
}

// Watch begins watching the specified key. Events are decoded into API objects,
// and any items selected by the options in 'opts' are sent down to returned watch.Interface.
// resourceVersion may be used to specify what version to begin watching,
// which should be the current resourceVersion, and no longer rv+1
// (e.g. reconnecting without missing any updates).
// If resource version is "0", this interface will get current object at given key
// and send it in an "ADDED" event, before watch starts.
func (s *store) Watch(ctx context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	s.logger.DebugContext(
		ctx,
		"Watching object",
		"key",
		key,
		"resourceVersion",
		opts.ResourceVersion,
		"progressNotify",
		opts.ProgressNotify,
	)

	if opts.ResourceVersion == "" {
		return s.broadcaster.Watch()
	}

	if opts.ResourceVersion == "0" {
		obj := s.newFunc()
		if err := s.Get(ctx, key, storage.GetOptions{}, obj); err != nil {
			return nil, err
		}

		return s.broadcaster.WatchWithPrefix([]watch.Event{{Type: watch.Added, Object: obj}})
	}

	listObj := s.newListFunc()
	if err := s.GetList(ctx, key, opts, listObj); err != nil {
		return nil, err
	}

	itemsValue, err := getItems(listObj)
	if err != nil {
		return nil, err
	}

	var events []watch.Event
	for i := range itemsValue.Len() {
		// Cast the item address to a runtime.Object
		item, ok := itemsValue.Index(i).Addr().Interface().(runtime.Object)
		if !ok {
			return nil, storage.NewInternalError(
				fmt.Errorf("unexpected item type: %T", itemsValue.Index(i).Addr().Interface()),
			)
		}

		events = append(events, watch.Event{
			Type:   watch.Added,
			Object: item,
		})
	}

	return s.broadcaster.WatchWithPrefix(events)
}

// Get unmarshals object found at key into objPtr. On a not found error, will either
// return a zero object of the requested type, or an error, depending on 'opts.ignoreNotFound'.
// Treats empty responses and nil response nodes exactly like a not found error.
// The returned contents may be delayed, but it is guaranteed that they will
// match 'opts.ResourceVersion' according 'opts.ResourceVersionMatch'.
func (s *store) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
	s.logger.DebugContext(
		ctx,
		"Getting object",
		"key",
		key,
		"ignoreNotFound",
		opts.IgnoreNotFound,
		"resourceVersion",
		opts.ResourceVersion,
	)

	name, namespace := extractNameAndNamespace(key)
	if name == "" || namespace == "" {
		return storage.NewInternalError(fmt.Errorf("invalid key: %s", key))
	}

	if err := runtime.SetZeroValue(objPtr); err != nil {
		return storage.NewInternalError(fmt.Errorf("unable to set objPtr zero value: %w", err))
	}

	query, args, err := psql.Select(
		sm.Columns("name", "namespace", "object"),
		sm.From(psql.Quote(s.table)),
		sm.Where(psql.Quote("name").EQ(psql.Arg(name))),
		sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
	).Build(ctx)
	if err != nil {
		return storage.NewInternalError(err)
	}

	var objectRecord objectSchema
	err = s.db.QueryRow(ctx, query, args...).Scan(
		&objectRecord.Name,
		&objectRecord.Namespace,
		&objectRecord.Object,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if opts.IgnoreNotFound {
				return nil
			}
			return storage.NewKeyNotFoundError(key, 0)
		}
		return storage.NewInternalError(err)
	}

	err = json.Unmarshal(objectRecord.Object, objPtr)
	if err != nil {
		return storage.NewInternalError(err)
	}

	return nil
}

// GetList unmarshalls objects found at key into a *List api object (an object
// that satisfies runtime.IsList definition).
// The returned contents may be delayed, but it is guaranteed that they will
// match 'opts.ResourceVersion' according 'opts.ResourceVersionMatch'.
//
//nolint:gocognit // This function can't be easily split into smaller parts.
func (s *store) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	s.logger.DebugContext(ctx, "Getting list",
		"key", key,
		"resourceVersion", opts.ResourceVersion,
		"labelSelector", opts.Predicate.Label.String(),
		"fieldSelector", opts.Predicate.Field.String(),
		"limit", opts.Predicate.Limit,
		"continue", opts.Predicate.Continue,
	)

	queryBuilder := psql.Select(
		sm.From(psql.Quote(s.table)),
		sm.Columns("name", "namespace", "object"),
	)

	namespace := extractNamespace(key)
	if namespace != "" {
		queryBuilder.Apply(
			sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		)
	}

	if opts.Predicate.Label != nil {
		labelSelectorExpressions, err := buildLabelSelectorExpressions(opts.Predicate.Label)
		if err != nil {
			return storage.NewInternalError(err)
		}
		for _, expression := range labelSelectorExpressions {
			queryBuilder.Apply(sm.Where(expression))
		}
	}

	if opts.Predicate.Field != nil {
		fieldSelectorExpressions, err := buildFieldSelectorExpressions(opts.Predicate.Field)
		if err != nil {
			return storage.NewInternalError(err)
		}
		for _, expression := range fieldSelectorExpressions {
			queryBuilder.Apply(sm.Where(expression))
		}
	}

	query, args, err := queryBuilder.Build(ctx)
	if err != nil {
		return storage.NewInternalError(err)
	}

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return storage.NewInternalError(err)
	}
	defer rows.Close()

	itemsValue, err := getItems(listObj)
	if err != nil {
		return err
	}

	for rows.Next() {
		var objectRecord objectSchema
		err = rows.Scan(
			&objectRecord.Name,
			&objectRecord.Namespace,
			&objectRecord.Object,
		)
		if err != nil {
			return storage.NewInternalError(err)
		}

		obj := s.newFunc()
		if err = json.Unmarshal(objectRecord.Object, obj); err != nil {
			return storage.NewInternalError(err)
		}

		// Append the object to the items slice
		itemsValue.Set(reflect.Append(itemsValue, reflect.ValueOf(obj).Elem()))
	}

	if err = rows.Err(); err != nil {
		return storage.NewInternalError(err)
	}

	// TODO: Implement pagination and use a proper resourceVersion
	if err = s.Versioner().UpdateList(listObj, 1, "", nil); err != nil {
		return storage.NewInternalError(err)
	}

	return nil
}

// GuaranteedUpdate keeps calling 'tryUpdate()' to update key 'key' (of type 'destination')
// retrying the update until success if there is index conflict.
// Note that object passed to tryUpdate may change across invocations of tryUpdate() if
// other writers are simultaneously updating it, so tryUpdate() needs to take into account
// the current contents of the object when deciding how the update object should look.
// If the key doesn't exist, it will return NotFound storage error if ignoreNotFound=false
// else `destination` will be set to the zero value of it's type.
// If the eventual successful invocation of `tryUpdate` returns an output with the same serialized
// contents as the input, it won't perform any update, but instead set `destination` to an object with those
// contents.
// If 'cachedExistingObject' is non-nil, it can be used as a suggestion about the
// current version of the object to avoid read operation from storage to get it.
// However, the implementations have to retry in case suggestion is stale.
//
// Example:
//
// s := /* implementation of Interface */
// err := s.GuaranteedUpdate(
//
//	 "myKey", &MyType{}, true, preconditions,
//	 func(input runtime.Object, res ResponseMeta) (runtime.Object, *uint64, error) {
//	   // Before each invocation of the user defined function, "input" is reset to
//	   // current contents for "myKey" in database.
//	   curr := input.(*MyType)  // Guaranteed to succeed.
//
//	   // Make the modification
//	   curr.Counter++
//
//	   // Return the modified object - return an error to stop iterating. Return
//	   // a uint64 to alter the TTL on the object, or nil to keep it the same value.
//	   return cur, nil, nil
//	}, cachedExistingObject
//
// )
//
//nolint:gocognit,funlen // This functions can't be easily split into smaller parts.
func (s *store) GuaranteedUpdate(
	ctx context.Context,
	key string,
	destination runtime.Object,
	ignoreNotFound bool,
	preconditions *storage.Preconditions,
	tryUpdate storage.UpdateFunc,
	_ runtime.Object,
) error {
	s.logger.DebugContext(ctx, "Guaranteed update", "key", key)

	name, namespace := extractNameAndNamespace(key)
	if name == "" || namespace == "" {
		return storage.NewInternalError(fmt.Errorf("invalid key: %s", key))
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err = tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			s.logger.ErrorContext(ctx, "failed to rollback transaction", "error", err)
		}
	}()

	for {
		query, args, err := psql.Select(
			sm.Columns("name", "namespace", "object"),
			sm.From(psql.Quote(s.table)),
			sm.Where(psql.Quote("name").EQ(psql.Arg(name))),
			sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		).Build(ctx)
		if err != nil {
			return storage.NewInternalError(err)
		}

		if err = runtime.SetZeroValue(destination); err != nil {
			return storage.NewInternalError(fmt.Errorf("unable to set destination to zero value: %w", err))
		}

		var objectRecord objectSchema
		err = tx.QueryRow(ctx, query, args...).Scan(
			&objectRecord.Name,
			&objectRecord.Namespace,
			&objectRecord.Object,
		)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				if !ignoreNotFound {
					return storage.NewKeyNotFoundError(key, 0)
				}
				return nil
			}
			return err
		}

		obj := s.newFunc()
		err = json.Unmarshal(objectRecord.Object, obj)
		if err != nil {
			return storage.NewInternalError(err)
		}

		err = preconditions.Check(key, obj)
		if err != nil {
			return err
		}

		var updatedObj runtime.Object
		updatedObj, _, err = tryUpdate(obj, storage.ResponseMeta{})
		if err != nil {
			if apierrors.IsConflict(err) && strings.Contains(err.Error(), registry.OptimisticLockErrorMsg) {
				s.logger.DebugContext(ctx, "Optimistic lock conflict", "key", key, "error", err)

				// retry update on optimistic lock conflict
				continue
			}
			return err
		}

		var version uint64
		version, err = s.Versioner().ObjectResourceVersion(obj)
		if err != nil {
			return storage.NewInternalError(err)
		}
		if err = s.Versioner().UpdateObject(updatedObj, version+1); err != nil {
			return storage.NewInternalError(err)
		}

		var bytes []byte
		bytes, err = json.Marshal(updatedObj)
		if err != nil {
			return storage.NewInternalError(err)
		}

		updateQuery, updateArgs, err := psql.Update(
			um.Table(psql.Quote(s.table)),
			um.SetCol("object").To(psql.Arg(bytes)),
			um.Where(psql.Quote("name").EQ(psql.Arg(name))),
			um.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		).Build(ctx)
		if err != nil {
			return storage.NewInternalError(err)
		}

		_, err = tx.Exec(ctx, updateQuery, updateArgs...)
		if err != nil {
			return storage.NewInternalError(err)
		}

		if err = tx.Commit(ctx); err != nil {
			return storage.NewInternalError(err)
		}

		if err = s.broadcaster.Action(watch.Modified, updatedObj); err != nil {
			return storage.NewInternalError(err)
		}

		if err = setValue(updatedObj, destination); err != nil {
			return err
		}

		break
	}

	return nil
}

// Count returns number of different entries under the key (generally being path prefix).
func (s *store) Count(key string) (int64, error) {
	s.logger.Debug("Counting objects", "key", key)

	namespace := extractNamespace(key)

	queryBuilder := psql.Select(
		sm.Columns("COUNT(*)"),
		sm.From(psql.Quote(s.table)),
	)

	if namespace != "" {
		queryBuilder.Apply(
			sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))),
		)
	}

	query, args, err := queryBuilder.Build(context.Background())
	if err != nil {
		return 0, storage.NewInternalError(err)
	}

	var count int64
	err = s.db.QueryRow(context.Background(), query, args...).Scan(&count)
	if err != nil {
		return 0, storage.NewInternalError(err)
	}

	return count, nil
}

// Stats returns storage stats.
//
// TODO: this is a dummy implementation to satisfy the storage.Interface.
func (s *store) Stats(_ context.Context) (storage.Stats, error) {
	return storage.Stats{}, nil
}

// ReadinessCheck checks if the storage is ready for accepting requests.
func (s *store) ReadinessCheck() error {
	return nil
}

// CompactRevision returns latest observed revision that was compacted.
// Without ListFromCacheSnapshot enabled only locally executed compaction will be observed.
// Returns 0 if no compaction was yet observed.
func (s *store) CompactRevision() int64 {
	// Return 0, as we don't have compaction in SQL storage.
	return 0
}

// SetKeysFunc allows to override the function used to get keys from storage.
// This allows to replace default function that fetches keys from storage with one using cache.
func (s *store) SetKeysFunc(_ storage.KeysFunc) {
	// No-op, we don't have a cache implementation.
}

// RequestWatchProgress requests the a watch stream progress status be sent in the
// watch response stream as soon as possible.
// Used for monitor watch progress even if watching resources with no changes.
//
// If watch is lagging, progress status might:
// * be pointing to stale resource version. Use etcd KV request to get linearizable resource version.
// * not be delivered at all. It's recommended to poll request progress periodically.
//
// Note: Only watches with matching context grpc metadata will be notified.
// https://github.com/kubernetes/kubernetes/blob/9325a57125e8502941d1b0c7379c4bb80a678d5c/vendor/go.etcd.io/etcd/client/v3/watch.go#L1037-L1042
//
// TODO: Remove when storage.Interface will be separate from etc3.store.
// Deprecated: Added temporarily to simplify exposing RequestProgress for watch cache.
func (s *store) RequestWatchProgress(_ context.Context) error {
	// As this is a deprecated method, we are not implementing it.
	return nil
}

// GetCurrentResourceVersion gets the current resource version from etcd.
// This method issues an empty list request and reads only the ResourceVersion from the object metadata
//
// TODO: this is a dummy implementation to satisfy the storage.Interface.
func (s *store) GetCurrentResourceVersion(_ context.Context) (uint64, error) {
	return 0, nil
}

// extractNameAndNamespace extracts the name and namespace from the key.
// Used for single object operations.
// Key format: /storage.sbomscanner.kubewarden.io/<resource>/<namespace>/<name>
func extractNameAndNamespace(key string) (string, string) {
	key = strings.TrimPrefix(key, "/")
	parts := strings.Split(key, "/")
	if len(parts) == 4 {
		return parts[3], parts[2]
	}

	return "", ""
}

// extractNamespace extracts the namespace from the key.
// Used for list operations.
// Key format: /storage.sbomscanner.kubewarden.io/<resource>/<namespace>
func extractNamespace(key string) string {
	key = strings.TrimPrefix(key, "/")
	parts := strings.Split(key, "/")
	if len(parts) == 3 {
		return parts[2]
	}

	return ""
}

// setValue sets the value of 'dest' to the value of 'source' after converting them to pointers.
func setValue(source, dest runtime.Object) error {
	destValue, err := conversion.EnforcePtr(dest)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("unable to convert destination object to pointer: %w", err))
	}

	sourceValue, err := conversion.EnforcePtr(source)
	if err != nil {
		return storage.NewInternalError(fmt.Errorf("unable to convert source object to pointer: %w", err))
	}

	destValue.Set(sourceValue)
	return nil
}

// getItems retrieves the items slice pointer from the provided ObjectList.
func getItems(listObj runtime.Object) (reflect.Value, error) {
	// Access the items field of the list object using reflection
	itemsPtr, err := meta.GetItemsPtr(listObj)
	if err != nil {
		return reflect.Value{}, storage.NewInternalError(fmt.Errorf("unable to get items pointer: %w", err))
	}

	itemsValue, err := conversion.EnforcePtr(itemsPtr)
	if err != nil || itemsValue.Kind() != reflect.Slice {
		return reflect.Value{}, storage.NewInternalError(fmt.Errorf("need pointer to slice: %w", err))
	}

	return itemsValue, nil
}

// buildLabelSelectorExpressions builds SQL expressions from the provided k8s label selector
// using PostgreSQL JSONB operators.
func buildLabelSelectorExpressions(labelSelector labels.Selector) ([]psql.Expression, error) {
	var expressions []psql.Expression
	requirements, selectable := labelSelector.Requirements()
	if !selectable {
		return expressions, nil
	}

	for _, req := range requirements {
		var expression psql.Expression

		switch req.Operator() {
		case selection.Equals, selection.DoubleEquals:
			expression = psql.Raw("object->'metadata'->'labels'->>?", req.Key()).EQ(psql.Arg(req.Values().List()[0]))
		case selection.NotEquals:
			expression = psql.Raw("object->'metadata'->'labels'->>?", req.Key()).NE(psql.Arg(req.Values().List()[0]))
		case selection.In:
			expression = psql.Raw("object->'metadata'->'labels'->>? = ANY(?)", req.Key(), req.Values().List())
		case selection.NotIn:
			expression = psql.Raw("object->'metadata'->'labels'->>? != ALL(?)", req.Key(), req.Values().List())
		case selection.Exists:
			expression = psql.Raw("jsonb_exists(object->'metadata'->'labels', ?)", req.Key())
		case selection.DoesNotExist:
			expression = psql.Not(psql.Raw("jsonb_exists(object->'metadata'->'labels', ?)", req.Key()))
		case selection.GreaterThan, selection.LessThan:
			return nil, fmt.Errorf("unsupported label selector operator: %s", req.Operator())
		}

		expressions = append(expressions, expression)
	}

	return expressions, nil
}

// buildFieldSelectorExpressions builds SQL expressions from the provided k8s field selector
// using PostgreSQL JSONB operators.
func buildFieldSelectorExpressions(fieldSelector fields.Selector) ([]psql.Expression, error) {
	var expressions []psql.Expression
	requirements := fieldSelector.Requirements()

	for _, req := range requirements {
		// Convert dot notation to JSON path
		// "metadata.name" -> {metadata,name}
		pathParts := strings.Split(req.Field, ".")
		jsonPath := "{" + strings.Join(pathParts, ",") + "}"

		var expression psql.Expression

		switch req.Operator {
		case selection.Equals, selection.DoubleEquals:
			expression = psql.Raw("object #>> ?", jsonPath).EQ(psql.Arg(req.Value))
		case selection.NotEquals:
			expression = psql.Raw("object #>> ?", jsonPath).NE(psql.Arg(req.Value))
		case selection.In, selection.NotIn, selection.Exists, selection.DoesNotExist, selection.GreaterThan, selection.LessThan:
			return nil, fmt.Errorf("unsupported field selector operator: %v", req.Operator)
		}

		expressions = append(expressions, expression)
	}
	return expressions, nil
}
