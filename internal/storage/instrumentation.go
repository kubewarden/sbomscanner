package storage

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
)

// Bounded storage.result span attribute values.
const (
	storageResultSuccess       = "success"
	storageResultNotFound      = "not_found"
	storageResultAlreadyExists = "already_exists"
	storageResultError         = "error"
)

// objectNameKey is the span attribute carrying the object name.
// There is no OTel semantic convention for the name of an arbitrary Kubernetes object.
const objectNameKey = attribute.Key("k8s.object.name")

// Instrumentation bundles the tracer and the metric instruments shared by the stores
// and the watch fan-out.
// Disabled telemetry is represented by no-op providers.
type Instrumentation struct {
	tracer      trace.Tracer
	watchEvents metric.Int64Counter
}

// NewInstrumentation creates a new Instrumentation.
func NewInstrumentation(tracer trace.Tracer, meter metric.Meter) (*Instrumentation, error) {
	watchEvents, err := meter.Int64Counter(
		"storage.watch.events",
		metric.WithDescription("Number of watch events distributed across the storage replicas."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating storage.watch.events counter: %w", err)
	}

	return &Instrumentation{
		tracer:      tracer,
		watchEvents: watchEvents,
	}, nil
}

// startPublishSpan opens the producer span for one watch event publication.
// The caller is responsible for ending the returned span.
//
//nolint:spancheck // The span deliberately outlives this helper.
func (i *Instrumentation) startPublishSpan(ctx context.Context, subject string, eventType watch.EventType) (context.Context, trace.Span) {
	return i.tracer.Start(ctx, "NatsBroadcaster.Publish",
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "nats"),
			attribute.String("messaging.destination.name", subject),
			attribute.String("event.type", strings.ToLower(string(eventType))),
		),
	)
}

// recordWatchEvent counts one watch event received by this replica.
func (i *Instrumentation) recordWatchEvent(ctx context.Context, resource string, eventType watch.EventType) {
	i.watchEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("resource", resource),
		attribute.String("event.type", strings.ToLower(string(eventType))),
	))
}

// instrumentedStore decorates a store with a span per storage operation.
type instrumentedStore struct {
	*store

	instrumentation *Instrumentation
	component       string
}

// instrumentStore wraps inner so that every storage operation runs in a span
// named <component>.<operation>.
func instrumentStore(instrumentation *Instrumentation, component string, inner *store) *instrumentedStore {
	return &instrumentedStore{
		store:           inner,
		instrumentation: instrumentation,
		component:       component,
	}
}

// startSpan opens the span for one storage operation.
//
//nolint:spancheck // The span deliberately outlives this helper.
func (s *instrumentedStore) startSpan(ctx context.Context, operation, name, namespace string) (context.Context, trace.Span) {
	attrs := make([]attribute.KeyValue, 0, 2)
	if namespace != "" {
		attrs = append(attrs, semconv.K8SNamespaceName(namespace))
	}
	if name != "" {
		attrs = append(attrs, objectNameKey.String(name))
	}

	return s.instrumentation.tracer.Start(ctx, s.component+"."+operation,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
}

// recordSpanResult classifies the operation outcome on the span.
func recordSpanResult(span trace.Span, err error) {
	result := storageResultSuccess
	switch {
	case err == nil:
	case storage.IsNotFound(err):
		result = storageResultNotFound
	case storage.IsExist(err):
		result = storageResultAlreadyExists
	default:
		result = storageResultError
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.SetAttributes(attribute.String("storage.result", result))
}

func (s *instrumentedStore) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	name, namespace := s.extractKeyNameAndNamespace(key)
	ctx, span := s.startSpan(ctx, "Create", name, namespace)
	defer span.End()

	err := s.store.Create(ctx, key, obj, out, ttl)
	recordSpanResult(span, err)
	return err
}

func (s *instrumentedStore) Delete(
	ctx context.Context, key string, out runtime.Object, preconditions *storage.Preconditions,
	validateDeletion storage.ValidateObjectFunc, cachedExistingObject runtime.Object, opts storage.DeleteOptions,
) error {
	name, namespace := s.extractKeyNameAndNamespace(key)
	ctx, span := s.startSpan(ctx, "Delete", name, namespace)
	defer span.End()

	err := s.store.Delete(ctx, key, out, preconditions, validateDeletion, cachedExistingObject, opts)
	recordSpanResult(span, err)
	return err
}

func (s *instrumentedStore) Get(ctx context.Context, key string, opts storage.GetOptions, objPtr runtime.Object) error {
	name, namespace := s.extractKeyNameAndNamespace(key)
	ctx, span := s.startSpan(ctx, "Get", name, namespace)
	defer span.End()

	err := s.store.Get(ctx, key, opts, objPtr)
	recordSpanResult(span, err)
	return err
}

func (s *instrumentedStore) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	ctx, span := s.startSpan(ctx, "GetList", "", s.extractKeyNamespace(key))
	defer span.End()

	err := s.store.GetList(ctx, key, opts, listObj)
	recordSpanResult(span, err)
	return err
}

func (s *instrumentedStore) GuaranteedUpdate(
	ctx context.Context, key string, destination runtime.Object, ignoreNotFound bool,
	preconditions *storage.Preconditions, tryUpdate storage.UpdateFunc, cachedExistingObject runtime.Object,
) error {
	name, namespace := s.extractKeyNameAndNamespace(key)
	ctx, span := s.startSpan(ctx, "GuaranteedUpdate", name, namespace)
	defer span.End()

	err := s.store.GuaranteedUpdate(ctx, key, destination, ignoreNotFound, preconditions, tryUpdate, cachedExistingObject)
	recordSpanResult(span, err)
	return err
}

// Watch spans only cover the watch setup; the returned stream outlives the span.
func (s *instrumentedStore) Watch(ctx context.Context, key string, opts storage.ListOptions) (watch.Interface, error) {
	ctx, span := s.startSpan(ctx, "Watch", "", s.extractKeyNamespace(key))
	defer span.End()

	watcher, err := s.store.Watch(ctx, key, opts)
	recordSpanResult(span, err)
	return watcher, err
}
