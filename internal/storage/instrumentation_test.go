package storage

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/storage/repository"
)

// fakeRepository serves Get from a canned object or error; the other methods are unused.
type fakeRepository struct {
	repository.Repository

	getObject runtime.Object
	getErr    error
}

func (f *fakeRepository) Get(_ context.Context, _ repository.Querier, _, _ string) (runtime.Object, error) {
	return f.getObject, f.getErr
}

func (f *fakeRepository) Delete(_ context.Context, _ pgx.Tx, _, _ string) (runtime.Object, error) {
	return f.getObject, f.getErr
}

func newTestInstrumentedStore(t *testing.T, repo repository.Repository) (*instrumentedStore, *tracetest.SpanRecorder) {
	t.Helper()

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() {
		require.NoError(t, tracerProvider.Shutdown(context.Background()))
	})

	inner := &store{
		repository: repo,
		newFunc:    func() runtime.Object { return &storagev1alpha1.Image{} },
		logger:     slog.New(slog.DiscardHandler),
	}

	instrumentation, err := NewInstrumentation(tracerProvider.Tracer("test"), metricnoop.NewMeterProvider().Meter("test"))
	require.NoError(t, err)

	return instrumentStore(instrumentation, "ImageStore", inner), spanRecorder
}

func attributeMap(span sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	attrs := make(map[attribute.Key]attribute.Value, len(span.Attributes()))
	for _, kv := range span.Attributes() {
		attrs[kv.Key] = kv.Value
	}
	return attrs
}

// TestRecordSpanResult asserts the outcome classification on the span:
// expected outcomes are attributes, only unexpected failures mark the span as errored.
func TestRecordSpanResult(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		result     string
		statusCode codes.Code
		hasEvents  bool
	}{
		{name: "success", err: nil, result: storageResultSuccess, statusCode: codes.Unset},
		{name: "not found", err: storage.NewKeyNotFoundError("key", 0), result: storageResultNotFound, statusCode: codes.Unset},
		{name: "already exists", err: storage.NewKeyExistsError("key", 0), result: storageResultAlreadyExists, statusCode: codes.Unset},
		{name: "internal error", err: errors.New("connection reset"), result: storageResultError, statusCode: codes.Error, hasEvents: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spanRecorder := tracetest.NewSpanRecorder()
			tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
			t.Cleanup(func() {
				require.NoError(t, tracerProvider.Shutdown(context.Background()))
			})

			_, span := tracerProvider.Tracer("test").Start(context.Background(), "operation")
			recordSpanResult(span, test.err)
			span.End()

			spans := spanRecorder.Ended()
			require.Len(t, spans, 1)
			attrs := attributeMap(spans[0])
			assert.Equal(t, test.result, attrs["storage.result"].AsString())
			assert.Equal(t, test.statusCode, spans[0].Status().Code)
			assert.Equal(t, test.hasEvents, len(spans[0].Events()) > 0)
		})
	}
}

// TestInstrumentedStore_GetSuccess asserts the span name, the identity attributes
// parsed from the key, and the success result.
func TestInstrumentedStore_GetSuccess(t *testing.T) {
	instrumented, spanRecorder := newTestInstrumentedStore(t, &fakeRepository{getObject: &storagev1alpha1.Image{}})

	objPtr := &storagev1alpha1.Image{}
	err := instrumented.Get(context.Background(), "/storage.sbomscanner.kubewarden.io/images/default/my-image", storage.GetOptions{}, objPtr)
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "ImageStore.Get", spans[0].Name())

	attrs := attributeMap(spans[0])
	assert.Equal(t, "default", attrs["k8s.namespace.name"].AsString())
	assert.Equal(t, "my-image", attrs["k8s.object.name"].AsString())
	assert.Equal(t, storageResultSuccess, attrs["storage.result"].AsString())
	assert.Equal(t, codes.Unset, spans[0].Status().Code)
}

// TestInstrumentedStore_GetNotFound asserts that a missing object is an expected
// outcome: recorded on the result attribute, not as a span error.
func TestInstrumentedStore_GetNotFound(t *testing.T) {
	instrumented, spanRecorder := newTestInstrumentedStore(t, &fakeRepository{getErr: repository.ErrNotFound})

	objPtr := &storagev1alpha1.Image{}
	err := instrumented.Get(context.Background(), "/storage.sbomscanner.kubewarden.io/images/default/my-image", storage.GetOptions{}, objPtr)
	require.Error(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	attrs := attributeMap(spans[0])
	assert.Equal(t, storageResultNotFound, attrs["storage.result"].AsString())
	assert.Equal(t, codes.Unset, spans[0].Status().Code)
	assert.Empty(t, spans[0].Events(), "no error event expected for a not found outcome")
}

// TestInstrumentedStore_GetInternalError asserts that an unexpected failure marks
// the span as errored and records the error event.
func TestInstrumentedStore_GetInternalError(t *testing.T) {
	instrumented, spanRecorder := newTestInstrumentedStore(t, &fakeRepository{getErr: errors.New("connection reset")})

	objPtr := &storagev1alpha1.Image{}
	err := instrumented.Get(context.Background(), "/storage.sbomscanner.kubewarden.io/images/default/my-image", storage.GetOptions{}, objPtr)
	require.Error(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	attrs := attributeMap(spans[0])
	assert.Equal(t, storageResultError, attrs["storage.result"].AsString())
	assert.Equal(t, codes.Error, spans[0].Status().Code)
	assert.NotEmpty(t, spans[0].Events(), "error event expected")
}
