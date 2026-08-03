package handlers

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/kubewarden/sbomscanner/internal/messaging"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// fakeHandler returns a fixed error so tests can drive success and failure outcomes.
type fakeHandler struct {
	err error
}

func (f *fakeHandler) Handle(context.Context, messaging.Message) error {
	return f.err
}

// fakeFailureHandler returns a fixed error so tests can drive success and failure outcomes.
type fakeFailureHandler struct {
	err error
}

func (f *fakeFailureHandler) HandleFailure(context.Context, messaging.Message, string) error {
	return f.err
}

// newTestInstrumentation builds an Instrumentation backed by in-memory SDK providers,
// returning the span recorder and metric reader used for assertions.
func newTestInstrumentation(t *testing.T) (*Instrumentation, *tracetest.SpanRecorder, *sdkmetric.ManualReader) {
	t.Helper()

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })

	instrumentation, err := NewInstrumentation(tracerProvider.Tracer("test"), meterProvider.Meter("test"))
	require.NoError(t, err)

	return instrumentation, spanRecorder, reader
}

// publishedMessage returns a message carrying the traceparent of a fresh publishing span,
// along with that span's context.
func publishedMessage(t *testing.T, instrumentation *Instrumentation) (*testMessage, trace.SpanContext) {
	t.Helper()

	publishCtx, publishSpan := instrumentation.tracer.Start(context.Background(), "publish")
	publishSpan.End()

	msg := &nats.Msg{Header: nats.Header{}}
	telemetry.InjectNATS(publishCtx, msg)
	require.NotEmpty(t, msg.Header.Get("traceparent"))

	return &testMessage{headers: msg.Header}, publishSpan.SpanContext()
}

// TestInstrumentHandler_JoinsPublisherTrace asserts that the consumer span is parented into the
// trace carried by the message headers, forming the job tree over NATS.
func TestInstrumentHandler_JoinsPublisherTrace(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)

	message, publishSpanContext := publishedMessage(t, instrumentation)
	handler := instrumentHandler(instrumentation, "CreateCatalogHandler", "catalog", &fakeHandler{})

	require.NoError(t, handler.Handle(context.Background(), message))

	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)
	span := spans[1]
	assert.Equal(t, "CreateCatalogHandler.Handle", span.Name())
	assert.Equal(t, trace.SpanKindConsumer, span.SpanKind())
	assert.Equal(t, publishSpanContext.TraceID(), span.SpanContext().TraceID(),
		"the consumer span must belong to the publishing trace")
	assert.Equal(t, publishSpanContext.SpanID(), span.Parent().SpanID())
	attrs := attribute.NewSet(span.Attributes()...)
	assert.Equal(t, "nats", attrValue(attrs, "messaging.system"))

	points := collectDataPoints(t, reader, "worker.scan.duration")
	require.Len(t, points, 1)
	assert.Equal(t, "catalog", attrValue(points[0], "stage"))
	assert.Equal(t, "success", attrValue(points[0], "result"))
}

// TestInstrumentHandler_Error asserts the error is recorded on the span,
// the duration, and the errors counter with a bounded error type.
func TestInstrumentHandler_Error(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)

	notFound := apierrors.NewNotFound(schema.GroupResource{Resource: "scanjobs"}, "my-job")
	handler := instrumentHandler(instrumentation, "ScanSBOMHandler", "scan_sbom", &fakeHandler{err: notFound})

	require.Error(t, handler.Handle(context.Background(), &testMessage{}))

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	require.Len(t, spans[0].Events(), 1, "the error must be recorded on the span")

	durations := collectDataPoints(t, reader, "worker.scan.duration")
	require.Len(t, durations, 1)
	assert.Equal(t, "error", attrValue(durations[0], "result"))

	errorsPoints := collectDataPoints(t, reader, "worker.handler.errors")
	require.Len(t, errorsPoints, 1)
	assert.Equal(t, "scan_sbom", attrValue(errorsPoints[0], "handler"))
	assert.Equal(t, "NotFound", attrValue(errorsPoints[0], "error.type"))
}

// TestInstrumentFailureHandler asserts the failure span joins the message trace.
func TestInstrumentFailureHandler(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, _ := newTestInstrumentation(t)

	message, publishSpanContext := publishedMessage(t, instrumentation)
	handler := instrumentFailureHandler(instrumentation, "ScanJobFailureHandler", &fakeFailureHandler{})

	require.NoError(t, handler.HandleFailure(context.Background(), message, "boom"))

	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)
	span := spans[1]
	assert.Equal(t, "ScanJobFailureHandler.HandleFailure", span.Name())
	assert.Equal(t, publishSpanContext.TraceID(), span.SpanContext().TraceID())
	attrs := attribute.NewSet(span.Attributes()...)
	assert.Equal(t, "boom", attrValue(attrs, "error.message"))
}

// TestStartTrivy asserts the Trivy span shape and the duration metric labels.
func TestStartTrivy(t *testing.T) {
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)

	_, done := instrumentation.startTrivy(context.Background(), trivyCommandSBOM)
	done(assert.AnError)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "Trivy.SBOM", spans[0].Name())
	attrs := attribute.NewSet(spans[0].Attributes()...)
	assert.Equal(t, "sbom", attrValue(attrs, "trivy.command"))

	points := collectDataPoints(t, reader, "worker.trivy.duration")
	require.Len(t, points, 1)
	assert.Equal(t, "sbom", attrValue(points[0], "command"))
	assert.Equal(t, "error", attrValue(points[0], "result"))
}

// TestStartRegistryCall asserts the duration metric labels.
func TestStartRegistryCall(t *testing.T) {
	instrumentation, _, reader := newTestInstrumentation(t)

	done := instrumentation.startRegistryCall(context.Background(), "catalog")
	done(assert.AnError)

	points := collectDataPoints(t, reader, "worker.registry.call.duration")
	require.Len(t, points, 1)
	assert.Equal(t, "catalog", attrValue(points[0], "operation"))
	assert.Equal(t, "error", attrValue(points[0], "result"))
}

func TestErrorType(t *testing.T) {
	assert.Equal(t, "NotFound", errorType(apierrors.NewNotFound(schema.GroupResource{Resource: "scanjobs"}, "x")))
	assert.Equal(t, "canceled", errorType(context.Canceled))
	assert.Equal(t, "deadline_exceeded", errorType(context.DeadlineExceeded))
	assert.Equal(t, "unknown", errorType(assert.AnError))
}

// collectDataPoints returns the int64 or float64 data points of the named metric as attribute sets.
func collectDataPoints(t *testing.T, reader *sdkmetric.ManualReader, name string) []attributePoint {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &resourceMetrics))

	var points []attributePoint
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, m := range scopeMetrics.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					points = append(points, attributePoint{attributes: point.Attributes, value: point.Value})
				}
			case metricdata.Histogram[float64]:
				for _, point := range data.DataPoints {
					points = append(points, attributePoint{attributes: point.Attributes, value: int64(point.Count)})
				}
			default:
				t.Fatalf("unexpected data type %T for metric %s", m.Data, name)
			}
		}
	}
	return points
}

// attributePoint is a metric data point reduced to its attributes and value for assertions.
type attributePoint struct {
	attributes attribute.Set
	value      int64
}

// attrValue returns the string form of the point attribute with the given key, or "" when absent.
func attrValue[T interface{ attribute.Set | attributePoint }](holder T, key string) string {
	var set attribute.Set
	switch v := any(holder).(type) {
	case attribute.Set:
		set = v
	case attributePoint:
		set = v.attributes
	}
	value, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return value.String()
}
