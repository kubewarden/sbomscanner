package webhook

import (
	"context"
	"testing"

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
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// fakeValidator returns a fixed error from every method so tests can drive allow and deny outcomes.
type fakeValidator struct {
	err error
}

func (f *fakeValidator) ValidateCreate(context.Context, *v1alpha1.Registry) (admission.Warnings, error) {
	return nil, f.err
}

func (f *fakeValidator) ValidateUpdate(context.Context, *v1alpha1.Registry, *v1alpha1.Registry) (admission.Warnings, error) {
	return nil, f.err
}

func (f *fakeValidator) ValidateDelete(context.Context, *v1alpha1.Registry) (admission.Warnings, error) {
	return nil, f.err
}

// fakeDefaulter returns a fixed error so tests can drive allow and deny outcomes.
type fakeDefaulter struct {
	err error
}

func (f *fakeDefaulter) Default(context.Context, *v1alpha1.Registry) error {
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

// collectDecisions returns the data points of the controller.webhook.decisions counter.
func collectDecisions(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.DataPoint[int64] {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &resourceMetrics))

	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, m := range scopeMetrics.Metrics {
			if m.Name == "controller.webhook.decisions" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				return sum.DataPoints
			}
		}
	}

	t.Fatal("metric controller.webhook.decisions not found")
	return nil
}

// newRequestContext returns a context carrying an admission request for the given operation.
func newRequestContext(ctx context.Context, operation admissionv1.Operation) context.Context {
	return admission.NewContextWithRequest(ctx, admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       types.UID("uid-1"),
			Operation: operation,
		},
	})
}

// newRegistry returns a Registry test object, optionally carrying the given annotations.
func newRegistry(annotations map[string]string) *v1alpha1.Registry {
	return &v1alpha1.Registry{
		ObjectMeta: metav1.ObjectMeta{Name: "my-registry", Namespace: "default", Annotations: annotations},
	}
}

// jobAnnotations returns annotations carrying the traceparent of a fresh trace,
// along with the span context of its root span.
func jobAnnotations(t *testing.T, instrumentation *Instrumentation) (map[string]string, trace.SpanContext) {
	t.Helper()

	jobCtx, jobSpan := instrumentation.tracer.Start(context.Background(), "RegistryScanRunner.CreateScanJob")
	jobSpan.End()

	annotations := map[string]string{}
	telemetry.InjectAnnotations(jobCtx, annotations)
	require.NotEmpty(t, annotations[telemetry.TraceparentAnnotation])

	return annotations, jobSpan.SpanContext()
}

func TestInstrumentedValidator_Allowed(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)
	validator := InstrumentValidator(instrumentation, "Registry", &fakeValidator{})

	ctx := newRequestContext(context.Background(), admissionv1.Create)
	_, err := validator.ValidateCreate(ctx, newRegistry(nil))
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "RegistryValidatingWebhook.Create", span.Name())
	attrs := attribute.NewSet(span.Attributes()...)
	assert.Equal(t, "validating", attrValue(attrs, "webhook.type"))
	assert.Equal(t, "Registry", attrValue(attrs, "webhook.kind"))
	assert.Equal(t, "create", attrValue(attrs, "webhook.operation"))
	assert.Equal(t, "uid-1", attrValue(attrs, "webhook.request.uid"))
	assert.Equal(t, "default", attrValue(attrs, "k8s.namespace.name"))
	assert.Equal(t, "my-registry", attrValue(attrs, "k8s.object.name"))
	assert.Equal(t, "true", attrValue(attrs, "webhook.allowed"))

	points := collectDecisions(t, reader)
	require.Len(t, points, 1)
	point := points[0]
	assert.Equal(t, int64(1), point.Value)
	assert.Equal(t, "validating", attrValue(point.Attributes, "type"))
	assert.Equal(t, "Registry", attrValue(point.Attributes, "kind"))
	assert.Equal(t, "create", attrValue(point.Attributes, "operation"))
	assert.Equal(t, "true", attrValue(point.Attributes, "allowed"))
	assert.Empty(t, attrValue(point.Attributes, "reason"))
}

func TestInstrumentedValidator_Denied(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)
	denial := apierrors.NewInvalid(v1alpha1.GroupVersion.WithKind("Registry").GroupKind(), "my-registry", nil)
	validator := InstrumentValidator(instrumentation, "Registry", &fakeValidator{err: denial})

	registry := newRegistry(nil)
	_, err := validator.ValidateUpdate(context.Background(), registry, registry)
	require.Error(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	attrs := attribute.NewSet(spans[0].Attributes()...)
	assert.Equal(t, "update", attrValue(attrs, "webhook.operation"))
	assert.Equal(t, "false", attrValue(attrs, "webhook.allowed"))
	assert.Equal(t, "Invalid", attrValue(attrs, "webhook.reason"))

	points := collectDecisions(t, reader)
	require.Len(t, points, 1)
	point := points[0]
	assert.Equal(t, "false", attrValue(point.Attributes, "allowed"))
	assert.Equal(t, "Invalid", attrValue(point.Attributes, "reason"))
}

// TestInstrumentedValidator_JoinsJobTrace asserts that the webhook span is parented into the trace
// carried by the object's traceparent annotation, so admission decisions appear in the job timeline.
func TestInstrumentedValidator_JoinsJobTrace(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, _ := newTestInstrumentation(t)

	annotations, jobSpanContext := jobAnnotations(t, instrumentation)
	validator := InstrumentValidator(instrumentation, "Registry", &fakeValidator{})

	_, err := validator.ValidateDelete(context.Background(), newRegistry(annotations))
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)
	webhookSpan := spans[1]
	assert.Equal(t, jobSpanContext.TraceID(), webhookSpan.SpanContext().TraceID(),
		"the webhook span must belong to the job trace")
	assert.Equal(t, jobSpanContext.SpanID(), webhookSpan.Parent().SpanID())
}

// TestInstrumentedDefaulter_InjectsTraceparent asserts the create-only, never-overwrite
// injection contract of InstrumentDefaulterWithTraceparent.
func TestInstrumentedDefaulter_InjectsTraceparent(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, _ := newTestInstrumentation(t)
	defaulter := InstrumentDefaulterWithTraceparent(instrumentation, "Registry", &fakeDefaulter{})

	t.Run("injects on create", func(t *testing.T) {
		registry := newRegistry(nil)
		require.NoError(t, defaulter.Default(newRequestContext(context.Background(), admissionv1.Create), registry))

		traceparent := registry.Annotations[telemetry.TraceparentAnnotation]
		require.NotEmpty(t, traceparent)

		// The injected traceparent must point at the mutating webhook span, the root of the job trace.
		spans := spanRecorder.Ended()
		require.NotEmpty(t, spans)
		webhookSpan := spans[len(spans)-1]
		assert.Contains(t, traceparent, webhookSpan.SpanContext().TraceID().String())
	})

	t.Run("never overwrites", func(t *testing.T) {
		registry := newRegistry(map[string]string{telemetry.TraceparentAnnotation: "pre-set"})
		require.NoError(t, defaulter.Default(newRequestContext(context.Background(), admissionv1.Create), registry))
		assert.Equal(t, "pre-set", registry.Annotations[telemetry.TraceparentAnnotation])
	})

	t.Run("skips update", func(t *testing.T) {
		registry := newRegistry(nil)
		require.NoError(t, defaulter.Default(newRequestContext(context.Background(), admissionv1.Update), registry))
		assert.Empty(t, registry.Annotations)
	})
}

// TestInstrumentedDefaulter_NoInjectionWithoutOption asserts that plain instrumented defaulters
// never write annotations, keeping config objects free of traceparents.
func TestInstrumentedDefaulter_NoInjectionWithoutOption(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, _, _ := newTestInstrumentation(t)
	defaulter := InstrumentDefaulter(instrumentation, "Registry", &fakeDefaulter{})

	registry := newRegistry(nil)
	require.NoError(t, defaulter.Default(newRequestContext(context.Background(), admissionv1.Create), registry))
	assert.Empty(t, registry.Annotations)
}

// TestInstrumentedDefaulter_RecordsDecision asserts the mutating decision metric shape.
func TestInstrumentedDefaulter_RecordsDecision(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder, reader := newTestInstrumentation(t)
	defaulter := InstrumentDefaulter(instrumentation, "Registry", &fakeDefaulter{})

	require.NoError(t, defaulter.Default(newRequestContext(context.Background(), admissionv1.Create), newRegistry(nil)))

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "RegistryMutatingWebhook.Create", spans[0].Name())
	attrs := attribute.NewSet(spans[0].Attributes()...)
	assert.Equal(t, "mutating", attrValue(attrs, "webhook.type"))
	assert.Equal(t, "create", attrValue(attrs, "webhook.operation"))

	points := collectDecisions(t, reader)
	require.Len(t, points, 1)
	point := points[0]
	assert.Equal(t, "mutating", attrValue(point.Attributes, "type"))
	assert.Equal(t, "true", attrValue(point.Attributes, "allowed"))
}

func TestDenialReason(t *testing.T) {
	assert.Equal(t, "Forbidden", denialReason(apierrors.NewForbidden(
		v1alpha1.GroupVersion.WithResource("registries").GroupResource(), "x", nil)))
	assert.Equal(t, "unknown", denialReason(assert.AnError))
}

// attrValue returns the string form of the attribute with the given key, or "" when absent.
func attrValue(set attribute.Set, key string) string {
	value, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return value.String()
}
