package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TestAnnotationsCarrier_RoundTrip injects a context into an annotations map and extracts it back,
// asserting the same trace context is recovered.
// This is the exact path used by the job runners (inject) and reconcilers/webhooks (extract).
func TestAnnotationsCarrier_RoundTrip(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	jobCtx, span := tracerProvider.Tracer("test").Start(context.Background(), "ScanJob created")
	defer span.End()
	expectedSpanContext := span.SpanContext()

	annotations := map[string]string{}
	InjectAnnotations(jobCtx, annotations)

	require.NotEmpty(t, annotations[TraceparentAnnotation],
		"traceparent annotation must be set by InjectAnnotations")

	extractedCtx, found := ExtractAnnotations(context.Background(), annotations)
	require.True(t, found)
	extractedSpanContext := trace.SpanContextFromContext(extractedCtx)

	assert.Equal(t, expectedSpanContext.TraceID(), extractedSpanContext.TraceID())
	assert.Equal(t, expectedSpanContext.SpanID(), extractedSpanContext.SpanID())
}

// TestInjectAnnotations_NilMap asserts that a nil map is left untouched without panicking,
// so call sites don't need a guard.
func TestInjectAnnotations_NilMap(t *testing.T) {
	assert.NotPanics(t, func() {
		InjectAnnotations(context.Background(), nil)
	})
}

// TestInjectAnnotations_NoSpan writes nothing when the context carries no valid span,
// which is also the telemetry-disabled path (no-op providers produce invalid span contexts).
func TestInjectAnnotations_NoSpan(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	annotations := map[string]string{}
	InjectAnnotations(context.Background(), annotations)

	assert.Empty(t, annotations)
}

// TestExtractAnnotations_Absent returns the parent context unchanged when no traceparent annotation is present,
// degrading gracefully to isolated spans.
func TestExtractAnnotations_Absent(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	parentCtx := context.Background()
	extractedCtx, found := ExtractAnnotations(parentCtx, map[string]string{"other": "annotation"})

	assert.False(t, found)
	assert.Equal(t, parentCtx, extractedCtx)
}

// TestExtractAnnotations_Malformed treats an unparseable traceparent as absent.
func TestExtractAnnotations_Malformed(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	parentCtx := context.Background()
	extractedCtx, found := ExtractAnnotations(parentCtx, map[string]string{TraceparentAnnotation: "garbage"})

	assert.False(t, found)
	assert.Equal(t, parentCtx, extractedCtx)
}

// TestAnnotationsCarrier_Keys returns only domain-prefixed fields with the prefix stripped,
// so foreign annotations never reach the propagator.
func TestAnnotationsCarrier_Keys(t *testing.T) {
	carrier := annotationsCarrier{
		TraceparentAnnotation:          "00-...",
		"kubectl.kubernetes.io/edited": "true",
	}

	assert.ElementsMatch(t, []string{"traceparent"}, carrier.Keys())
}
