package telemetry

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TestNATSCarrier_RoundTrip injects a context into NATS headers and extracts it back,
// asserting the same trace context is recovered.
// This is the exact path used by NatsPublisher / NatsSubscriber in Task 1.
func TestNATSCarrier_RoundTrip(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	producerCtx, span := tracerProvider.Tracer("test").Start(context.Background(), "produce")
	defer span.End()
	expectedSpanContext := span.SpanContext()

	msg := &nats.Msg{Subject: "sbomscanner.test"}
	InjectNATS(producerCtx, msg)

	require.NotEmpty(t, msg.Header.Get("traceparent"),
		"traceparent header must be set by InjectNATS")

	consumerCtx := ExtractNATS(context.Background(), msg.Header)
	extractedSpanContext := trace.SpanContextFromContext(consumerCtx)

	assert.Equal(t, expectedSpanContext.TraceID(), extractedSpanContext.TraceID())
	assert.Equal(t, expectedSpanContext.SpanID(), extractedSpanContext.SpanID())
}

// TestInjectNATS_NilMsg asserts that InjectNATS is safe to call with a nil message,
// returning without panicking so publisher call sites don't need a guard.
func TestInjectNATS_NilMsg(t *testing.T) {
	assert.NotPanics(t, func() {
		InjectNATS(context.Background(), nil)
	})
}

// TestInjectNATS_CreatesHeader lazily allocates msg.Header when it is nil,
// instead of panicking on map assignment.
func TestInjectNATS_CreatesHeader(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
	ctx, span := tracerProvider.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	msg := &nats.Msg{Subject: "sbomscanner.test"} // Header is nil
	InjectNATS(ctx, msg)

	require.NotNil(t, msg.Header)
	assert.NotEmpty(t, msg.Header.Get("traceparent"))
}

// TestExtractNATS_NilHeader returns the parent context unchanged,
// so consumers can call it without pre-checking.
func TestExtractNATS_NilHeader(t *testing.T) {
	parentCtx := context.Background()
	extractedCtx := ExtractNATS(parentCtx, nil)
	assert.Equal(t, parentCtx, extractedCtx)
}

// TestExtractNATS_NoTraceparent returns a context with an invalid SpanContext,
// when the header has no propagation keys.
func TestExtractNATS_NoTraceparent(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	hdr := nats.Header{}
	hdr.Set("Nats-Msg-Id", "abc")

	extractedCtx := ExtractNATS(context.Background(), hdr)
	assert.False(t, trace.SpanContextFromContext(extractedCtx).IsValid())
}

// TestNATSHeaderCarrier_Keys returns every header key,
// matching the TextMapCarrier contract.
func TestNATSHeaderCarrier_Keys(t *testing.T) {
	hdr := nats.Header{}
	hdr.Set("traceparent", "00-...")
	hdr.Set("Nats-Msg-Id", "id")

	keys := natsHeaderCarrier(hdr).Keys()
	assert.ElementsMatch(t, []string{"traceparent", "Nats-Msg-Id"}, keys)
}

// TestNATSHeaderCarrier_GetMissing returns an empty string for absent keys,
// per the TextMapCarrier contract.
func TestNATSHeaderCarrier_GetMissing(t *testing.T) {
	assert.Empty(t, natsHeaderCarrier(nats.Header{}).Get("traceparent"))
}
