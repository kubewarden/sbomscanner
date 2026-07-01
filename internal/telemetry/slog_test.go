package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// TestTraceContextHandler_InjectsIDs verifies that trace_id/span_id are added to log records,
// when a span is active in the record's context.
func TestTraceContextHandler_InjectsIDs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewTraceContextHandler(slog.NewJSONHandler(&buf, nil)))

	// Use a real (in-memory) SDK tracer so SpanContext is valid.
	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	ctx, span := tracerProvider.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	logger.InfoContext(ctx, "hello")

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))

	assert.Equal(t, span.SpanContext().TraceID().String(), record[traceIDKey])
	assert.Equal(t, span.SpanContext().SpanID().String(), record[spanIDKey])
	assert.Equal(t, "hello", record["msg"])
}

// TestTraceContextHandler_NoSpan asserts the wrapper is a transparent pass-through,
// when no span is in the context.
func TestTraceContextHandler_NoSpan(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewTraceContextHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Info("plain")

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.NotContains(t, record, traceIDKey, "trace_id should be absent when no span")
	assert.NotContains(t, record, spanIDKey, "span_id should be absent when no span")
}

// TestNewTraceContextHandler_NilInput returns nil for a nil inner handler,
// so callers can chain it unconditionally.
func TestNewTraceContextHandler_NilInput(t *testing.T) {
	assert.Nil(t, NewTraceContextHandler(nil))
}

// TestNewTraceContextHandler_AvoidsStacking returns the same handler when called twice,
// to prevent N-layer wrappers in code that defensively re-wraps.
func TestNewTraceContextHandler_AvoidsStacking(t *testing.T) {
	inner := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	once := NewTraceContextHandler(inner)
	twice := NewTraceContextHandler(once)

	assert.Same(t, once, twice)
}
