package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// Attribute keys used to decorate slog records with the active span identifiers.
const (
	traceIDKey = "trace_id"
	spanIDKey  = "span_id"
)

// traceContextHandler wraps a [slog.Handler] and decorates every record with the active span's trace_id and span_id,
// when the record's context carries one.
//
// When no span is active, the handler is a transparent pass-through.
type traceContextHandler struct {
	inner slog.Handler
}

// NewTraceContextHandler wraps handler so that records emitted with a context-carrying SpanContext are annotated with `trace_id` and `span_id` fields.
// The wrapper preserves group/attribute behaviour of the inner handler.
func NewTraceContextHandler(handler slog.Handler) slog.Handler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(*traceContextHandler); ok {
		// Already wrapped, avoid stacking.
		return handler
	}
	return &traceContextHandler{inner: handler}
}

// Enabled reports whether the inner handler is enabled for the given level.
func (h *traceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle adds trace_id and span_id attributes to record when ctx carries a valid SpanContext,
// then delegates to the inner handler.
// The record is cloned before mutation so downstream handlers (or future fan-out wrappers) never see attrs leaked from a shared backing array.
func (h *traceContextHandler) Handle(ctx context.Context, record slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		record = record.Clone()
		record.AddAttrs(
			slog.String(traceIDKey, sc.TraceID().String()),
			slog.String(spanIDKey, sc.SpanID().String()),
		)
	}
	if err := h.inner.Handle(ctx, record); err != nil {
		return fmt.Errorf("inner slog handler: %w", err)
	}
	return nil
}

// WithAttrs returns a new traceContextHandler wrapping the inner handler with attrs applied.
func (h *traceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceContextHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup returns a new traceContextHandler wrapping the inner handler with the given group name.
func (h *traceContextHandler) WithGroup(name string) slog.Handler {
	return &traceContextHandler{inner: h.inner.WithGroup(name)}
}
