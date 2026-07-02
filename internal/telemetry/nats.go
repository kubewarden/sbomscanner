package telemetry

import (
	"context"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// natsHeaderCarrier adapts nats.Header to the TextMapCarrier interface,
// so the global OTel propagator can inject/extract W3C `traceparent`
// (and any other configured propagators) directly into JetStream message headers.
//
// NATS headers permit repeated keys, but this carrier follows net/http semantics:
// Set overwrites any existing entry, and Get returns the first value for the key.
type natsHeaderCarrier nats.Header

var _ propagation.TextMapCarrier = natsHeaderCarrier{}

// Get returns the first value associated with key, or an empty string if absent.
func (carrier natsHeaderCarrier) Get(key string) string {
	values := nats.Header(carrier).Values(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Set stores value under key, overwriting any existing entry.
func (carrier natsHeaderCarrier) Set(key, value string) {
	nats.Header(carrier).Set(key, value)
}

// Keys returns every header key present in the carrier.
func (carrier natsHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for key := range carrier {
		keys = append(keys, key)
	}
	return keys
}

// InjectNATS writes the trace context from ctx into msg.Header using the globally configured TextMapPropagator.
// The header is created if needed.
// Safe to call when telemetry is disabled, since the no-op propagator simply writes nothing.
func InjectNATS(ctx context.Context, msg *nats.Msg) {
	if msg == nil {
		return
	}
	if msg.Header == nil {
		msg.Header = nats.Header{}
	}
	otel.GetTextMapPropagator().Inject(ctx, natsHeaderCarrier(msg.Header))
}

// ExtractNATS returns a context derived from parent that carries the trace context found in hdr.
// When telemetry is disabled or no propagation headers are present, the parent context is returned unchanged.
func ExtractNATS(parent context.Context, hdr nats.Header) context.Context {
	if hdr == nil {
		return parent
	}
	return otel.GetTextMapPropagator().Extract(parent, natsHeaderCarrier(hdr))
}
