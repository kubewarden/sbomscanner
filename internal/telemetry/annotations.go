package telemetry

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// annotationDomain prefixes every propagation field stored on a Kubernetes object,
// so the W3C `traceparent` lands at sbomscanner.kubewarden.io/traceparent.
const annotationDomain = "sbomscanner.kubewarden.io/"

// TraceparentAnnotation is the object annotation carrying the W3C traceparent of the trace
// a job (and its result objects) belongs to.
// It is written once at object creation (runner or mutating webhook) and read by every later actor.
const TraceparentAnnotation = annotationDomain + "traceparent"

// annotationsCarrier adapts an object's annotations map to the TextMapCarrier interface,
// prefixing every propagation field with the sbomscanner annotation domain.
type annotationsCarrier map[string]string

var _ propagation.TextMapCarrier = annotationsCarrier{}

// Get returns the value stored under the domain-prefixed key, or an empty string if absent.
func (carrier annotationsCarrier) Get(key string) string {
	return carrier[annotationDomain+key]
}

// Set stores value under the domain-prefixed key.
func (carrier annotationsCarrier) Set(key, value string) {
	carrier[annotationDomain+key] = value
}

// Keys returns every propagation field present in the carrier, with the domain prefix stripped.
// Annotations outside the domain are not propagation fields and are skipped.
func (carrier annotationsCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for key := range carrier {
		if field, ok := strings.CutPrefix(key, annotationDomain); ok {
			keys = append(keys, field)
		}
	}
	return keys
}

// InjectAnnotations writes the trace context from ctx into annotations using the globally configured TextMapPropagator.
// The annotations map must be non-nil to receive the fields; a nil map is left untouched.
// Safe to call when telemetry is disabled, since the span context is invalid and the propagator writes nothing.
func InjectAnnotations(ctx context.Context, annotations map[string]string) {
	if annotations == nil {
		return
	}
	otel.GetTextMapPropagator().Inject(ctx, annotationsCarrier(annotations))
}

// ExtractAnnotations returns a context derived from parent that carries the trace context found in annotations,
// and whether a valid traceparent was present.
// When the annotation is absent or malformed, the parent context is returned unchanged.
func ExtractAnnotations(parent context.Context, annotations map[string]string) (context.Context, bool) {
	if annotations[TraceparentAnnotation] == "" {
		return parent, false
	}

	extracted := otel.GetTextMapPropagator().Extract(parent, annotationsCarrier(annotations))
	if !trace.SpanContextFromContext(extracted).IsValid() {
		return parent, false
	}

	return extracted, true
}
