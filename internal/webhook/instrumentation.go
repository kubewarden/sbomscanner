// Package webhook provides OpenTelemetry instrumentation for the admission webhooks.
package webhook

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// Bounded values for the type metric label and the webhook.type span attribute.
const (
	webhookTypeValidating = "validating"
	webhookTypeMutating   = "mutating"
)

// Instrumentation bundles the tracer and the metric instruments shared by the admission webhooks.
// Disabled telemetry is represented by no-op providers, never by a nil Instrumentation.
type Instrumentation struct {
	tracer    trace.Tracer
	decisions metric.Int64Counter
}

// NewInstrumentation creates the metric instruments used by this package on the given meter.
func NewInstrumentation(tracer trace.Tracer, meter metric.Meter) (*Instrumentation, error) {
	decisions, err := meter.Int64Counter(
		"controller.webhook.decisions",
		metric.WithDescription("Number of admission webhook decisions."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating controller.webhook.decisions counter: %w", err)
	}

	return &Instrumentation{
		tracer:    tracer,
		decisions: decisions,
	}, nil
}

// startAdmissionSpan starts the span for one admission call,
// joining the job trace when the object carries a traceparent annotation.
//
//nolint:spancheck // The span is returned to the caller, which is responsible for ending it.
func (i *Instrumentation) startAdmissionSpan(ctx context.Context, spanName, webhookType, kind, operation string, obj client.Object) (context.Context, trace.Span) {
	attrs := []attribute.KeyValue{
		attribute.String("webhook.type", webhookType),
		attribute.String("webhook.kind", kind),
		attribute.String("webhook.operation", operation),
		attribute.String("k8s.namespace.name", obj.GetNamespace()),
		attribute.String("k8s.object.name", obj.GetName()),
	}
	if req, err := admission.RequestFromContext(ctx); err == nil {
		attrs = append(attrs, attribute.String("webhook.request.uid", string(req.UID)))
	}

	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attrs...),
	}

	parentCtx, joined := telemetry.ExtractAnnotations(ctx, obj.GetAnnotations())
	if joined && trace.SpanContextFromContext(ctx).IsValid() {
		opts = append(opts, trace.WithLinks(trace.LinkFromContext(ctx)))
	}

	return i.tracer.Start(parentCtx, spanName, opts...)
}

// recordDecision records the admission outcome on the span and counts the decision.
func (i *Instrumentation) recordDecision(ctx context.Context, span trace.Span, webhookType, kind, operation string, err error) {
	allowed := err == nil
	span.SetAttributes(attribute.Bool("webhook.allowed", allowed))

	attrs := []attribute.KeyValue{
		attribute.String("type", webhookType),
		attribute.String("kind", kind),
		attribute.String("operation", operation),
		attribute.Bool("allowed", allowed),
	}
	if err != nil {
		reason := denialReason(err)
		span.SetAttributes(attribute.String("webhook.reason", reason))
		attrs = append(attrs, attribute.String("reason", reason))
	}

	i.decisions.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// InstrumentValidator wraps inner with tracing and metrics; kind is the validated resource kind.
func InstrumentValidator[T client.Object](instrumentation *Instrumentation, kind string, inner admission.Validator[T]) admission.Validator[T] {
	return &instrumentedValidator[T]{
		inner:           inner,
		instrumentation: instrumentation,
		kind:            kind,
	}
}

// instrumentedValidator decorates an admission.Validator with a span and a decision metric per admission call.
type instrumentedValidator[T client.Object] struct {
	inner           admission.Validator[T]
	instrumentation *Instrumentation
	kind            string
}

// ValidateCreate implements admission.Validator.
func (v *instrumentedValidator[T]) ValidateCreate(ctx context.Context, obj T) (admission.Warnings, error) {
	ctx, span := v.instrumentation.startAdmissionSpan(ctx, v.kind+"ValidatingWebhook.Create", webhookTypeValidating, v.kind, "create", obj)
	defer span.End()

	warnings, err := v.inner.ValidateCreate(ctx, obj)
	v.instrumentation.recordDecision(ctx, span, webhookTypeValidating, v.kind, "create", err)

	//nolint:wrapcheck // Pass-through decorator: the validator's admission error must reach the webhook handler unwrapped.
	return warnings, err
}

// ValidateUpdate implements admission.Validator.
func (v *instrumentedValidator[T]) ValidateUpdate(ctx context.Context, oldObj, newObj T) (admission.Warnings, error) {
	ctx, span := v.instrumentation.startAdmissionSpan(ctx, v.kind+"ValidatingWebhook.Update", webhookTypeValidating, v.kind, "update", newObj)
	defer span.End()

	warnings, err := v.inner.ValidateUpdate(ctx, oldObj, newObj)
	v.instrumentation.recordDecision(ctx, span, webhookTypeValidating, v.kind, "update", err)

	//nolint:wrapcheck // Pass-through decorator: the validator's admission error must reach the webhook handler unwrapped.
	return warnings, err
}

// ValidateDelete implements admission.Validator.
func (v *instrumentedValidator[T]) ValidateDelete(ctx context.Context, obj T) (admission.Warnings, error) {
	ctx, span := v.instrumentation.startAdmissionSpan(ctx, v.kind+"ValidatingWebhook.Delete", webhookTypeValidating, v.kind, "delete", obj)
	defer span.End()

	warnings, err := v.inner.ValidateDelete(ctx, obj)
	v.instrumentation.recordDecision(ctx, span, webhookTypeValidating, v.kind, "delete", err)

	//nolint:wrapcheck // Pass-through decorator: the validator's admission error must reach the webhook handler unwrapped.
	return warnings, err
}

// InstrumentDefaulter wraps inner with tracing and metrics; kind is the defaulted resource kind.
func InstrumentDefaulter[T client.Object](instrumentation *Instrumentation, kind string, inner admission.Defaulter[T]) admission.Defaulter[T] {
	return &instrumentedDefaulter[T]{
		inner:           inner,
		instrumentation: instrumentation,
		kind:            kind,
	}
}

// InstrumentDefaulterWithTraceparent is InstrumentDefaulter for job kinds:
// it also adds the span's traceparent to created objects that do not already carry one.
func InstrumentDefaulterWithTraceparent[T client.Object](instrumentation *Instrumentation, kind string, inner admission.Defaulter[T]) admission.Defaulter[T] {
	return &instrumentedDefaulter[T]{
		inner:             inner,
		instrumentation:   instrumentation,
		kind:              kind,
		injectTraceparent: true,
	}
}

// instrumentedDefaulter decorates an admission.Defaulter with a span and a decision metric per admission call.
type instrumentedDefaulter[T client.Object] struct {
	inner             admission.Defaulter[T]
	instrumentation   *Instrumentation
	kind              string
	injectTraceparent bool
}

// Default implements admission.Defaulter.
func (d *instrumentedDefaulter[T]) Default(ctx context.Context, obj T) error {
	operation, isCreate := requestOperation(ctx)

	ctx, span := d.instrumentation.startAdmissionSpan(ctx, d.kind+"MutatingWebhook."+spanVerb(operation), webhookTypeMutating, d.kind, operation, obj)
	defer span.End()

	err := d.inner.Default(ctx, obj)

	if err == nil && isCreate && d.injectTraceparent {
		injectTraceparent(ctx, obj)
	}

	d.instrumentation.recordDecision(ctx, span, webhookTypeMutating, d.kind, operation, err)

	//nolint:wrapcheck // Pass-through decorator: the defaulter's admission error must reach the webhook handler unwrapped.
	return err
}

// requestOperation returns the admission operation from the request in ctx and whether it is a create.
func requestOperation(ctx context.Context) (string, bool) {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return "unknown", false
	}
	return strings.ToLower(string(req.Operation)), req.Operation == admissionv1.Create
}

// spanVerb converts the bounded lowercase operation label into the PascalCase verb used in span names.
func spanVerb(operation string) string {
	switch operation {
	case "create":
		return "Create"
	case "update":
		return "Update"
	case "delete":
		return "Delete"
	case "connect":
		return "Connect"
	default:
		return "Unknown"
	}
}

// injectTraceparent adds the traceparent from ctx to the object's annotations, unless one exists.
func injectTraceparent(ctx context.Context, obj client.Object) {
	annotations := obj.GetAnnotations()
	if annotations[telemetry.TraceparentAnnotation] != "" {
		return
	}
	if annotations == nil {
		annotations = map[string]string{}
	}

	telemetry.InjectAnnotations(ctx, annotations)
	if annotations[telemetry.TraceparentAnnotation] != "" {
		obj.SetAnnotations(annotations)
	}
}

// denialReason maps a validation error to a bounded metric label value.
func denialReason(err error) string {
	if reason := apierrors.ReasonForError(err); reason != metav1.StatusReasonUnknown {
		return string(reason)
	}
	return "unknown"
}
