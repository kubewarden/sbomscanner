package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/sbomscanner/internal/messaging"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// Bounded result label values.
const (
	resultSuccess = "success"
	resultError   = "error"
)

// Bounded handler.skip_reason span attribute values, set on the early-return paths.
const (
	skipReasonJobNotFound    = "job_not_found"
	skipReasonUIDMismatch    = "uid_mismatch"
	skipReasonJobFailed      = "job_failed"
	skipReasonObjectNotFound = "object_not_found"
)

// Trivy subcommands used by the handlers.
const (
	trivyCommandImage      = "image"
	trivyCommandSBOM       = "sbom"
	trivyCommandFilesystem = "filesystem"
)

// Instrumentation bundles the tracer and the metric instruments shared by the worker handlers.
// Disabled telemetry is represented by no-op providers.
type Instrumentation struct {
	tracer               trace.Tracer
	scanDuration         metric.Float64Histogram
	imagesScanned        metric.Int64Counter
	registryCallDuration metric.Float64Histogram
	trivyDuration        metric.Float64Histogram
	handlerErrors        metric.Int64Counter
}

// NewInstrumentation creates a new Instrumentation.
func NewInstrumentation(tracer trace.Tracer, meter metric.Meter) (*Instrumentation, error) {
	scanDuration, err := meter.Float64Histogram(
		"worker.scan.duration",
		metric.WithDescription("Duration of one handled scan stage."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating worker.scan.duration histogram: %w", err)
	}

	imagesScanned, err := meter.Int64Counter(
		"sbomscanner.images.scanned",
		metric.WithDescription("Number of images scanned."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sbomscanner.images.scanned counter: %w", err)
	}

	registryCallDuration, err := meter.Float64Histogram(
		"worker.registry.call.duration",
		metric.WithDescription("Duration of registry calls."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating worker.registry.call.duration histogram: %w", err)
	}

	trivyDuration, err := meter.Float64Histogram(
		"worker.trivy.duration",
		metric.WithDescription("Duration of Trivy invocations."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating worker.trivy.duration histogram: %w", err)
	}

	handlerErrors, err := meter.Int64Counter(
		"worker.handler.errors",
		metric.WithDescription("Number of handler errors."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating worker.handler.errors counter: %w", err)
	}

	return &Instrumentation{
		tracer:               tracer,
		scanDuration:         scanDuration,
		imagesScanned:        imagesScanned,
		registryCallDuration: registryCallDuration,
		trivyDuration:        trivyDuration,
		handlerErrors:        handlerErrors,
	}, nil
}

// recordHandled records the duration of one handled message, and counts the error when it failed.
func (i *Instrumentation) recordHandled(ctx context.Context, stage string, elapsed time.Duration, err error) {
	result := resultSuccess
	if err != nil {
		result = resultError
		i.handlerErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("handler", stage),
			attribute.String("error.type", errorType(err)),
		))
	}
	i.scanDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(
		attribute.String("stage", stage),
		attribute.String("result", result),
	))
}

// recordImageScanned counts one scanned image with the given registry host and scan outcome.
func (i *Instrumentation) recordImageScanned(ctx context.Context, registryHost string, err error) {
	result := resultSuccess
	if err != nil {
		result = resultError
	}
	i.imagesScanned.Add(ctx, 1, metric.WithAttributes(
		attribute.String("registry", registryHost),
		attribute.String("result", result),
	))
}

// startTrivy starts a span for one Trivy invocation and returns a done function
// that records its duration and outcome.
//
//nolint:spancheck // The span is ended by the returned done function.
func (i *Instrumentation) startTrivy(ctx context.Context, command string) (context.Context, func(error)) {
	ctx, span := i.tracer.Start(ctx, trivySpanName(command),
		trace.WithAttributes(attribute.String("trivy.command", command)),
	)
	start := time.Now()

	return ctx, func(err error) {
		result := resultSuccess
		if err != nil {
			result = resultError
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		i.trivyDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(
			attribute.String("command", command),
			attribute.String("result", result),
		))
		span.End()
	}
}

// startRegistryCall returns a done function recording the duration and outcome of one registry call.
func (i *Instrumentation) startRegistryCall(ctx context.Context, operation string) func(error) {
	start := time.Now()

	return func(err error) {
		result := resultSuccess
		if err != nil {
			result = resultError
		}
		i.registryCallDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.String("result", result),
		))
	}
}

// instrumentHandler wraps inner with a consumer span and metrics per handled message.
func instrumentHandler(instrumentation *Instrumentation, name, stage string, inner messaging.Handler) *InstrumentedHandler {
	return &InstrumentedHandler{
		inner:           inner,
		instrumentation: instrumentation,
		spanName:        name + ".Handle",
		stage:           stage,
	}
}

// InstrumentedHandler decorates a messaging.Handler with a span and metrics per message.
type InstrumentedHandler struct {
	inner           messaging.Handler
	instrumentation *Instrumentation
	spanName        string
	stage           string
}

// Handle implements messaging.Handler.
func (h *InstrumentedHandler) Handle(ctx context.Context, message messaging.Message) error {
	ctx = telemetry.ExtractNATS(ctx, message.Headers())
	ctx, span := h.instrumentation.tracer.Start(ctx, h.spanName,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(attribute.String("messaging.system", "nats")),
	)
	defer span.End()

	start := time.Now()
	err := h.inner.Handle(ctx, message)
	h.instrumentation.recordHandled(ctx, h.stage, time.Since(start), err)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	//nolint:wrapcheck // Pass-through decorator: the inner handler's error must reach the subscriber unwrapped.
	return err
}

// instrumentFailureHandler wraps inner with a consumer span per failed message.
func instrumentFailureHandler(instrumentation *Instrumentation, name string, inner messaging.FailureHandler) *InstrumentedFailureHandler {
	return &InstrumentedFailureHandler{
		inner:           inner,
		instrumentation: instrumentation,
		spanName:        name + ".HandleFailure",
	}
}

// InstrumentedFailureHandler decorates a messaging.FailureHandler with a span per failed message.
type InstrumentedFailureHandler struct {
	inner           messaging.FailureHandler
	instrumentation *Instrumentation
	spanName        string
}

// HandleFailure implements messaging.FailureHandler.
func (h *InstrumentedFailureHandler) HandleFailure(ctx context.Context, message messaging.Message, errorMessage string) error {
	ctx = telemetry.ExtractNATS(ctx, message.Headers())
	ctx, span := h.instrumentation.tracer.Start(ctx, h.spanName,
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "nats"),
			attribute.String("error.message", errorMessage),
		),
	)
	defer span.End()

	err := h.inner.HandleFailure(ctx, message, errorMessage)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	//nolint:wrapcheck // Pass-through decorator: the inner handler's error must reach the subscriber unwrapped.
	return err
}

// recordSpanSkipReason records on the current span why a handler skipped processing.
func recordSpanSkipReason(ctx context.Context, reason string) {
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("handler.skip_reason", reason))
}

// trivySpanName maps a Trivy subcommand to its span name.
func trivySpanName(command string) string {
	switch command {
	case trivyCommandImage:
		return "Trivy.Image"
	case trivyCommandSBOM:
		return "Trivy.SBOM"
	case trivyCommandFilesystem:
		return "Trivy.Filesystem"
	default:
		return "Trivy.Unknown"
	}
}

// errorType maps a handler error to a bounded metric label value.
func errorType(err error) string {
	if reason := apierrors.ReasonForError(err); reason != metav1.StatusReasonUnknown {
		return string(reason)
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	}
	return "unknown"
}
