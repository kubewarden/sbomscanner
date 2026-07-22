package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// ShutdownFunc flushes and stops the providers installed by Setup.
// It is always safe to call (no-op when telemetry is disabled).
type ShutdownFunc func(ctx context.Context) error

// envOTLPEndpoint is the environment variable inspected to decide whether telemetry export is enabled.
// When unset, Setup is a no-op.
//
// We deliberately check only the unsigned/general endpoint variable.
// Users who want to enable only one signal can set both OTEL_EXPORTER_OTLP_ENDPOINT and OTEL_TRACES_SAMPLER=always_off
// (or the metric equivalent) per the OTel spec.
const envOTLPEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"

// envHistogramAggregation is the standard environment variable selecting the exporter's
// default histogram aggregation. Setup defaults it to base2 exponential histograms;
// setting the variable restores the standard SDK behaviour.
const envHistogramAggregation = "OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION"

// Option configures Setup.
type Option func(*setupConfig)

type setupConfig struct {
	metricProducers []sdkmetric.Producer
}

// WithMetricProducer registers an additional metric producer,
// e.g. the Prometheus bridge exposing an already populated Prometheus registry,
// whose metrics are collected and exported alongside the SDK's own on every reader tick.
// Ignored when telemetry export is disabled.
func WithMetricProducer(producer sdkmetric.Producer) Option {
	return func(config *setupConfig) {
		config.metricProducers = append(config.metricProducers, producer)
	}
}

// Setup installs global Tracer and Meter providers and the W3C TraceContext + Baggage propagators.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset, Setup installs the W3C propagators, leaves the global
// TracerProvider and MeterProvider as their default no-op implementations, and returns a no-op shutdown function.
// Otherwise it constructs OTLP/gRPC trace and metric exporters
// (which themselves read OTEL_EXPORTER_OTLP_* environment variables)
// and wires them through a BatchSpanProcessor and a PeriodicReader.
//
// serviceName and serviceVersion populate the standard resource attributes,
// and are overridable via OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES.
func Setup(ctx context.Context, serviceName, serviceVersion string, opts ...Option) (ShutdownFunc, error) {
	// Always install W3C propagators so application code can call otel.GetTextMapPropagator() without branching on whether export is enabled.
	// Propagation through NATS headers (see nats.go) is a pure in-process concern and works even with no-op providers.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if os.Getenv(envOTLPEndpoint) == "" {
		// No-op shutdown.
		// The default global TracerProvider and MeterProvider are already no-op implementations.
		return func(context.Context) error { return nil }, nil
	}

	res, err := buildResource(ctx, serviceName, serviceVersion)
	if err != nil {
		return nil, fmt.Errorf("building otel resource: %w", err)
	}

	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	// Histograms default to base2 exponential aggregation: bucket resolution adapts
	// to the recorded values, so instruments never depend on hand-picked boundaries.
	// The standard aggregation environment variable, when set, takes precedence.
	var metricOpts []otlpmetricgrpc.Option
	if os.Getenv(envHistogramAggregation) == "" {
		metricOpts = append(metricOpts, otlpmetricgrpc.WithAggregationSelector(histogramAggregationSelector))
	}
	metricExporter, err := otlpmetricgrpc.New(ctx, metricOpts...)
	if err != nil {
		// Roll back the trace exporter so we don't leak its gRPC connection.
		// Uses a fresh context so a cancelled caller ctx still lets the exporter flush.
		// The rollback error (if any) is joined onto the returned error, never dropped.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return nil, errors.Join(
			fmt.Errorf("creating OTLP metric exporter: %w", err),
			traceExporter.Shutdown(shutdownCtx),
		)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	var config setupConfig
	for _, opt := range opts {
		opt(&config)
	}
	readerOpts := make([]sdkmetric.PeriodicReaderOption, 0, len(config.metricProducers))
	for _, producer := range config.metricProducers {
		readerOpts = append(readerOpts, sdkmetric.WithProducer(producer))
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, readerOpts...)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	shutdown := func(ctx context.Context) error {
		// Best-effort: try both, surface both errors.
		return errors.Join(
			tracerProvider.Shutdown(ctx),
			meterProvider.Shutdown(ctx),
		)
	}

	return shutdown, nil
}

// histogramAggregationSelector aggregates histograms as base2 exponential histograms
// and leaves every other instrument kind on the SDK default.
func histogramAggregationSelector(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	if kind == sdkmetric.InstrumentKindHistogram {
		return sdkmetric.AggregationBase2ExponentialHistogram{MaxSize: 160, MaxScale: 20}
	}
	return sdkmetric.DefaultAggregationSelector(kind)
}

// downwardAPIEnv maps the environment variables wired by the Helm Deployments (downward API) to OTel semantic-convention attribute keys.
// Empty values are skipped so we don't fabricate hollow attributes.
var downwardAPIEnv = []struct {
	env string
	key attribute.Key
}{
	{"K8S_POD_NAME", semconv.K8SPodNameKey},
	{"K8S_POD_NAMESPACE", semconv.K8SNamespaceNameKey},
	{"K8S_NODE_NAME", semconv.K8SNodeNameKey},
	{"K8S_POD_UID", semconv.K8SPodUIDKey},
	{"K8S_CONTAINER_NAME", semconv.K8SContainerNameKey},
}

// buildResource merges SDK defaults
// (which already include attributes from OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME)
// with the service name and version supplied by the caller,
// plus any Kubernetes pod metadata exposed by the chart.
func buildResource(ctx context.Context, serviceName, serviceVersion string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(serviceVersion),
	}
	for _, e := range downwardAPIEnv {
		if v := os.Getenv(e.env); v != "" {
			attrs = append(attrs, e.key.String(v))
		}
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		// resource.New can return a partial resource with a non-fatal error
		// (e.g. schema URL conflicts when merging).
		// Surface the resource if we have one and let the SDK use it.
		if res == nil {
			return nil, fmt.Errorf("creating otel resource: %w", err)
		}
	}
	return res, nil
}
