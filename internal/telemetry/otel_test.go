package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// TestSetup_NoEndpoint asserts that when OTEL_EXPORTER_OTLP_ENDPOINT is unset
// (the default in tests),
// Setup installs propagators, returns a non-nil no-op shutdown,
// and never touches the network.
func TestSetup_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, clientTracerProvider, err := Setup(context.Background(), "test-service", "v0.0.0")
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.NotNil(t, clientTracerProvider)

	// Composite W3C propagator should be installed even in no-op mode.
	prop := otel.GetTextMapPropagator()
	require.NotNil(t, prop)
	assert.Contains(t, prop.Fields(), "traceparent")

	// Shutdown is a no-op and must not error.
	require.NoError(t, shutdown(context.Background()))
}

// TestSetup_WithEndpoint asserts that with OTEL_EXPORTER_OTLP_ENDPOINT set,
// Setup installs real SDK providers instead of the default no-ops.
func TestSetup_WithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	// Short exporter timeout so the shutdown flush fails fast when nothing is listening.
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "100")
	t.Cleanup(resetGlobalProviders)

	shutdown, clientTracerProvider, err := Setup(context.Background(), "test-service", "v0.0.0")
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	assert.IsType(t, &sdktrace.TracerProvider{}, clientTracerProvider)

	assert.IsType(t, &sdktrace.TracerProvider{}, otel.GetTracerProvider())
	assert.IsType(t, &sdkmetric.MeterProvider{}, otel.GetMeterProvider())

	// The endpoint is unreachable, so the flush will fail. That is fine here.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = shutdown(shutdownCtx)
}

// TestKubernetesClientTracerProvider asserts the parent-based sampling of the
// Kubernetes client provider: spans join an existing trace but never start one.
func TestKubernetesClientTracerProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "100")
	t.Cleanup(resetGlobalProviders)

	shutdown, clientTracerProvider, err := Setup(context.Background(), "test-service", "v0.0.0")
	require.NoError(t, err)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = shutdown(shutdownCtx)
	})

	clientTracer := clientTracerProvider.Tracer("test")

	// Without a parent trace, the client span must not be sampled.
	_, orphan := clientTracer.Start(context.Background(), "orphan")
	assert.False(t, orphan.SpanContext().IsSampled())
	orphan.End()

	// Inside a sampled trace, the client span joins it.
	ctx, parent := otel.Tracer("test").Start(context.Background(), "parent")
	require.True(t, parent.SpanContext().IsSampled())
	_, child := clientTracer.Start(ctx, "child")
	assert.True(t, child.SpanContext().IsSampled())
	assert.Equal(t, parent.SpanContext().TraceID(), child.SpanContext().TraceID())
	child.End()
	parent.End()
}

// TestHistogramAggregationSelector asserts histograms aggregate as base2 exponential histograms
// while every other instrument kind keeps the SDK default.
func TestHistogramAggregationSelector(t *testing.T) {
	assert.Equal(t,
		sdkmetric.AggregationBase2ExponentialHistogram{MaxSize: 160, MaxScale: 20},
		histogramAggregationSelector(sdkmetric.InstrumentKindHistogram))

	assert.Equal(t,
		sdkmetric.DefaultAggregationSelector(sdkmetric.InstrumentKindCounter),
		histogramAggregationSelector(sdkmetric.InstrumentKindCounter))
	assert.Equal(t,
		sdkmetric.DefaultAggregationSelector(sdkmetric.InstrumentKindGauge),
		histogramAggregationSelector(sdkmetric.InstrumentKindGauge))
}

// TestBuildResource_InstanceID checks that service.instance.id identifies the replica,
// from the downward-API pod identity when present, from the hostname otherwise.
func TestBuildResource_InstanceID(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("K8S_POD_NAMESPACE", "sbomscanner")
	t.Setenv("K8S_POD_NAME", "worker-abc123")

	res, err := buildResource(context.Background(), "svc", "v0")
	require.NoError(t, err)
	attrs := attributesAsMap(res.Attributes())
	assert.Equal(t, "sbomscanner/worker-abc123", attrs[string(semconv.ServiceInstanceIDKey)])

	t.Setenv("K8S_POD_NAMESPACE", "")
	t.Setenv("K8S_POD_NAME", "")
	res, err = buildResource(context.Background(), "svc", "v0")
	require.NoError(t, err)
	attrs = attributesAsMap(res.Attributes())
	assert.NotEmpty(t, attrs[string(semconv.ServiceInstanceIDKey)], "hostname fallback")
}

// TestBuildResource_ServiceAttrs checks that service.name and service.version end up on the resource.
func TestBuildResource_ServiceAttrs(t *testing.T) {
	// Clear inherited env to keep the test deterministic.
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_SERVICE_NAME", "")

	res, err := buildResource(context.Background(), "svc-under-test", "v1.2.3")
	require.NoError(t, err)
	require.NotNil(t, res)

	attrs := attributesAsMap(res.Attributes())
	assert.Equal(t, "svc-under-test", attrs[string(semconv.ServiceNameKey)])
	assert.Equal(t, "v1.2.3", attrs[string(semconv.ServiceVersionKey)])
}

// TestBuildResource_IncludesDownwardAPI checks that each K8S_* env var lands on the resource under its OTel key.
func TestBuildResource_IncludesDownwardAPI(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("K8S_POD_NAME", "pod-1")
	t.Setenv("K8S_POD_NAMESPACE", "sbomscanner")
	t.Setenv("K8S_NODE_NAME", "node-a")
	t.Setenv("K8S_POD_UID", "uid-123")
	t.Setenv("K8S_CONTAINER_NAME", "controller")

	res, err := buildResource(context.Background(), "svc", "v0")
	require.NoError(t, err)

	attrs := attributesAsMap(res.Attributes())
	assert.Equal(t, "pod-1", attrs[string(semconv.K8SPodNameKey)])
	assert.Equal(t, "sbomscanner", attrs[string(semconv.K8SNamespaceNameKey)])
	assert.Equal(t, "node-a", attrs[string(semconv.K8SNodeNameKey)])
	assert.Equal(t, "uid-123", attrs[string(semconv.K8SPodUIDKey)])
	assert.Equal(t, "controller", attrs[string(semconv.K8SContainerNameKey)])
}

// TestBuildResource_SkipsEmptyDownwardAPI checks that empty K8S_* env vars are not added as empty attributes.
func TestBuildResource_SkipsEmptyDownwardAPI(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	for _, e := range downwardAPIEnv {
		t.Setenv(e.env, "")
	}

	res, err := buildResource(context.Background(), "svc", "v0")
	require.NoError(t, err)

	attrs := attributesAsMap(res.Attributes())
	for _, e := range downwardAPIEnv {
		assert.NotContains(t, attrs, string(e.key))
	}
}

// TestBuildResource_PartialFromMalformedEnv checks that a malformed OTEL_RESOURCE_ATTRIBUTES value still yields a resource with the good pairs.
func TestBuildResource_PartialFromMalformedEnv(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "good.key=good-value,malformed-no-equals")
	t.Setenv("OTEL_SERVICE_NAME", "")

	res, err := buildResource(context.Background(), "svc", "v0")
	require.NoError(t, err)
	require.NotNil(t, res)

	attrs := attributesAsMap(res.Attributes())
	assert.Equal(t, "good-value", attrs["good.key"])
	assert.Equal(t, "svc", attrs[string(semconv.ServiceNameKey)])
}

// attributesAsMap turns an attribute slice into a plain string map for easier assertions.
func attributesAsMap(attrs []attribute.KeyValue) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// resetGlobalProviders returns the process-global TracerProvider and MeterProvider to explicit no-op implementations,
// preventing an SDK provider installed by one test from leaking into others.
func resetGlobalProviders() {
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
}
