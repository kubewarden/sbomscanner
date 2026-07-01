package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

// TestSetup_NoEndpoint asserts that when OTEL_EXPORTER_OTLP_ENDPOINT is unset
// (the default in tests),
// Setup installs propagators, returns a non-nil no-op shutdown,
// and never touches the network.
func TestSetup_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, err := Setup(context.Background(), "test-service", "v0.0.0")
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// Composite W3C propagator should be installed even in no-op mode.
	prop := otel.GetTextMapPropagator()
	require.NotNil(t, prop)
	assert.Contains(t, prop.Fields(), "traceparent")

	// Shutdown is a no-op and must not error.
	require.NoError(t, shutdown(context.Background()))
}
