package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"k8s.io/apimachinery/pkg/watch"
)

// noopInstrumentation returns an Instrumentation backed by no-op providers.
func noopInstrumentation(t *testing.T) *Instrumentation {
	t.Helper()

	instrumentation, err := NewInstrumentation(
		tracenoop.NewTracerProvider().Tracer("test"),
		metricnoop.NewMeterProvider().Meter("test"),
	)
	require.NoError(t, err)
	return instrumentation
}

// mustReadEvents reads n events from the watch.Interface or fails the test if not enough events are received in time.
func mustReadEvents(t *testing.T, w watch.Interface, n int) []watch.Event {
	events := make([]watch.Event, 0, n)

	require.Eventually(t, func() bool {
		select {
		case evt := <-w.ResultChan():
			events = append(events, evt)
			return len(events) == n
		default:
			return false
		}
	}, time.Second, 5*time.Millisecond, "expected %d events", n)

	return events
}
