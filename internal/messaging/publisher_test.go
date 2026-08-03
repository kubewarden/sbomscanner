package messaging

import (
	"log/slog"
	"testing"

	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const testPublisherSubject = "sbomscanner.publisher.test"

func TestPublisher_Publish(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	opts := natstest.DefaultTestOptions
	opts.Port = -1 // Use a random port
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	ns := natstest.RunServer(&opts)
	defer ns.Shutdown()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)

	publisher, err := NewNatsPublisher(t.Context(), nc, slog.Default())
	require.NoError(t, err)

	// Publish within an active span, so the message must carry its traceparent.
	tracerProvider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tracerProvider.Shutdown(t.Context()) })
	publishCtx, span := tracerProvider.Tracer("test").Start(t.Context(), "publish")
	defer span.End()

	message := []byte(`{"data":"test data"}`)
	err = publisher.Publish(publishCtx, testPublisherSubject, "id", message)
	require.NoError(t, err)

	// Send a duplicate message with the same ID to test idempotency
	messageDup := []byte(`{"data":"test data duplicate"}`)
	err = publisher.Publish(t.Context(), testPublisherSubject, "id", messageDup)
	require.NoError(t, err)

	cons, err := publisher.js.CreateOrUpdateConsumer(t.Context(), streamName, jetstream.ConsumerConfig{})
	require.NoError(t, err)

	batch, err := cons.FetchNoWait(10) // Fetch max 10 messages, but we expect only 1
	require.NoError(t, err)
	require.NoError(t, batch.Error())

	var messages []jetstream.Msg
	for msg := range batch.Messages() {
		messages = append(messages, msg)
	}
	require.Len(t, messages, 1)

	receivedMessage := messages[0]
	assert.Equal(t, testPublisherSubject, receivedMessage.Subject())
	assert.Equal(t, message, receivedMessage.Data())
	assert.Contains(t, receivedMessage.Headers().Get("traceparent"), span.SpanContext().TraceID().String(),
		"the message must carry the traceparent of the publishing context")
}
