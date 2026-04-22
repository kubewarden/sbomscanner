package messaging

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	streamName         = "SBOMSCANNER"
	sbomscannerSubject = "sbomscanner.>"
)

type Publisher interface {
	// Publish publishes a message.
	// The messageID is set as the "Nats-Msg-Id" header to enable deduplication by JetStream.
	// If a message with the same ID has already been published in, it will be ignored.
	// The default deduplication window is 2 minutes.
	Publish(ctx context.Context, subject string, messageID string, message []byte) error
}

// NatsPublisher is an implementation of the Publisher interface that uses NATS JetStream to publish messages.
type NatsPublisher struct {
	js     jetstream.JetStream
	logger *slog.Logger
}

// NewNatsPublisher creates a new NatsPublisher instance with the provided NATS connection.
func NewNatsPublisher(ctx context.Context, nc *nats.Conn, logger *slog.Logger) (*NatsPublisher, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	logger = logger.With("component", "nats_publisher")

	// CreateStream is an idempotent operation, if the stream already exists, it will succeed without error.
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{
		Name:      streamName,
		Retention: jetstream.WorkQueuePolicy,
		Subjects:  []string{sbomscannerSubject},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream stream: %w", err)
	}

	logger.DebugContext(ctx, "Stream created", "stream", streamName, "subjects", sbomscannerSubject)

	publisher := &NatsPublisher{
		js:     js,
		logger: logger,
	}

	return publisher, nil
}

// Publish publishes a message.
// The messageID is set as the "Nats-Msg-Id" header to enable deduplication by JetStream.
// If a message with the same ID has already been published in, it will be ignored.
// The default deduplication window is 2 minutes.
func (p *NatsPublisher) Publish(ctx context.Context, subject string, messageID string, message []byte) error {
	msg := &nats.Msg{
		Subject: subject,
		Data:    message,
		Header: nats.Header{
			jetstream.MsgIDHeader: []string{messageID},
		},
	}
	if _, err := p.js.PublishMsg(ctx, msg); err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	p.logger.DebugContext(ctx, "Message published", "subject", msg.Subject, "header", msg.Header, "message", string(msg.Data))

	return nil
}
