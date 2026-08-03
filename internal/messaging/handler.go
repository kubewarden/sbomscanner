package messaging

import (
	"context"

	"github.com/nats-io/nats.go"
)

// Message represents a message received by the handler.
// It provides access to the message data and headers, and allows marking the message as in-progress
// to extend the acknowledgement timeout during long-running operations.
type Message interface {
	Data() []byte
	Headers() nats.Header
	InProgress() error
}

// Handler processes messages.
type Handler interface {
	Handle(ctx context.Context, message Message) error
}

// FailureHandler handles messages that failed processing after exhausting retries.
type FailureHandler interface {
	HandleFailure(ctx context.Context, message Message, errorMessage string) error
}
