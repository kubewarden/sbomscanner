package messaging

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const maxDeliver = 5

// RetryConfig defines retry behavior for message handling.
type RetryConfig struct {
	// BaseDelay is the base backoff delay.
	// Subsequent retries will use an exponential backoff strategy based on this value.
	BaseDelay time.Duration
	// Jitter is the jitter factor to apply to the backoff delay.
	// For example, a jitter of 0.2 means the delay can vary by +/-20%.
	Jitter float64
	// MaxAttempts is the maximum number of attempts (including the first try).
	MaxAttempts int
}

// HandlerRegistry is a map that associates subjects with their respective handlers.
type HandlerRegistry map[string]Handler

// NatsSubscriber is an implementation of a message subscriber that uses NATS JetStream to receive messages.
type NatsSubscriber struct {
	cons           jetstream.Consumer
	handlers       HandlerRegistry
	failureHandler FailureHandler
	retryConfig    *RetryConfig
	logger         *slog.Logger
}

// NewNatsSubscriber creates a new NatsSubscriber instance with the provided NATS connection and durable subscription name.
func NewNatsSubscriber(ctx context.Context,
	nc *nats.Conn,
	durable string,
	handlers HandlerRegistry,
	failureHandler FailureHandler,
	retryConfig *RetryConfig,
	logger *slog.Logger,
) (*NatsSubscriber, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	var subjects []string
	for subject := range handlers {
		subjects = append(subjects, subject)
	}

	cons, err := js.CreateOrUpdateConsumer(ctx,
		streamName,
		jetstream.ConsumerConfig{
			FilterSubjects: subjects,
			Durable:        durable,
			// AckWait defines how long the server will wait for an acknowledgement
			// before resending a message.
			// We set it to a higher value than the default to allow for longer processing times.
			// Handlers that are expected to take longer should use `InProgress` to extend the AckWait.
			AckWait: 10 * time.Minute,
			// We do not set MaxDeliver here because we want to handle retries manually
			// to implement custom backoff and failure handling logic.
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create or update consumer: %w", err)
	}

	subscriber := &NatsSubscriber{
		cons:           cons,
		handlers:       handlers,
		failureHandler: failureHandler,
		retryConfig:    retryConfig,
		logger:         logger.With("component", "subscriber"),
	}

	return subscriber, nil
}

// Run starts the subscriber and processes messages in a loop until the context is done.
func (s *NatsSubscriber) Run(ctx context.Context) error {
	consContext, err := s.cons.Consume(
		func(msg jetstream.Msg) {
			s.logger.DebugContext(ctx, "Processing message", "subject", msg.Subject())

			metadata, err := msg.Metadata()
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to get message metadata",
					"subject", msg.Subject(),
					"error", err,
				)
				// Can't determine delivery count, NAK without delay
				if err := msg.Nak(); err != nil {
					s.logger.ErrorContext(ctx, "Failed to nak message",
						"subject", msg.Subject(),
						"error", err,
					)
				}
				return
			}

			if err := s.handleMessage(ctx, msg.Subject(), msg); err != nil {
				s.handleFailure(ctx, msg, metadata, err)
				return
			}

			if err := msg.Ack(); err != nil {
				s.logger.ErrorContext(ctx, "Failed to ack message",
					"subject", msg.Subject(),
					"error", err,
				)
			}
		},
	)
	if err != nil {
		return fmt.Errorf("failed to start consuming: %w", err)
	}

	s.logger.InfoContext(ctx, "Subscriber started, waiting for messages...")

	<-ctx.Done()

	s.logger.InfoContext(ctx, "Subscriber shutting down...")
	consContext.Stop()

	return nil
}

// handleMessage handles individual message processing.
func (s *NatsSubscriber) handleMessage(ctx context.Context, subject string, message Message) error {
	handler, found := s.handlers[subject]
	if !found {
		return fmt.Errorf("no handler found for subject: %s", subject)
	}

	if err := handler.Handle(ctx, message); err != nil {
		return fmt.Errorf("failed to handle message on subject %s: %w", subject, err)
	}

	return nil
}

// handleFailure handles message processing failures, either by retrying with backoff
// or by invoking the failure handler if max retries have been exceeded.
func (s *NatsSubscriber) handleFailure(ctx context.Context, msg jetstream.Msg, metadata *jetstream.MsgMetadata, processingErr error) {
	s.logger.ErrorContext(ctx, "Failed to process message",
		"subject", msg.Subject(),
		"headers", msg.Headers(),
		"error", processingErr,
	)

	if metadata.NumDelivered >= maxDeliver {
		s.logger.InfoContext(ctx, "Max delivery attempts reached, invoking failure handler",
			"subject", msg.Subject(),
			"deliveryCount", metadata.NumDelivered,
			"maxAttempts", s.retryConfig.MaxAttempts,
		)

		if err := s.failureHandler.HandleFailure(ctx, msg, processingErr.Error()); err != nil {
			s.logger.ErrorContext(ctx, "Failed to handle failure",
				"subject", msg.Subject(),
				"error", err,
			)
		}
		// Ack the message to remove it from the stream after failure handling
		if err := msg.Ack(); err != nil {
			s.logger.ErrorContext(ctx, "Failed to ack message after failure handling",
				"subject", msg.Subject(),
				"error", err,
			)
		}

		return
	}

	delay := s.backoffDelay(int(metadata.NumDelivered))
	s.logger.InfoContext(ctx, "Retrying failed message after delay",
		"subject", msg.Subject(),
		"deliveryCount", metadata.NumDelivered,
		"maxAttempts", s.retryConfig.MaxAttempts,
		"delay", delay,
	)
	if err := msg.NakWithDelay(delay); err != nil {
		s.logger.ErrorContext(ctx, "Failed to nak message with delay",
			"subject", msg.Subject(),
			"error", err,
		)
	}
}

// backoffDelay calculates exponential backoff with jitter
func (s *NatsSubscriber) backoffDelay(attempt int) time.Duration {
	base := float64(s.retryConfig.BaseDelay)
	delay := base * math.Pow(2, float64(attempt-1)) // exponential

	if s.retryConfig.Jitter > 0 {
		// Using math/rand for backoff jitter is fine - this isn't security-sensitive
		//nolint:gosec // G404: weak random source is acceptable for retry jitter
		jitter := delay * (s.retryConfig.Jitter * (rand.Float64()*2 - 1))
		delay += jitter
		if delay < 0 {
			delay = 0
		}
	}

	return time.Duration(delay)
}
