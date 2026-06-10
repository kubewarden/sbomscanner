package messaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

const testSubscriberSubject = "sbomscanner.subscriber.test"

type testMessage struct {
	data []byte
}

func (m *testMessage) Data() []byte {
	return m.data
}

func (m *testMessage) InProgress() error {
	return nil
}

type testHandler struct {
	handleFunc func(Message) error
}

func (h *testHandler) Handle(_ context.Context, message Message) error {
	return h.handleFunc(message)
}

type testFailureHandler struct {
	handleFailureFunc func(message Message, errorMessage string) error
}

func (h *testFailureHandler) HandleFailure(_ context.Context, message Message, errorMessage string) error {
	return h.handleFailureFunc(message, errorMessage)
}

func TestSubscriber_Run(t *testing.T) {
	opts := natstest.DefaultTestOptions
	opts.Port = -1 // Use a random port
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	ns := natstest.RunServer(&opts)
	defer ns.Shutdown()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	publisher, err := NewNatsPublisher(t.Context(), nc, slog.Default())
	require.NoError(t, err)

	processed := make(chan Message, 1)
	done := make(chan struct{})

	handleFunc := func(m Message) error {
		processed <- m
		return nil
	}

	testHandler := &testHandler{handleFunc: handleFunc}
	handlers := HandlerRegistry{
		testSubscriberSubject: testHandler,
	}
	subscriber, err := NewNatsSubscriber(t.Context(), nc, "test-durable", handlers, nil, nil, slog.Default())
	require.NoError(t, err, "failed to create subscriber")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	message := []byte(`{"data":"test data"}`)
	err = publisher.Publish(t.Context(), testSubscriberSubject, "id", message)
	require.NoError(t, err, "failed to publish message")

	go func() {
		err = subscriber.Run(ctx)
		close(done)
	}()

	select {
	case processedMessage := <-processed:
		require.Equal(t, message, processedMessage.Data(), "unexpected message")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timed out waiting for message to be processed")
	}

	cancel()
	<-done

	require.NoError(t, err, "unexpected subscriber error")
}

func TestSubscriber_Run_WithRetry(t *testing.T) {
	opts := natstest.DefaultTestOptions
	opts.Port = -1 // Use a random port
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	ns := natstest.RunServer(&opts)
	defer ns.Shutdown()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	publisher, err := NewNatsPublisher(t.Context(), nc, slog.Default())
	require.NoError(t, err)

	var attemptCount atomic.Int32
	processed := make(chan Message, 1)
	done := make(chan struct{})

	// Handler that fails 3 times then succeeds
	handleFunc := func(m Message) error {
		count := attemptCount.Add(1)
		if count < 4 {
			return fmt.Errorf("processing failed, attempt %d", count)
		}
		processed <- m
		return nil
	}

	testHandler := &testHandler{handleFunc: handleFunc}
	handlers := HandlerRegistry{
		testSubscriberSubject: testHandler,
	}
	retryConfig := &RetryConfig{
		BaseDelay:   100 * time.Millisecond,
		Jitter:      0,
		MaxAttempts: 5,
	}
	subscriber, err := NewNatsSubscriber(t.Context(), nc, "test-durable-retry", handlers, nil, retryConfig, slog.Default())
	require.NoError(t, err, "failed to create subscriber")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	message := []byte(`{"data":"test retry data"}`)
	err = publisher.Publish(t.Context(), testSubscriberSubject, "id", message)
	require.NoError(t, err, "failed to publish message")

	go func() {
		err = subscriber.Run(ctx)
		close(done)
	}()

	select {
	case processedMessage := <-processed:
		require.Equal(t, message, processedMessage.Data(), "unexpected message")
		require.Equal(t, int32(4), attemptCount.Load(), "expected 4 attempts (1 initial + 3 retries)")
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for message to be processed after retries")
	}

	cancel()
	<-done
	require.NoError(t, err, "unexpected subscriber error")
}

func TestSubscriber_Run_WithMaxRetriesExceeded(t *testing.T) {
	opts := natstest.DefaultTestOptions
	opts.Port = -1 // Use a random port
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	ns := natstest.RunServer(&opts)
	defer ns.Shutdown()

	nc, err := nats.Connect(ns.ClientURL())
	require.NoError(t, err)
	defer nc.Close()

	publisher, err := NewNatsPublisher(t.Context(), nc, slog.Default())
	require.NoError(t, err)

	var attemptCount atomic.Int32
	failureHandled := make(chan struct{}, 1)
	done := make(chan struct{})

	// Handler that always fails
	handleFunc := func(_ Message) error {
		count := attemptCount.Add(1)
		return fmt.Errorf("processing failed, attempt %d", count)
	}

	failureHandleFunc := func(message Message, errorMessage string) error {
		require.Contains(t, string(message.Data()), "max-retry-test")
		require.Contains(t, errorMessage, "processing failed")
		require.Equal(t, int32(5), attemptCount.Load(), "expected exactly 5 attempts before failure handler")

		failureHandled <- struct{}{}
		return nil
	}

	testHandler := &testHandler{handleFunc: handleFunc}
	testFailureHandler := &testFailureHandler{handleFailureFunc: failureHandleFunc}

	handlers := HandlerRegistry{
		testSubscriberSubject: testHandler,
	}
	retryConfig := &RetryConfig{
		BaseDelay:   100 * time.Millisecond,
		Jitter:      0,
		MaxAttempts: 5,
	}
	subscriber, err := NewNatsSubscriber(t.Context(), nc, "test-durable-max-retry", handlers, testFailureHandler, retryConfig, slog.Default())
	require.NoError(t, err, "failed to create subscriber")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	message := []byte(`{"data":"max-retry-test"}`)
	err = publisher.Publish(t.Context(), testSubscriberSubject, "id", message)
	require.NoError(t, err, "failed to publish message")

	go func() {
		err = subscriber.Run(ctx)
		close(done)
	}()

	select {
	case <-failureHandled:
	// Success, failure handler was called
	case <-time.After(5 * time.Second):
		require.Fail(t, "timed out waiting for failure handler after max retries")
	}

	cancel()
	<-done
	require.NoError(t, err, "unexpected subscriber error")
}

func TestSubscriber_handleMessage(t *testing.T) {
	tests := []struct {
		name          string
		subject       string
		message       testMessage
		handleFunc    func(Message) error
		expectedError string
	}{
		{
			name:    "valid message",
			subject: testSubscriberSubject,
			message: testMessage{
				data: []byte("data"),
			},
			handleFunc: func(_ Message) error {
				return nil
			},
			expectedError: "",
		},
		{
			name:    "unregistered subject",
			subject: "unknown",
			message: testMessage{
				data: []byte("data"),
			},
			expectedError: "no handler found for subject: unknown",
		},
		{
			name:    "handler failure",
			subject: testSubscriberSubject,
			message: testMessage{
				data: []byte("data"),
			},
			handleFunc: func(_ Message) error {
				return errors.New("handler error")
			},
			expectedError: "failed to handle message on subject sbomscanner.subscriber.test: handler error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handlers := HandlerRegistry{}
			handlers[testSubscriberSubject] = &testHandler{
				handleFunc: test.handleFunc,
			}

			subscriber := &NatsSubscriber{
				handlers: handlers,
				logger:   slog.Default(),
			}

			err := subscriber.handleMessage(t.Context(), test.subject, &test.message)

			if test.expectedError == "" {
				require.NoError(t, err, "expected no error, got: %v", err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedError, "expected error message does not match")
			}
		})
	}
}
