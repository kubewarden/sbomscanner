package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
)

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
