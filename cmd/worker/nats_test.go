package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeNodeSubscriberName(t *testing.T) {
	tests := []struct {
		name     string
		nodeName string
		expected string
	}{
		{
			name:     "plain node name is unchanged",
			nodeName: "pippo",
			expected: "worker-node-pippo",
		},
		{
			name:     "FQDN dots are replaced with underscores",
			nodeName: "turingpi-node1.localdomain",
			expected: "worker-node-turingpi-node1_localdomain",
		},
		{
			name:     "dot and dash node names do not collide",
			nodeName: "node-1.local",
			expected: "worker-node-node-1_local",
		},
		{
			name:     "characters that are invalid in node names are removed",
			nodeName: "node*1 .local",
			expected: "worker-node-node1_local",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, sanitizeNodeSubscriberName(test.nodeName))
		})
	}
}

func TestSanitizeNodeSubscriberName_Overlong(t *testing.T) {
	// The longest possible node name (253 chars) plus the "worker-node-" prefix
	// exceeds the 255-char limit and must be truncated with a hash suffix.
	long := strings.Repeat("a", 252)
	sanitizedA := sanitizeNodeSubscriberName(long + "b")
	sanitizedB := sanitizeNodeSubscriberName(long + "c")

	require.Len(t, sanitizedA, 255)
	require.Len(t, sanitizedB, 255)
	require.NotEqual(t, sanitizedA, sanitizedB, "node names differing past the truncation point must stay distinct")
	require.Equal(t, sanitizedA, sanitizeNodeSubscriberName(long+"b"), "sanitization must be deterministic")
}
