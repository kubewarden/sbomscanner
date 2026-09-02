package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// sanitizeNodeSubscriberName returns the durable consumer name of the node worker
// for the given node name.
// It assumes that nodeName is a valid Kubernetes node name (RFC 1123 DNS subdomain):
// lowercase alphanumerics, '-', and '.', at most 253 characters.
// NATS forbids '.' in consumer names, so dots are replaced with '_'.
// A node name cannot contain '_', so two node names can never map to the same result.
// Characters that cannot appear in a node name are removed defensively.
// A name over the 255-character NATS limit is truncated
// and gets a hash of the original node name as suffix to stay collision-resistant.
func sanitizeNodeSubscriberName(nodeName string) string {
	const maxLen = 255

	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r == '.':
			return '_'
		case r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			return r
		default:
			return -1
		}
	}, nodeName)

	name := "worker-node-" + sanitized
	if len(name) > maxLen {
		hash := sha256.Sum256([]byte(nodeName))
		suffix := "-" + hex.EncodeToString(hash[:16])
		name = name[:maxLen-len(suffix)] + suffix
	}

	return name
}
