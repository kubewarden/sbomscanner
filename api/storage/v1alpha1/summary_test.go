package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSummaryFromResults(t *testing.T) {
	results := []Result{
		{
			Vulnerabilities: []Vulnerability{
				{Severity: "CRITICAL", Suppressed: false},
				{Severity: "HIGH", Suppressed: false},
				{Severity: "MEDIUM", Suppressed: false},
				{Severity: "LOW", Suppressed: false},
				{Severity: "UNKNOWN", Suppressed: false},
				{Severity: "HIGH", Suppressed: true}, // suppressed, shouldn't count in HIGH
			},
		},
		{
			Vulnerabilities: []Vulnerability{
				{Severity: "CRITICAL", Suppressed: false},
				{Severity: "MEDIUM", Suppressed: true}, // another suppressed
			},
		},
	}

	summary := NewSummaryFromResults(results)

	expected := Summary{
		Critical:   2,
		High:       1,
		Medium:     1,
		Low:        1,
		Unknown:    1,
		Suppressed: 2,
	}

	assert.Equal(t, expected, summary)
}
