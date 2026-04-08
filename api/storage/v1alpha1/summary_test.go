package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSummaryFromResults(t *testing.T) {
	results := []Result{
		{
			Vulnerabilities: []Vulnerability{
				{Severity: SeverityCritical, Suppressed: false},
				{Severity: SeverityHigh, Suppressed: false},
				{Severity: SeverityMedium, Suppressed: false},
				{Severity: SeverityLow, Suppressed: false},
				{Severity: SeverityUnknown, Suppressed: false},
				{Severity: SeverityHigh, Suppressed: true}, // suppressed, shouldn't count in HIGH
			},
		},
		{
			Vulnerabilities: []Vulnerability{
				{Severity: SeverityCritical, Suppressed: false},
				{Severity: SeverityMedium, Suppressed: true}, // another suppressed
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
