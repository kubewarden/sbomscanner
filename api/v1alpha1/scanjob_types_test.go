package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestScanJobMarks(t *testing.T) {
	scheduled := func(s *ScanJob) { s.MarkScheduled(ReasonScanJobScheduled, "scheduled") }
	inProgress := func(s *ScanJob) { s.MarkInProgress(ReasonScanJobInProgress, "in progress") }
	complete := func(s *ScanJob) { s.MarkComplete(ReasonScanJobComplete, "complete") }
	failed := func(s *ScanJob) { s.MarkFailed(ReasonScanJobFailed, "failed") }

	states := map[string]func(*ScanJob) bool{
		"pending":    (*ScanJob).IsPending,
		"scheduled":  (*ScanJob).IsScheduled,
		"inProgress": (*ScanJob).IsInProgress,
		"complete":   (*ScanJob).IsComplete,
		"failed":     (*ScanJob).IsFailed,
	}

	tests := []struct {
		name               string
		marks              []func(*ScanJob)
		wantState          string
		wantStartTime      bool
		wantCompletionTime bool
	}{
		{
			name:      "initialized",
			wantState: "pending",
		},
		{
			name:      "scheduled",
			marks:     []func(*ScanJob){scheduled},
			wantState: "scheduled",
		},
		{
			name:          "in progress",
			marks:         []func(*ScanJob){scheduled, inProgress},
			wantState:     "inProgress",
			wantStartTime: true,
		},
		{
			name:          "in progress with repeated updates",
			marks:         []func(*ScanJob){scheduled, inProgress, inProgress, inProgress},
			wantState:     "inProgress",
			wantStartTime: true,
		},
		{
			name:               "complete",
			marks:              []func(*ScanJob){scheduled, inProgress, complete},
			wantState:          "complete",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
		{
			name:               "complete after repeated updates",
			marks:              []func(*ScanJob){scheduled, inProgress, inProgress, complete},
			wantState:          "complete",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
		{
			name:               "failed before start",
			marks:              []func(*ScanJob){scheduled, failed},
			wantState:          "failed",
			wantCompletionTime: true,
		},
		{
			name:               "failed while in progress",
			marks:              []func(*ScanJob){scheduled, inProgress, failed},
			wantState:          "failed",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanJob := &ScanJob{}
			scanJob.InitializeConditions()

			var firstStartTime *metav1.Time
			for _, mark := range test.marks {
				mark(scanJob)
				if firstStartTime == nil {
					firstStartTime = scanJob.Status.StartTime
				}
			}

			for name, isState := range states {
				assert.Equal(t, name == test.wantState, isState(scanJob), name)
			}

			if test.wantStartTime {
				require.NotNil(t, scanJob.Status.StartTime)
				assert.Equal(t, firstStartTime, scanJob.Status.StartTime)
			} else {
				assert.Nil(t, scanJob.Status.StartTime)
			}

			if test.wantCompletionTime {
				require.NotNil(t, scanJob.Status.CompletionTime)
			} else {
				assert.Nil(t, scanJob.Status.CompletionTime)
			}

			if test.wantStartTime && test.wantCompletionTime {
				assert.False(t, scanJob.Status.CompletionTime.Before(scanJob.Status.StartTime))
			}
		})
	}
}
