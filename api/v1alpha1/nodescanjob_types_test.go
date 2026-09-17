package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNodeScanJobMarks(t *testing.T) {
	scheduled := func(s *NodeScanJob) { s.MarkScheduled(ReasonNodeScanJobScheduled, "scheduled") }
	inProgress := func(s *NodeScanJob) { s.MarkInProgress(ReasonNodeScanJobInProgress, "in progress") }
	complete := func(s *NodeScanJob) { s.MarkComplete(ReasonNodeScanJobComplete, "complete") }
	failed := func(s *NodeScanJob) { s.MarkFailed(ReasonNodeScanJobFailed, "failed") }

	states := map[string]func(*NodeScanJob) bool{
		"pending":    (*NodeScanJob).IsPending,
		"scheduled":  (*NodeScanJob).IsScheduled,
		"inProgress": (*NodeScanJob).IsInProgress,
		"complete":   (*NodeScanJob).IsComplete,
		"failed":     (*NodeScanJob).IsFailed,
	}

	tests := []struct {
		name               string
		marks              []func(*NodeScanJob)
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
			marks:     []func(*NodeScanJob){scheduled},
			wantState: "scheduled",
		},
		{
			name:          "in progress",
			marks:         []func(*NodeScanJob){scheduled, inProgress},
			wantState:     "inProgress",
			wantStartTime: true,
		},
		{
			name:          "in progress with repeated updates",
			marks:         []func(*NodeScanJob){scheduled, inProgress, inProgress, inProgress},
			wantState:     "inProgress",
			wantStartTime: true,
		},
		{
			name:               "complete",
			marks:              []func(*NodeScanJob){scheduled, inProgress, complete},
			wantState:          "complete",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
		{
			name:               "complete after repeated updates",
			marks:              []func(*NodeScanJob){scheduled, inProgress, inProgress, complete},
			wantState:          "complete",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
		{
			name:               "failed before start",
			marks:              []func(*NodeScanJob){scheduled, failed},
			wantState:          "failed",
			wantCompletionTime: true,
		},
		{
			name:               "failed while in progress",
			marks:              []func(*NodeScanJob){scheduled, inProgress, failed},
			wantState:          "failed",
			wantStartTime:      true,
			wantCompletionTime: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nodeScanJob := &NodeScanJob{}
			nodeScanJob.InitializeConditions()

			var firstStartTime *metav1.Time
			for _, mark := range test.marks {
				mark(nodeScanJob)
				if firstStartTime == nil {
					firstStartTime = nodeScanJob.Status.StartTime
				}
			}

			for name, isState := range states {
				assert.Equal(t, name == test.wantState, isState(nodeScanJob), name)
			}

			if test.wantStartTime {
				require.NotNil(t, nodeScanJob.Status.StartTime)
				assert.Equal(t, firstStartTime, nodeScanJob.Status.StartTime)
			} else {
				assert.Nil(t, nodeScanJob.Status.StartTime)
			}

			if test.wantCompletionTime {
				require.NotNil(t, nodeScanJob.Status.CompletionTime)
			} else {
				assert.Nil(t, nodeScanJob.Status.CompletionTime)
			}

			if test.wantStartTime && test.wantCompletionTime {
				assert.False(t, nodeScanJob.Status.CompletionTime.Before(nodeScanJob.Status.StartTime))
			}
		})
	}
}
