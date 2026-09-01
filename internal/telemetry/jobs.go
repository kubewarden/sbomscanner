package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// Bounded result label values of the job counters.
const (
	jobResultComplete = "complete"
	jobResultFailed   = "failed"
)

// Bounded source label values of the ScanJob counter.
const (
	scanJobSourceRegistry = "registry"
	scanJobSourceWorkload = "workload"
)

// JobMetrics counts ScanJobs and NodeScanJobs that reach a terminal state.
// The counters are incremented at the write sites: every code path that persists
// a terminal status calls a Record method right after the successful status update.
// Each completion is counted once, by the process that persists it, without leader
// election or transition tracking. A crash between the status write and the metric
// export can lose that count: the counters favor no double counting over durable delivery.
type JobMetrics struct {
	scanJobs     metric.Int64Counter
	nodeScanJobs metric.Int64Counter
}

// NewJobMetrics creates the job counters and pre-creates the bounded series at zero,
// so range queries see the first completion: increase() cannot see the birth of a series.
func NewJobMetrics(meter metric.Meter) (*JobMetrics, error) {
	scanJobs, err := meter.Int64Counter(
		"sbomscanner.scanjobs",
		metric.WithDescription("Number of ScanJobs that reached a terminal state."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sbomscanner.scanjobs counter: %w", err)
	}

	nodeScanJobs, err := meter.Int64Counter(
		"sbomscanner.nodescanjobs",
		metric.WithDescription("Number of NodeScanJobs that reached a terminal state."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sbomscanner.nodescanjobs counter: %w", err)
	}

	for _, result := range []string{jobResultComplete, jobResultFailed} {
		for _, source := range []string{scanJobSourceRegistry, scanJobSourceWorkload} {
			scanJobs.Add(context.Background(), 0, metric.WithAttributes(
				attribute.String("result", result),
				attribute.String("source", source),
			))
		}
		nodeScanJobs.Add(context.Background(), 0, metric.WithAttributes(
			attribute.String("result", result),
		))
	}

	return &JobMetrics{
		scanJobs:     scanJobs,
		nodeScanJobs: nodeScanJobs,
	}, nil
}

// JobFinished reports whether the job reached a terminal state.
// Callers use it to snapshot the state before a terminal status write,
// so a job finished by an earlier writer is not counted again.
func JobFinished(job v1alpha1.ConditionedJob) bool {
	return job.IsComplete() || job.IsFailed()
}

// RecordScanJobFinished counts one finished ScanJob, labelled with the result and the scan source.
// It is a no-op when the job is not in a terminal state, so callers can invoke it
// after every status update of a job that was not terminal before.
func (m *JobMetrics) RecordScanJobFinished(ctx context.Context, scanJob *v1alpha1.ScanJob) {
	if !JobFinished(scanJob) {
		return
	}
	m.scanJobs.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", jobResult(scanJob)),
		attribute.String("source", scanJobSource(scanJob)),
	))
}

// RecordNodeScanJobFinished counts one finished NodeScanJob, labelled with the result.
// It is a no-op when the job is not in a terminal state.
func (m *JobMetrics) RecordNodeScanJobFinished(ctx context.Context, nodeScanJob *v1alpha1.NodeScanJob) {
	if !JobFinished(nodeScanJob) {
		return
	}
	m.nodeScanJobs.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", jobResult(nodeScanJob)),
	))
}

// jobResult maps the terminal state to a bounded result label value.
func jobResult(job v1alpha1.ConditionedJob) string {
	if job.IsFailed() {
		return jobResultFailed
	}
	return jobResultComplete
}

// scanJobSource returns the bounded source label of a ScanJob:
// workload when the job carries the workloadscan label
// (stamped by the runner for jobs created against workloadscan-managed registries), registry otherwise.
func scanJobSource(scanJob *v1alpha1.ScanJob) string {
	if scanJob.GetLabels()[api.LabelWorkloadScanKey] == api.LabelWorkloadScanValue {
		return scanJobSourceWorkload
	}
	return scanJobSourceRegistry
}
