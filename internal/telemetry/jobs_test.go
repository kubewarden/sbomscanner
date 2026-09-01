package telemetry

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// newTestJobMetrics builds a JobMetrics backed by an in-memory SDK provider,
// returning the metric reader used for assertions.
func newTestJobMetrics(t *testing.T) (*JobMetrics, *sdkmetric.ManualReader) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })

	jobs, err := NewJobMetrics(meterProvider.Meter("test"))
	require.NoError(t, err)

	return jobs, reader
}

// collectCounter returns the data points of the named counter keyed by their attributes, empty when absent.
func collectCounter(t *testing.T, reader *sdkmetric.ManualReader, name string, keys ...string) map[string]int64 {
	t.Helper()

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &resourceMetrics))

	results := map[string]int64{}
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, m := range scopeMetrics.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				parts := make([]string, 0, len(keys))
				for _, attrKey := range keys {
					value, _ := point.Attributes.Value(attribute.Key(attrKey))
					parts = append(parts, value.String())
				}
				results[strings.Join(parts, "/")] += point.Value
			}
		}
	}
	return results
}

// scanJobInStatus returns a ScanJob in the given lifecycle status.
func scanJobInStatus(status string) *v1alpha1.ScanJob {
	scanJob := &v1alpha1.ScanJob{}
	scanJob.InitializeConditions()
	switch status {
	case "in_progress":
		scanJob.MarkInProgress(v1alpha1.ReasonScanJobImageScanInProgress, "in progress")
	case "complete":
		scanJob.MarkComplete(v1alpha1.ReasonScanJobAllImagesScanned, "complete")
	case "failed":
		scanJob.MarkFailed(v1alpha1.ReasonScanJobRegistryNotFound, "failed")
	}
	return scanJob
}

// TestRecordScanJobFinished asserts that the series are pre-created at zero,
// that only terminal jobs are counted, and that the source label follows the workloadscan label.
func TestRecordScanJobFinished(t *testing.T) {
	jobs, reader := newTestJobMetrics(t)

	workloadJob := scanJobInStatus("complete")
	workloadJob.Labels = map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue}

	jobs.RecordScanJobFinished(context.Background(), scanJobInStatus("complete"))
	jobs.RecordScanJobFinished(context.Background(), workloadJob)
	jobs.RecordScanJobFinished(context.Background(), scanJobInStatus("failed"))
	jobs.RecordScanJobFinished(context.Background(), scanJobInStatus("in_progress")) // not terminal, not counted

	results := collectCounter(t, reader, "sbomscanner.scanjobs", "result", "source")
	assert.Equal(t, map[string]int64{
		"complete/registry": 1,
		"complete/workload": 1,
		"failed/registry":   1,
		"failed/workload":   0, // pre-created at zero, never incremented
	}, results)
}

// TestRecordNodeScanJobFinished asserts that the series are pre-created at zero
// and that only terminal jobs are counted.
func TestRecordNodeScanJobFinished(t *testing.T) {
	jobs, reader := newTestJobMetrics(t)

	failedJob := &v1alpha1.NodeScanJob{}
	failedJob.InitializeConditions()
	failedJob.MarkFailed(v1alpha1.ReasonScanJobInternalError, "failed")

	pendingJob := &v1alpha1.NodeScanJob{}
	pendingJob.InitializeConditions()

	jobs.RecordNodeScanJobFinished(context.Background(), failedJob)
	jobs.RecordNodeScanJobFinished(context.Background(), pendingJob) // not terminal, not counted

	results := collectCounter(t, reader, "sbomscanner.nodescanjobs", "result")
	assert.Equal(t, map[string]int64{
		"failed":   1,
		"complete": 0, // pre-created at zero, never incremented
	}, results)
}
