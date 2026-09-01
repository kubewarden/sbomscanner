package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// fakeReconciler returns a fixed result/error pair so tests can drive every outcome branch.
type fakeReconciler struct {
	result ctrl.Result
	err    error
}

func (f *fakeReconciler) Reconcile(context.Context, ctrl.Request) (ctrl.Result, error) {
	return f.result, f.err
}

// newTestInstrumentation builds an Instrumentation backed by in-memory SDK providers,
// returning the span recorder used for assertions.
func newTestInstrumentation(t *testing.T) (*Instrumentation, *tracetest.SpanRecorder) {
	t.Helper()

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })

	meterProvider := sdkmetric.NewMeterProvider()
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })

	instrumentation, err := NewInstrumentation(tracerProvider.Tracer("test"), meterProvider.Meter("test"))
	require.NoError(t, err)

	return instrumentation, spanRecorder
}

// newFakeReader returns a fake cached client seeded with the given objects,
// standing in for the informer cache the wrapper reads the traceparent from.
func newFakeReader(t *testing.T, objects ...client.Object) client.Reader {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	return fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// newNoopInstrumentation builds an Instrumentation on no-op providers,
// for tests that exercise instrumented components without asserting on telemetry.
func newNoopInstrumentation() *Instrumentation {
	instrumentation, err := NewInstrumentation(tracenoop.NewTracerProvider().Tracer("test"), metricnoop.NewMeterProvider().Meter("test"))
	if err != nil {
		panic(err)
	}
	return instrumentation
}

func TestInstrumentedReconciler_Success(t *testing.T) {
	instrumentation, spanRecorder := newTestInstrumentation(t)
	reconciler := instrumentReconciler(instrumentation, "ScanJob", "ScanJob", &fakeReconciler{})

	request := ctrl.Request{}
	request.Namespace = "default"
	request.Name = "my-job"

	_, err := reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "ScanJobReconciler.Reconcile", span.Name())
	attrs := attribute.NewSet(span.Attributes()...)
	assert.Equal(t, "ScanJob", attrValue(attrs, "k8s.resource.kind"))
	assert.Equal(t, "default", attrValue(attrs, "k8s.namespace.name"))
	assert.Equal(t, "my-job", attrValue(attrs, "k8s.object.name"))
	assert.Equal(t, "success", attrValue(attrs, "controller.result"))
}

func TestInstrumentedReconciler_Error(t *testing.T) {
	instrumentation, spanRecorder := newTestInstrumentation(t)
	notFound := apierrors.NewNotFound(schema.GroupResource{Group: v1alpha1.GroupVersion.Group, Resource: "scanjobs"}, "my-job")
	reconciler := instrumentReconciler(instrumentation, "ScanJob", "ScanJob", &fakeReconciler{err: notFound})

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{})
	require.Error(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	attrs := attribute.NewSet(spans[0].Attributes()...)
	assert.Equal(t, "error", attrValue(attrs, "controller.result"))
}

func TestInstrumentedReconciler_Requeue(t *testing.T) {
	instrumentation, spanRecorder := newTestInstrumentation(t)
	reconciler := instrumentReconciler(instrumentation, "ScanJob", "ScanJob", &fakeReconciler{result: ctrl.Result{RequeueAfter: time.Minute}})

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{})
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	attrs := attribute.NewSet(spans[0].Attributes()...)
	assert.Equal(t, "requeue", attrValue(attrs, "controller.result"))
}

// TestInstrumentedReconciler_JoinsJobTrace asserts that the reconcile span is parented into the
// trace carried by the object's traceparent annotation, resolved before the span starts.
func TestInstrumentedReconciler_JoinsJobTrace(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder := newTestInstrumentation(t)

	// Simulate the runner: a job trace injected into the object's annotations.
	jobCtx, jobSpan := instrumentation.startJobTrace(context.Background(), "RegistryScanRunner.CreateScanJob")
	annotations := map[string]string{}
	telemetry.InjectAnnotations(jobCtx, annotations)
	jobSpan.End()

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{Name: "my-job", Namespace: "default", Annotations: annotations},
	}
	reconciler := instrumentReconcilerWithTraceparent(instrumentation, "ScanJob", "ScanJob", newFakeReader(t, scanJob), &v1alpha1.ScanJob{}, &fakeReconciler{})

	request := ctrl.Request{}
	request.Namespace = "default"
	request.Name = "my-job"

	_, err := reconciler.Reconcile(context.Background(), request)
	require.NoError(t, err)

	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)
	reconcileSpan := spans[1]
	assert.Equal(t, "ScanJobReconciler.Reconcile", reconcileSpan.Name())
	assert.Equal(t, jobSpan.SpanContext().TraceID(), reconcileSpan.SpanContext().TraceID(),
		"the reconcile span must belong to the job trace")
	assert.Equal(t, jobSpan.SpanContext().SpanID(), reconcileSpan.Parent().SpanID())
}

// TestStartJobTrace asserts that each created job gets a fresh trace,
// linked back to the runner tick span instead of being parented under it.
func TestStartJobTrace(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	instrumentation, spanRecorder := newTestInstrumentation(t)

	tickCtx, tickSpan := instrumentation.tracer.Start(context.Background(), "runner cycle")
	defer tickSpan.End()

	jobCtx, jobSpan := instrumentation.startJobTrace(tickCtx, "RegistryScanRunner.CreateScanJob")
	annotations := map[string]string{}
	telemetry.InjectAnnotations(jobCtx, annotations)
	jobSpan.End()

	require.NotEmpty(t, annotations[telemetry.TraceparentAnnotation])

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "RegistryScanRunner.CreateScanJob", span.Name())
	assert.NotEqual(t, tickSpan.SpanContext().TraceID(), span.SpanContext().TraceID(),
		"each job must start a fresh trace, not join the tick trace")
	require.Len(t, span.Links(), 1)
	assert.Equal(t, tickSpan.SpanContext().SpanID(), span.Links()[0].SpanContext.SpanID())
}

func TestJobStatus(t *testing.T) {
	scanJob := &v1alpha1.ScanJob{}
	assert.Equal(t, "pending", jobStatus(scanJob))

	scanJob.InitializeConditions()
	scanJob.MarkScheduled(v1alpha1.ReasonScanJobScheduled, "scheduled")
	assert.Equal(t, "scheduled", jobStatus(scanJob))

	scanJob.MarkInProgress(v1alpha1.ReasonScanJobImageScanInProgress, "in progress")
	assert.Equal(t, "in_progress", jobStatus(scanJob))

	scanJob.MarkComplete(v1alpha1.ReasonScanJobAllImagesScanned, "complete")
	assert.Equal(t, "complete", jobStatus(scanJob))

	scanJob.MarkFailed(v1alpha1.ReasonScanJobRegistryNotFound, "failed")
	assert.Equal(t, "failed", jobStatus(scanJob))
}

// attrValue returns the string form of the attribute with the given key, or "" when absent.
func attrValue(set attribute.Set, key string) string {
	value, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return value.String()
}
