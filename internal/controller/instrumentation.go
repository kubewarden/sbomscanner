package controller

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
)

// Bounded result label values.
const (
	resultSuccess = "success"
	resultRequeue = "requeue"
	resultError   = "error"
)

// Instrumentation bundles the tracer and the metric instruments shared by the reconcilers and runners in this package.
// Disabled telemetry is represented by no-op providers.
type Instrumentation struct {
	tracer            trace.Tracer
	registryScanTicks metric.Int64Counter
	nodeScanTicks     metric.Int64Counter
	scanJobs          metric.Int64Counter
	nodeScanJobs      metric.Int64Counter
}

// NewInstrumentation creates a new Instrumentation.
func NewInstrumentation(tracer trace.Tracer, meter metric.Meter) (*Instrumentation, error) {
	registryScanTicks, err := meter.Int64Counter(
		"controller.registry_scan.ticks",
		metric.WithDescription("Number of RegistryScanRunner ticks."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating controller.registry_scan.ticks counter: %w", err)
	}

	nodeScanTicks, err := meter.Int64Counter(
		"controller.node_scan.ticks",
		metric.WithDescription("Number of NodeScanRunner ticks."),
	)
	if err != nil {
		return nil, fmt.Errorf("creating controller.node_scan.ticks counter: %w", err)
	}

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

	return &Instrumentation{
		tracer:            tracer,
		registryScanTicks: registryScanTicks,
		nodeScanTicks:     nodeScanTicks,
		scanJobs:          scanJobs,
		nodeScanJobs:      nodeScanJobs,
	}, nil
}

// recordRegistryScanTick counts one RegistryScanRunner tick with the given result.
func (i *Instrumentation) recordRegistryScanTick(ctx context.Context, result string) {
	i.registryScanTicks.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// recordNodeScanTick counts one NodeScanRunner tick with the given result.
func (i *Instrumentation) recordNodeScanTick(ctx context.Context, result string) {
	i.nodeScanTicks.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// startJobTrace starts a fresh trace for a job being created.
//
//nolint:spancheck // The span is returned to the caller, which is responsible for ending it.
func (i *Instrumentation) startJobTrace(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return i.tracer.Start(ctx, name,
		trace.WithNewRoot(),
		trace.WithLinks(trace.LinkFromContext(ctx)),
		trace.WithAttributes(attrs...),
	)
}

// scanJobTransitions returns an informer event handler counting ScanJobs that reach a terminal state,
// labelled with the scan source (registry or workload).
func (i *Instrumentation) scanJobTransitions() toolscache.ResourceEventHandler {
	return jobTransitions(i.scanJobs, func(job client.Object) []attribute.KeyValue {
		return []attribute.KeyValue{attribute.String("source", scanJobSource(job))}
	})
}

// nodeScanJobTransitions returns an informer event handler counting NodeScanJobs that reach a terminal state.
func (i *Instrumentation) nodeScanJobTransitions() toolscache.ResourceEventHandler {
	return jobTransitions(i.nodeScanJobs, nil)
}

// instrumentedReconciler decorates a reconcile.Reconciler with a span per call,
// parented into the job trace carried by the object's traceparent annotation.
type instrumentedReconciler struct {
	inner           reconcile.Reconciler
	instrumentation *Instrumentation
	reader          client.Reader
	prototype       client.Object
	spanName        string
	kind            string
}

// instrumentReconciler creates a new instrumentedReconciler starting from a reconciler.
// name names the span (e.g. "ScanJobReconciler.Reconcile").
func instrumentReconciler(instrumentation *Instrumentation, name, kind string, inner reconcile.Reconciler) reconcile.Reconciler {
	return &instrumentedReconciler{
		inner:           inner,
		instrumentation: instrumentation,
		spanName:        name + "Reconciler.Reconcile",
		kind:            kind,
	}
}

// instrumentReconcilerWithTraceparent is instrumentReconciler for kinds carrying the traceparent annotation:
// the span parent is resolved from the annotation before the span starts.
// prototype is the prototype of the object watched by the reconciler:
// it must match the watched shape, so the lookup hits the existing informer.
func instrumentReconcilerWithTraceparent(instrumentation *Instrumentation, name, kind string, reader client.Reader, prototype client.Object, inner reconcile.Reconciler) reconcile.Reconciler {
	return &instrumentedReconciler{
		inner:           inner,
		instrumentation: instrumentation,
		reader:          reader,
		prototype:       prototype,
		spanName:        name + "Reconciler.Reconcile",
		kind:            kind,
	}
}

// Reconcile implements reconcile.Reconciler.
func (r *instrumentedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	parentCtx := r.resolveParent(ctx, req)

	ctx, span := r.instrumentation.tracer.Start(parentCtx, r.spanName, trace.WithAttributes(
		attribute.String("k8s.resource.kind", r.kind),
		attribute.String("k8s.namespace.name", req.Namespace),
		attribute.String("k8s.object.name", req.Name),
	))
	defer span.End()

	result, err := r.inner.Reconcile(ctx, req)

	span.SetAttributes(attribute.String("controller.result", reconcileOutcome(result, err)))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	//nolint:wrapcheck // Pass-through decorator: the inner reconciler's error must reach controller-runtime unwrapped.
	return result, err
}

// resolveParent resolves the span parent from the object's traceparent annotation,
// with a cache read of the object before the span starts.
// Without a reader (plain instrumentReconciler), or when the object is deleted or not annotated,
// the parent is ctx unchanged (a standalone span).
func (r *instrumentedReconciler) resolveParent(ctx context.Context, req ctrl.Request) context.Context {
	if r.reader == nil {
		return ctx
	}

	object, ok := r.prototype.DeepCopyObject().(client.Object)
	if !ok {
		return ctx
	}
	if err := r.reader.Get(ctx, req.NamespacedName, object); err != nil {
		return ctx
	}

	parentCtx, _ := telemetry.ExtractAnnotations(ctx, object.GetAnnotations())
	return parentCtx
}

// reconcileOutcome maps a reconcile return pair to a bounded result label: error, requeue, or success.
func reconcileOutcome(result ctrl.Result, err error) string {
	switch {
	case err != nil:
		return resultError
	case !result.IsZero():
		return resultRequeue
	default:
		return resultSuccess
	}
}

// isTerminal reports whether the job reached a final state.
func isTerminal(job v1alpha1.ConditionedJob) bool {
	return job.IsComplete() || job.IsFailed()
}

// scanJobSource returns the bounded source label of a ScanJob:
// workload when the job carries the workloadscan label
// (stamped by the runner for jobs created against workloadscan-managed registries), registry otherwise.
func scanJobSource(job client.Object) string {
	if job.GetLabels()[api.LabelWorkloadScanKey] == api.LabelWorkloadScanValue {
		return "workload"
	}
	return "registry"
}

// jobTransitions returns an informer event handler that increments counter each time a job finishes
// (its status transitions to complete or failed).
// It misses jobs that finish while the controller is not running.
func jobTransitions(counter metric.Int64Counter, extraAttributes func(client.Object) []attribute.KeyValue) toolscache.ResourceEventHandler {
	return toolscache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			oldJob, oldOK := oldObj.(v1alpha1.ConditionedJob)
			newJob, newOK := newObj.(v1alpha1.ConditionedJob)
			if !oldOK || !newOK || isTerminal(oldJob) || !isTerminal(newJob) {
				return
			}

			attrs := []attribute.KeyValue{attribute.String("result", jobStatus(newJob))}
			if newObject, ok := newObj.(client.Object); ok && extraAttributes != nil {
				attrs = append(attrs, extraAttributes(newObject)...)
			}
			counter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
		},
	}
}

// jobStatus derives a bounded status label from the job conditions, for use as a span attribute.
func jobStatus(job v1alpha1.ConditionedJob) string {
	switch {
	case job.IsFailed():
		return "failed"
	case job.IsComplete():
		return "complete"
	case job.IsInProgress():
		return "in_progress"
	case job.IsScheduled():
		return "scheduled"
	default:
		return "pending"
	}
}
