package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/handlers"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

const (
	maxConcurrentReconciles = 10
	scanJobsHistoryLimit    = 10
)

// ScanJobReconciler reconciles a ScanJob object
type ScanJobReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Publisher messaging.Publisher
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=scanjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=scanjobs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=registries,verbs=get;list;watch

// Reconcile reconciles a ScanJob object.
func (r *ScanJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling ScanJob")

	scanJob := &v1alpha1.ScanJob{}
	if err := r.Get(ctx, req.NamespacedName, scanJob); err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("ScanJob not found, skipping reconciliation", "scanJob", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get ScanJob: %w", err)
	}

	if !scanJob.DeletionTimestamp.IsZero() {
		log.V(1).Info("ScanJob is being deleted, skipping reconciliation", "scanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if !scanJob.IsPending() {
		log.V(1).Info("ScanJob is not in pending state, skipping reconciliation", "scanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	scanJob.InitializeConditions()

	reconcileResult, reconcileErr := r.reconcileScanJob(ctx, scanJob)

	if err := r.Status().Update(ctx, scanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update ScanJob status: %w", err)
	}

	return reconcileResult, reconcileErr
}

// reconcileScanJob implements the actual reconciliation logic.
func (r *ScanJobReconciler) reconcileScanJob(ctx context.Context, scanJob *v1alpha1.ScanJob) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if err := r.cleanupOldScanJobs(ctx, scanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup old ScanJobs: %w", err)
	}

	registry := &v1alpha1.Registry{}
	if err := r.Get(ctx, client.ObjectKey{
		Name:      scanJob.Spec.Registry,
		Namespace: scanJob.Namespace,
	}, registry); err != nil {
		if errors.IsNotFound(err) {
			log.Error(err, "Registry not found", "registry", scanJob.Spec.Registry)
			scanJob.MarkFailed(v1alpha1.ReasonRegistryNotFound, fmt.Sprintf("Registry %s not found", scanJob.Spec.Registry))

			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("unable to get Registry %s: %w", scanJob.Spec.Registry, err)
	}

	// Only patch if we haven't already set the registry annotation
	// This avoids triggering multiple reconciles while we're still processing
	if _, hasAnnotation := scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]; !hasAnnotation {
		registryData, err := json.Marshal(registry)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to marshal registry data: %w", err)
		}

		original := scanJob.DeepCopy()

		if err = controllerutil.SetControllerReference(registry, scanJob, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set owner reference on ScanJob: %w", err)
		}
		if scanJob.Annotations == nil {
			scanJob.Annotations = map[string]string{}
		}
		scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey] = string(registryData)

		if err = r.Patch(ctx, scanJob, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update ScanJob with registry data: %w", err)
		}

		log.V(1).Info("Patched ScanJob with registry data", "scanJob", scanJob.Name, "namespace", scanJob.Namespace, "registry", scanJob.Spec.Registry)

		// Patch triggers a new reconcile, so return early
		// The next reconcile will publish the message and update status
		return ctrl.Result{}, nil
	}

	log.V(1).Info("Publishing CreateCatalog message for ScanJob", "scanJob", scanJob.Name, "namespace", scanJob.Namespace, "registry", scanJob.Spec.Registry)
	messageID := fmt.Sprintf("createCatalog/%s", scanJob.GetUID())
	message, err := json.Marshal(&handlers.CreateCatalogMessage{
		BaseMessage: handlers.BaseMessage{
			ScanJob: handlers.ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.GetUID()),
			},
		},
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to marshal CreateCatalog message: %w", err)
	}

	if err := r.Publisher.Publish(ctx, handlers.CreateCatalogSubject, messageID, message); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to publish CreateSBOM message: %w", err)
	}

	scanJob.MarkScheduled(v1alpha1.ReasonScheduled, "ScanJob has been scheduled for processing by the controller")

	return ctrl.Result{}, nil
}

// cleanupOldScanJobs ensures we don't have more than scanJobsHistoryLimit for any registry
func (r *ScanJobReconciler) cleanupOldScanJobs(ctx context.Context, currentScanJob *v1alpha1.ScanJob) error {
	log := logf.FromContext(ctx)

	scanJobList := &v1alpha1.ScanJobList{}
	listOpts := []client.ListOption{
		client.InNamespace(currentScanJob.Namespace),
		client.MatchingFields{v1alpha1.IndexScanJobSpecRegistry: currentScanJob.Spec.Registry},
	}

	if err := r.List(ctx, scanJobList, listOpts...); err != nil {
		return fmt.Errorf("failed to list ScanJobs for registry %s: %w", currentScanJob.Spec.Registry, err)
	}

	if len(scanJobList.Items) <= scanJobsHistoryLimit {
		return nil
	}

	sort.Slice(scanJobList.Items, func(i, j int) bool {
		ti := scanJobList.Items[i].GetCreationTimestampFromAnnotation()
		tj := scanJobList.Items[j].GetCreationTimestampFromAnnotation()

		return ti.Before(tj)
	})

	log.V(1).Info("Sorting ScanJobs by creation timestamp for cleanup2",
		"registry", currentScanJob.Spec.Registry,
		"scanjobs", scanJobList.Items)

	scanJobsToDelete := len(scanJobList.Items) - scanJobsHistoryLimit
	for _, scanJob := range scanJobList.Items[:scanJobsToDelete] {
		if err := r.Delete(ctx, &scanJob); err != nil {
			return fmt.Errorf("failed to delete old ScanJob %s: %w", scanJob.Name, err)
		}
		log.Info("cleaned up old ScanJob",
			"name", scanJob.Name,
			"registry", scanJob.Spec.Registry,
			"creationTimestamp", scanJob.CreationTimestamp)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ScanJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ScanJob{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
		}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create ScanJob controller: %w", err)
	}

	return nil
}
