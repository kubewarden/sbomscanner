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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/handlers"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

// NodeScanJobReconciler reconciles a NodeScanJob object
type NodeScanJobReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Publisher messaging.Publisher
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanjobs/status,verbs=get;update;patch

// Reconcile reconciles a NodeScanJob object.
func (r *NodeScanJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling NodeScanJob")

	nodeScanJob := &v1alpha1.NodeScanJob{}
	if err := r.Get(ctx, req.NamespacedName, nodeScanJob); err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("NodeScanJob not found, skipping reconciliation", "nodeScanJob", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get NodeScanJob: %w", err)
	}

	if !nodeScanJob.DeletionTimestamp.IsZero() {
		log.V(1).Info("NodeScanJob is being deleted, skipping reconciliation", "nodeScanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if !nodeScanJob.IsPending() {
		log.V(1).Info("NodeScanJob is not in pending state, skipping reconciliation", "nodeScanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	nodeScanJob.InitializeConditions()

	reconcileResult, reconcileErr := r.reconcileNodeScanJob(ctx, nodeScanJob)

	if err := r.Status().Update(ctx, nodeScanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
	}

	log.V(1).Info("Successfully reconciled NodeScanJob", "nodeScanJob", req.NamespacedName)
	return reconcileResult, reconcileErr
}

// reconcileScanJob implements the actual reconciliation logic.
func (r *NodeScanJobReconciler) reconcileNodeScanJob(ctx context.Context, nodeScanJob *v1alpha1.NodeScanJob) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if err := r.cleanupOldNodeScanJobs(ctx, nodeScanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup old NodeScanJobs: %w", err)
	}

	log.V(1).Info("Publishing GenerateNodeSBOM message for NodeScanJob", "nodescanJob", nodeScanJob.Name)
	messageID := fmt.Sprintf("generateNodeSBOM/%s", nodeScanJob.GetUID())
	message, err := json.Marshal(&handlers.GenerateNodeSBOMMessage{
		NodeBaseMessage: handlers.NodeBaseMessage{
			NodeScanJob: handlers.ObjectRef{
				Name:      nodeScanJob.Name,
				Namespace: nodeScanJob.Namespace,
				UID:       string(nodeScanJob.GetUID()),
			},
		},
		Node: handlers.ObjectRef{
			Name: nodeScanJob.Spec.NodeName,
		},
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to marshal GenerateNodeSBOM message: %w", err)
	}

	if err := r.Publisher.Publish(ctx, handlers.GenerateNodeSBOMSubject+"."+nodeScanJob.Spec.NodeName, messageID, message); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to publish GenerateNodeSBOM message: %w", err)
	}

	nodeScanJob.MarkScheduled(v1alpha1.ReasonScheduled, "NodeScanJob has been scheduled for processing by the controller")

	return ctrl.Result{}, nil
}

// cleanupOldNodeScanJobs ensures we don't have more than scanJobsHistoryLimit
func (r *NodeScanJobReconciler) cleanupOldNodeScanJobs(ctx context.Context, currentNodeScanJob *v1alpha1.NodeScanJob) error {
	log := logf.FromContext(ctx)

	scanJobList := &v1alpha1.NodeScanJobList{}

	if err := r.List(ctx, scanJobList); err != nil {
		return fmt.Errorf("failed to list NodeScanJobs: %w", err)
	}

	if len(scanJobList.Items) <= scanJobsHistoryLimit {
		return nil
	}

	sort.Slice(scanJobList.Items, func(i, j int) bool {
		ti := scanJobList.Items[i].GetCreationTimestampFromAnnotation()
		tj := scanJobList.Items[j].GetCreationTimestampFromAnnotation()

		return ti.Before(tj)
	})

	log.V(1).Info("Sorting NodeScanJobs by creation timestamp for cleanup",
		"scanjobs", scanJobList.Items)

	scanJobsToDelete := len(scanJobList.Items) - scanJobsHistoryLimit
	for _, scanJob := range scanJobList.Items[:scanJobsToDelete] {
		if err := r.Delete(ctx, &scanJob); err != nil {
			return fmt.Errorf("failed to delete old NodeScanJob %s: %w", scanJob.Name, err)
		}
		log.Info("cleaned up old NodeScanJob",
			"name", scanJob.Name,
			"creationTimestamp", scanJob.CreationTimestamp)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NodeScanJob{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
		}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create NodeScanJob controller: %w", err)
	}

	return nil
}
