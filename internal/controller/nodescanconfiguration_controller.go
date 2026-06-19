package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// NodeScanConfigurationReconciler watches the singleton NodeScanConfiguration
// and cleans up every NodeScanJob and NodeSBOM across the cluster when the
// configuration is missing or has scanning disabled.
type NodeScanConfigurationReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations,verbs=get;list;watch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanjobs,verbs=list;delete;deletecollection
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=nodesboms,verbs=list;watch;delete;deletecollection

func (r *NodeScanConfigurationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, req.NamespacedName, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("NodeScanConfiguration not found, cleaning up all node scan resources")
			if err := r.cleanupAllNodeResources(ctx); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup all node scan resources: %w", err)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	if !config.Spec.Enabled {
		logger.Info("NodeScanConfiguration disabled, cleaning up all node scan resources")
		if err := r.cleanupAllNodeResources(ctx); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to cleanup all node scan resources: %w", err)
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// cleanupAllNodeResources deletes every NodeScanJob and NodeSBOM across the cluster.
// Both resources are cluster-scoped, so an unscoped DeleteAllOf removes all instances.
func (r *NodeScanConfigurationReconciler) cleanupAllNodeResources(ctx context.Context) error {
	if err := r.DeleteAllOf(ctx, &v1alpha1.NodeScanJob{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete all NodeScanJobs: %w", err)
	}

	if err := r.DeleteAllOf(ctx, &storagev1alpha1.NodeSBOM{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete all NodeSBOMs: %w", err)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanConfigurationReconciler) SetupWithManager(manager ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(manager).
		Named("nodescanconfiguration-controller").
		For(&v1alpha1.NodeScanConfiguration{}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create nodescanconfiguration controller: %w", err)
	}
	return nil
}
