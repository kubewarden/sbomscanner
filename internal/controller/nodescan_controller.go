package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// NodeScanReconciler reconciles a NodeScanConfiguration object by managing
// a DaemonSet that performs filesystem scans on cluster nodes.
type NodeScanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations,verbs=get;list;watch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete

func (r *NodeScanReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("NodeScanConfiguration not found, cleaning up managed DaemonSet")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	if !config.Spec.Enabled {
		logger.V(1).Info("Node scanning is disabled")
		return ctrl.Result{}, nil
	}

	logger.Info("Successfully reconciled NodeScan")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanReconciler) SetupWithManager(manager ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(manager).
		Named("nodescan-controller").
		// Reconcile all matching namespaces when config changes.
		Watches(&v1alpha1.NodeScanConfiguration{},
			handler.EnqueueRequestsFromMapFunc(mapConfigToNamespaces(manager.GetClient())),
		).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create nodescan controller: %w", err)
	}
	return nil
}
