package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// NodeScanReconciler watches Nodes and cleans up NodeScanJobs and NodeSBOMs
// when a Node is deleted.
type NodeScanReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=nodesboms,verbs=list;watch;delete
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanjobs,verbs=list;delete
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

func (r *NodeScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var node corev1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Node deleted, cleaning up related resources", "node", req.Name)
			if err := r.cleanupNodeResources(ctx, req.Name); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup resources for deleted node %s: %w", req.Name, err)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Node: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *NodeScanReconciler) cleanupNodeResources(ctx context.Context, nodeName string) error {
	if err := r.DeleteAllOf(ctx, &v1alpha1.NodeScanJob{},
		client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: nodeName},
	); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NodeScanJobs for node %s: %w", nodeName, err)
	}

	if err := r.DeleteAllOf(ctx, &storagev1alpha1.NodeSBOM{},
		client.MatchingFields{storagev1alpha1.IndexNodeMetadataName: nodeName},
	); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NodeSBOMs for node %s: %w", nodeName, err)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanReconciler) SetupWithManager(manager ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(manager).
		Named("nodescan-controller").
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []ctrl.Request {
				return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: obj.GetName()}}}
			}),
			builder.WithPredicates(predicate.Funcs{
				// Only trigger reconciliation on Node deletions, ignore creates and updates.
				DeleteFunc:  func(_ event.DeleteEvent) bool { return true },
				CreateFunc:  func(_ event.CreateEvent) bool { return false },
				UpdateFunc:  func(_ event.UpdateEvent) bool { return false },
				GenericFunc: func(_ event.GenericEvent) bool { return false },
			}),
		).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create nodescan controller: %w", err)
	}
	return nil
}
