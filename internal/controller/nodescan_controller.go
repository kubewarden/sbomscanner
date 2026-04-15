package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"github.com/kubewarden/sbomscanner/api"

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
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

func (r *NodeScanReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("NodeScanConfiguration not found, cleaning up managed DaemonSet")
			if err := r.cleanupAllManagedResources(ctx); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup managed resources: %w", err)
			}
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	logger.Info("Successfully reconciled NodeScanConfiguration")

	// get the list of nodes in the cluster
	nodes := &corev1.NodeList{}
	err := r.Client.List(ctx, nodes, &client.ListOptions{})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes.Items {
		logger.Info("Node found", "nodeName", node.Name)
		r.Client.Create(ctx, &v1alpha1.NodeScanJob{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("nodescanjob-%s", node.Name),
				Namespace: "default",
				Labels: map[string]string{
					api.LabelManagedByKey: api.LabelManagedByValue,
					api.LabelNodeScanKey:  api.LabelNodeScanValue,
				},
			},
			Spec: v1alpha1.NodeScanJobSpec{
				NodeName: node.Name,
			},
		}, &client.CreateOptions{})
	}

	return ctrl.Result{}, nil
}

// cleanupAllManagedResources deletes all NodeScanJob resources
// managed by the node scan controller across all namespaces.
func (r *NodeScanReconciler) cleanupAllManagedResources(ctx context.Context) error {
	logger := log.FromContext(ctx)

	var nodescanjobs v1alpha1.NodeScanJobList
	if err := r.List(ctx, &nodescanjobs,
		client.MatchingLabels{
			api.LabelManagedByKey: api.LabelManagedByValue,
			api.LabelNodeScanKey:  api.LabelNodeScanValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed nodescanjobs: %w", err)
	}

	for i := range nodescanjobs.Items {
		nodescanjob := &nodescanjobs.Items[i]
		logger.Info("Deleting managed nodescanjobs", "nodescanjob", nodescanjob.Name, "namespace", nodescanjob.Namespace)
		if err := r.Delete(ctx, nodescanjob); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete nodescanjob %s/%s: %w", nodescanjob.Namespace, nodescanjob.Name, err)
		}
	}

	// TODO: remove also NodeSBOM, NodeVulnerabilityReport and
	// NodeScanReport resources when they are implemented.

	//var reports storagev1alpha1.NodeScanReportList
	//if err := r.List(ctx, &reports,
	//	client.MatchingLabels{
	//		api.LabelManagedByKey: api.LabelManagedByValue,
	//	},
	//); err != nil {
	//	return fmt.Errorf("failed to list managed WorkloadScanReports: %w", err)
	//}

	//for i := range reports.Items {
	//	report := &reports.Items[i]
	//	logger.Info("Deleting managed WorkloadScanReport", "report", report.Name, "namespace", report.Namespace)
	//	if err := r.Delete(ctx, report); err != nil && !apierrors.IsNotFound(err) {
	//		return fmt.Errorf("failed to delete WorkloadScanReport %s/%s: %w", report.Namespace, report.Name, err)
	//	}
	//}

	return nil
}


// mapNodeScanConfigToSingleton enqueues reconciliation for the singleton
// NodeScanConfiguration regardless of the incoming event object.
func mapNodeScanConfigToSingleton(_ context.Context, _ client.Object) []ctrl.Request {
	return []ctrl.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: v1alpha1.NodeScanConfigurationName,
			},
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanReconciler) SetupWithManager(manager ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(manager).
		Named("nodescan-controller").
		// Reconcile singleton NodeScanConfiguration when config changes.
		Watches(&v1alpha1.NodeScanConfiguration{},
			handler.EnqueueRequestsFromMapFunc(mapNodeScanConfigToSingleton),
		).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create nodescan controller: %w", err)
	}
	return nil
}
