package controller

import (
	"context"
	"fmt"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/internal/filters"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// NodeScanReconciler reconciles a NodeScanConfiguration object by managing
// a DaemonSet that performs filesystem scans on cluster nodes.
type NodeScanReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIReader client.Reader
}

// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations,verbs=get;list;watch
// +kubebuilder:rbac:groups=sbomscanner.kubewarden.io,resources=nodescanconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=storage.sbomscanner.kubewarden.io,resources=nodesboms,verbs=list;watch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch

func (r *NodeScanReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("NodeScanConfiguration not found, cleaning up managed resources")
			if err := r.cleanupAllManagedResources(ctx); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup managed resources: %w", err)
			}
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	// get the list of nodes in the cluster
	nodes := &corev1.NodeList{}
	var listOpts []client.ListOption
	if config.Spec.NodeSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to parse node selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}
	if err := r.Client.List(ctx, nodes, listOpts...); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) > 0 {
		logger.Info("Nodes found matching selector", "count", len(nodes.Items))
	} else {
		logger.Info("No nodes found matching selector")
	}

	activeNodeNames := make(map[string]struct{}, len(nodes.Items))
	for i := range nodes.Items {
		node := &nodes.Items[i]

		if !filters.IsPlatformAllowed(
			node.Status.NodeInfo.OperatingSystem,
			node.Status.NodeInfo.Architecture,
			"",
			config.Spec.Platforms,
		) {
			logger.V(1).Info("Skipping node with disallowed platform",
				"nodeName", node.Name,
				"platform", fmt.Sprintf("%s/%s", node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture),
			)
			continue
		}

		activeNodeNames[node.Name] = struct{}{}
		logger.Info("Processing node", "nodeName", node.Name)

		nodeScanJob := &v1alpha1.NodeScanJob{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("nodescanjob-%s", node.Name),
				Labels: map[string]string{
					api.LabelManagedByKey: api.LabelManagedByValue,
					api.LabelNodeScanKey:  api.LabelNodeScanValue,
				},
			},
			Spec: v1alpha1.NodeScanJobSpec{
				NodeName: node.Name,
			},
		}

		if err := controllerutil.SetControllerReference(node, nodeScanJob, r.Scheme); err != nil {
			logger.Error(err, "Failed to set owner reference on NodeScanJob", "nodeScanJob", nodeScanJob.Name)
			return ctrl.Result{}, fmt.Errorf("failed to set owner reference on NodeScanJob: %w", err)
		}

		if err := r.Client.Create(ctx, nodeScanJob, &client.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				logger.V(1).Info("NodeScanJob already exists", "nodeScanJob", nodeScanJob.Name)
				continue
			}
			logger.Error(err, "Failed to create NodeScanJob", "nodeScanJob", nodeScanJob.Name)
			return ctrl.Result{}, fmt.Errorf("failed to create nodescanjob for node %s: %w", node.Name, err)
		}
	}

	if err := r.cleanupStaleNodeScanJobs(ctx, activeNodeNames); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup stale NodeScanJobs: %w", err)
	}

	if err := r.cleanupStaleNodeSBOMs(ctx, activeNodeNames); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup stale NodeSBOMs: %w", err)
	}

	logger.Info("Successfully reconciled NodeScanConfiguration")

	return ctrl.Result{}, nil
}

func (r *NodeScanReconciler) cleanupStaleNodeScanJobs(ctx context.Context, activeNodeNames map[string]struct{}) error {
	logger := log.FromContext(ctx)

	var nodeScanJobs v1alpha1.NodeScanJobList
	if err := r.List(ctx, &nodeScanJobs,
		client.MatchingLabels{
			api.LabelManagedByKey: api.LabelManagedByValue,
			api.LabelNodeScanKey:  api.LabelNodeScanValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed NodeScanJobs: %w", err)
	}

	for i := range nodeScanJobs.Items {
		job := &nodeScanJobs.Items[i]
		if _, exists := activeNodeNames[job.Spec.NodeName]; !exists {
			logger.Info("Deleting stale NodeScanJob for removed node", "nodeScanJob", job.Name, "nodeName", job.Spec.NodeName)
			if err := r.Delete(ctx, job); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete stale NodeScanJob %s: %w", job.Name, err)
			}
		}
	}

	return nil
}

func (r *NodeScanReconciler) cleanupStaleNodeSBOMs(ctx context.Context, activeNodeNames map[string]struct{}) error {
	logger := log.FromContext(ctx)

	var nodesboms storagev1alpha1.NodeSBOMList
	if err := r.List(ctx, &nodesboms, client.MatchingLabels{
		api.LabelManagedByKey: api.LabelManagedByValue,
	}); err != nil {
		logger.Error(err, "failed to list managed nodesboms")
		return fmt.Errorf("failed to list managed NodeSBOMs: %w", err)
	}

	for i := range nodesboms.Items {
		nodesbom := &nodesboms.Items[i]
		if _, exists := activeNodeNames[nodesbom.NodeMetadata.Name]; !exists {
			logger.Info("Deleting stale NodeSBOM for filtered node",
				"nodesbom", nodesbom.Name,
				"nodeName", nodesbom.NodeMetadata.Name,
				"platform", nodesbom.NodeMetadata.Platform,
			)
			if err := r.Delete(ctx, nodesbom); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to delete stale NodeSBOM %s: %w", nodesbom.Name, err)
			}
		}
	}

	return nil
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
		logger.Info("Deleting managed nodescanjobs", "nodescanjob", nodescanjob.Name)
		if err := r.Delete(ctx, nodescanjob); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete nodescanjob %s: %w", nodescanjob.Name, err)
		}
	}

	var nodesboms storagev1alpha1.NodeSBOMList
	if err := r.List(ctx, &nodesboms,
		client.MatchingLabels{
			api.LabelManagedByKey: api.LabelManagedByValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed nodesboms: %w", err)
	}

	for i := range nodesboms.Items {
		nodesbom := &nodesboms.Items[i]
		logger.Info("Deleting managed nodesboms", "nodesbom", nodesbom.Name)
		if err := r.Delete(ctx, nodesbom); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete nodesbom %s: %w", nodesbom.Name, err)
		}
	}

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
		// Used to GC NodeScanJobs when nodes are deleted,
		// and to trigger new NodeScanJobs when new nodes appear.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(mapNodeScanConfigToSingleton),
		).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create nodescan controller: %w", err)
	}
	return nil
}
