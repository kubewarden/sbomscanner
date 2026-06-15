package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/filters"
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

	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: nodeScanJob.Spec.NodeName}, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Node no longer exists, deleting NodeScanJob", "nodeScanJob", req.NamespacedName, "nodeName", nodeScanJob.Spec.NodeName)
			if delErr := r.Delete(ctx, nodeScanJob); delErr != nil && !errors.IsNotFound(delErr) {
				return ctrl.Result{}, fmt.Errorf("failed to delete NodeScanJob for missing node: %w", delErr)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to check if node %s exists: %w", nodeScanJob.Spec.NodeName, err)
	}

	if !nodeScanJob.IsPending() {
		log.V(1).Info("NodeScanJob is not in pending state, skipping reconciliation", "nodeScanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	nodeScanJob.InitializeConditions()

	var valid bool
	valid, err := r.validateNodeAgainstConfig(ctx, nodeScanJob, &node)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !valid {
		if err := r.Status().Update(ctx, nodeScanJob); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
		}
		return ctrl.Result{}, nil
	}

	reconcileResult, reconcileErr := r.reconcileNodeScanJob(ctx, nodeScanJob)

	if err := r.Status().Update(ctx, nodeScanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
	}

	log.V(1).Info("Successfully reconciled NodeScanJob", "nodeScanJob", req.NamespacedName)
	return reconcileResult, reconcileErr
}

// validateNodeAgainstConfig checks the NodeScanConfiguration exists and
// the node matches it. Returns (true, nil) when the node is valid.
func (r *NodeScanJobReconciler) validateNodeAgainstConfig(ctx context.Context, job *v1alpha1.NodeScanJob, node *corev1.Node) (bool, error) {
	log := logf.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if errors.IsNotFound(err) {
			log.Info("NodeScanConfiguration not found, marking NodeScanJob as failed", "nodeScanJob", job.Name)
			job.MarkFailed(v1alpha1.ReasonNodeScanJobConfigurationMissing, "NodeScanConfiguration not found: node scanning is not configured")
			return false, nil
		}
		return false, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	if config.Spec.NodeSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			return false, fmt.Errorf("failed to parse NodeSelector: %w", err)
		}
		if !selector.Matches(labels.Set(node.Labels)) {
			log.Info("Node does not match NodeScanConfiguration nodeSelector, marking NodeScanJob as failed",
				"nodeScanJob", job.Name, "node", node.Name)
			job.MarkFailed(v1alpha1.ReasonNodeScanJobNotMatching,
				fmt.Sprintf("node %q does not match the NodeScanConfiguration nodeSelector", node.Name))
			return false, nil
		}
	}

	if !filters.IsPlatformAllowed(
		node.Status.NodeInfo.OperatingSystem,
		node.Status.NodeInfo.Architecture,
		"",
		config.Spec.Platforms,
	) {
		log.Info("Node platform not allowed by NodeScanConfiguration, marking NodeScanJob as failed",
			"nodeScanJob", job.Name, "node", node.Name,
			"platform", fmt.Sprintf("%s/%s", node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture))
		job.MarkFailed(v1alpha1.ReasonNodeScanJobNotMatching,
			fmt.Sprintf("node %q platform %s/%s is not allowed by the NodeScanConfiguration",
				node.Name, node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture))
		return false, nil
	}

	return true, nil
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

	nodeScanJob.MarkScheduled(v1alpha1.ReasonScanJobScheduled, "NodeScanJob has been scheduled for processing by the controller")

	return ctrl.Result{}, nil
}

// cleanupOldNodeScanJobs ensures we don't have more than scanJobsHistoryLimit
// for a given node, scoped to controller-managed jobs only.
func (r *NodeScanJobReconciler) cleanupOldNodeScanJobs(ctx context.Context, currentNodeScanJob *v1alpha1.NodeScanJob) error {
	log := logf.FromContext(ctx)

	scanJobList := &v1alpha1.NodeScanJobList{}
	listOpts := []client.ListOption{
		client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: currentNodeScanJob.Spec.NodeName},
	}

	if err := r.List(ctx, scanJobList, listOpts...); err != nil {
		return fmt.Errorf("failed to list NodeScanJobs for node %s: %w", currentNodeScanJob.Spec.NodeName, err)
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
		"nodeName", currentNodeScanJob.Spec.NodeName,
		"scanjobs", scanJobList.Items)

	scanJobsToDelete := len(scanJobList.Items) - scanJobsHistoryLimit
	for _, scanJob := range scanJobList.Items[:scanJobsToDelete] {
		if err := r.Delete(ctx, &scanJob); err != nil {
			return fmt.Errorf("failed to delete old NodeScanJob %s: %w", scanJob.Name, err)
		}
		log.Info("cleaned up old NodeScanJob",
			"name", scanJob.Name,
			"nodeName", scanJob.Spec.NodeName,
			"creationTimestamp", scanJob.CreationTimestamp)
	}

	return nil
}

func (r *NodeScanJobReconciler) mapNodeToNodeScanJobs(ctx context.Context, obj client.Object) []ctrl.Request {
	log := logf.FromContext(ctx)

	var nodeScanJobs v1alpha1.NodeScanJobList
	if err := r.List(ctx, &nodeScanJobs,
		client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: obj.GetName()},
	); err != nil {
		log.Error(err, "Failed to list NodeScanJobs for node", "node", obj.GetName())
		return nil
	}

	requests := make([]ctrl.Request, 0, len(nodeScanJobs.Items))
	for i := range nodeScanJobs.Items {
		requests = append(requests, ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name: nodeScanJobs.Items[i].Name,
			},
		})
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeScanJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NodeScanJob{}).
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.mapNodeToNodeScanJobs),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
		}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed to create NodeScanJob controller: %w", err)
	}

	return nil
}
