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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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

	if !nodeScanJob.IsPending() {
		log.V(1).Info("NodeScanJob is not in pending state, skipping reconciliation", "nodeScanJob", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	nodeScanJob.InitializeConditions()

	config := &v1alpha1.NodeScanConfiguration{}
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, config); err != nil {
		if errors.IsNotFound(err) {
			log.Info("NodeScanConfiguration not found, marking NodeScanJob as failed", "nodeScanJob", nodeScanJob.Name)
			nodeScanJob.MarkFailed(v1alpha1.ReasonNodeScanJobConfigurationMissing, "NodeScanConfiguration not found: node scanning is not configured")
			if err := r.Status().Update(ctx, nodeScanJob); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	valid, err := r.validateNodeAgainstConfig(ctx, nodeScanJob, config)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !valid {
		if err := r.Status().Update(ctx, nodeScanJob); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
		}
		return ctrl.Result{}, nil
	}

	reconcileResult, reconcileErr := r.reconcileNodeScanJob(ctx, nodeScanJob, config)

	if err := r.Status().Update(ctx, nodeScanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update NodeScanJob status: %w", err)
	}

	log.V(1).Info("Successfully reconciled NodeScanJob", "nodeScanJob", req.NamespacedName)
	return reconcileResult, reconcileErr
}

// validateNodeAgainstConfig checks that the node referenced by the job exists
// and matches the provided NodeScanConfiguration. Returns true when the node
// is valid.
func (r *NodeScanJobReconciler) validateNodeAgainstConfig(ctx context.Context, job *v1alpha1.NodeScanJob, config *v1alpha1.NodeScanConfiguration) (bool, error) {
	log := logf.FromContext(ctx)

	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: job.Spec.NodeName}, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Node not found, marking NodeScanJob as failed",
				"nodeScanJob", job.Name, "nodeName", job.Spec.NodeName)
			job.MarkFailed(v1alpha1.ReasonNodeScanJobNodeNotFound,
				fmt.Sprintf("Node %s not found", job.Spec.NodeName))
			return false, nil
		}
		return false, fmt.Errorf("failed to check if node %s exists: %w", job.Spec.NodeName, err)
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
func (r *NodeScanJobReconciler) reconcileNodeScanJob(ctx context.Context, nodeScanJob *v1alpha1.NodeScanJob, config *v1alpha1.NodeScanConfiguration) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if err := r.cleanupOldNodeScanJobs(ctx, nodeScanJob); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup old NodeScanJobs: %w", err)
	}

	// Only patch if we haven't already set the NodeScanConfiguration annotation
	// This avoids triggering multiple reconciles while we're still processing
	if _, hasAnnotation := nodeScanJob.Annotations[v1alpha1.AnnotationNodeScanJobNodeScanConfigurationKey]; !hasAnnotation {
		configData, err := json.Marshal(config)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to marshal NodeScanConfiguration data: %w", err)
		}
		original := nodeScanJob.DeepCopy()
		if err = controllerutil.SetControllerReference(config, nodeScanJob, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set owner reference on NodeScanJob: %w", err)
		}
		if nodeScanJob.Annotations == nil {
			nodeScanJob.Annotations = map[string]string{}
		}
		nodeScanJob.Annotations[v1alpha1.AnnotationNodeScanJobNodeScanConfigurationKey] = string(configData)
		if err = r.Patch(ctx, nodeScanJob, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to patch NodeScanJob with NodeScanConfiguration snapshot: %w", err)
		}
		log.V(1).Info("Patched NodeScanJob with NodeScanConfiguration snapshot", "nodeScanJob", nodeScanJob.Name)
		// Patch triggers a new reconcile, so return early
		// The next reconcile will publish the message and update status
		return ctrl.Result{}, nil
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
