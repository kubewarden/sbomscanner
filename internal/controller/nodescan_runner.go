package controller

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/filters"
)

const nodeScanRunnerPeriod = 10 * time.Second

// NodeScanRunner handles periodic scanning of nodes based on the NodeScanConfiguration.
type NodeScanRunner struct {
	client.Client
}

func (r *NodeScanRunner) Start(ctx context.Context) error {
	log := log.FromContext(ctx)
	log.Info("Starting node scan runner")

	ticker := time.NewTicker(nodeScanRunnerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping node scan runner")

			return nil
		case <-ticker.C:
			if err := r.scanNodes(ctx); err != nil {
				log.Error(err, "Failed to scan nodes")
			}
		}
	}
}

func (r *NodeScanRunner) scanNodes(ctx context.Context) error {
	log := log.FromContext(ctx)

	var config v1alpha1.NodeScanConfiguration
	if err := r.Get(ctx, types.NamespacedName{Name: v1alpha1.NodeScanConfigurationName}, &config); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("NodeScanConfiguration not found, skipping")
			return nil
		}

		return fmt.Errorf("failed to get NodeScanConfiguration: %w", err)
	}

	nodes, err := r.getMatchingNodes(ctx, &config)
	if err != nil {
		return fmt.Errorf("failed to list matching nodes: %w", err)
	}

	log.V(1).Info("Checking nodes for scanning", "count", len(nodes))

	for i := range nodes {
		if err := r.checkNodeForScan(ctx, &config, &nodes[i]); err != nil {
			log.Error(err, "Failed to check node for scan", "node", nodes[i].Name)

			continue
		}
	}

	return nil
}

func (r *NodeScanRunner) getMatchingNodes(ctx context.Context, config *v1alpha1.NodeScanConfiguration) ([]corev1.Node, error) {
	var nodeList corev1.NodeList

	listOpts := []client.ListOption{}

	if config.Spec.NodeSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node selector: %w", err)
		}

		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}

	if err := r.List(ctx, &nodeList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	return nodeList.Items, nil
}

func (r *NodeScanRunner) checkNodeForScan(ctx context.Context, config *v1alpha1.NodeScanConfiguration, node *corev1.Node) error {
	log := log.FromContext(ctx)

	if !filters.IsPlatformAllowed(
		node.Status.NodeInfo.OperatingSystem,
		node.Status.NodeInfo.Architecture,
		"",
		config.Spec.Platforms,
	) {
		log.V(1).Info("Skipping node with disallowed platform",
			"node", node.Name,
			"platform", fmt.Sprintf("%s/%s", node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture),
		)
		return nil
	}

	lastScanJob, err := r.getLastNodeScanJob(ctx, node.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get last node scan job for node %s: %w", node.Name, err)
	}

	if lastScanJob != nil && !lastScanJob.IsComplete() && !lastScanJob.IsFailed() {
		log.V(1).Info("Node has a running NodeScanJob, skipping", "node", node.Name, "nodeScanJob", lastScanJob.Name)

		return nil
	}

	if !r.shouldCreateNodeScanJob(ctx, config, node.Name, lastScanJob) {
		return nil
	}

	if err := r.createNodeScanJob(ctx, node.Name); err != nil {
		return fmt.Errorf("failed to create node scan job for node %s: %w", node.Name, err)
	}

	log.Info("Created node scan job for node", "node", node.Name)

	return nil
}

func (r *NodeScanRunner) shouldCreateNodeScanJob(ctx context.Context, config *v1alpha1.NodeScanConfiguration, nodeName string, lastScanJob *v1alpha1.NodeScanJob) bool {
	log := log.FromContext(ctx)

	if config.Spec.ScanInterval == nil || config.Spec.ScanInterval.Duration == 0 {
		if lastScanJob != nil {
			log.V(1).Info("Skipping node with disabled scan interval", "node", nodeName)
		}

		return false
	}

	if lastScanJob == nil {
		return true
	}

	if lastScanJob.Status.CompletionTime != nil {
		timeSinceLastScan := time.Since(lastScanJob.Status.CompletionTime.Time)
		if timeSinceLastScan < config.Spec.ScanInterval.Duration {
			log.V(1).Info("Node doesn't need scanning yet", "node", nodeName, "timeSinceLastScan", timeSinceLastScan)

			return false
		}
	}

	return true
}

func (r *NodeScanRunner) getLastNodeScanJob(ctx context.Context, nodeName string) (*v1alpha1.NodeScanJob, error) {
	var nodeScanJobs v1alpha1.NodeScanJobList

	listOpts := []client.ListOption{
		client.MatchingFields{v1alpha1.IndexNodeScanJobSpecNodeName: nodeName},
	}
	if err := r.List(ctx, &nodeScanJobs, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list node scan jobs: %w", err)
	}

	if len(nodeScanJobs.Items) == 0 {
		return nil, apierrors.NewNotFound(
			v1alpha1.GroupVersion.WithResource("nodescanjobs").GroupResource(),
			fmt.Sprintf("for node %s", nodeName),
		)
	}

	sort.Slice(nodeScanJobs.Items, func(i, j int) bool {
		return nodeScanJobs.Items[i].CreationTimestamp.After(nodeScanJobs.Items[j].CreationTimestamp.Time)
	})

	return &nodeScanJobs.Items[0], nil
}

func (r *NodeScanRunner) createNodeScanJob(ctx context.Context, nodeName string) error {
	nodeScanJob := &v1alpha1.NodeScanJob{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("node-%s-", nodeName),
			Annotations: map[string]string{
				v1alpha1.AnnotationNodeScanJobTriggerKey: "runner",
			},
			Labels: map[string]string{
				api.LabelManagedByKey: api.LabelManagedByValue,
				api.LabelNodeScanKey:  api.LabelNodeScanValue,
			},
		},
		Spec: v1alpha1.NodeScanJobSpec{
			NodeName: nodeName,
		},
	}

	if err := r.Create(ctx, nodeScanJob); err != nil {
		return fmt.Errorf("failed to create NodeScanJob: %w", err)
	}

	return nil
}

func (r *NodeScanRunner) NeedLeaderElection() bool {
	return true
}

func (r *NodeScanRunner) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed to create NodeScanRunner: %w", err)
	}

	return nil
}
