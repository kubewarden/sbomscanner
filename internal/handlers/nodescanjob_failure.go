package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sbombasticv1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

// NodeScanJobFailureHandler handles failures for messages related to node scan jobs.
type NodeScanJobFailureHandler struct {
	k8sClient client.Client
	logger    *slog.Logger
}

// NewNodeScanJobFailureHandler creates a new instance of NodeScanJobFailureHandler.
func NewNodeScanJobFailureHandler(
	k8sClient client.Client,
	logger *slog.Logger,
) *NodeScanJobFailureHandler {
	return &NodeScanJobFailureHandler{
		k8sClient: k8sClient,
		logger:    logger.With("handler", "nodescanjob_failure_handler"),
	}
}

// HandleFailure processes message failures and updates the associated NodeScanJob status.
func (h *NodeScanJobFailureHandler) HandleFailure(ctx context.Context, message messaging.Message, errorMessage string) error {
	nodeBaseMessage := &NodeBaseMessage{}
	if err := json.Unmarshal(message.Data(), nodeBaseMessage); err != nil {
		return fmt.Errorf("failed to unmarshal node base message: %w", err)
	}
	h.logger.DebugContext(ctx, "Handling NodeScanJob failure",
		"nodescanjob", nodeBaseMessage.NodeScanJob.Name,
		"error", errorMessage,
	)

	nodeScanJob := &sbombasticv1alpha1.NodeScanJob{}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name: nodeBaseMessage.NodeScanJob.Name,
		}, nodeScanJob); err != nil {
			return fmt.Errorf("cannot get NodeScanJob %s: %w", nodeBaseMessage.NodeScanJob.Name, err)
		}

		nodeScanJob.MarkFailed(sbombasticv1alpha1.ReasonInternalError, errorMessage)
		return h.k8sClient.Status().Update(ctx, nodeScanJob)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "NodeScanJob not found, skipping updating NodeScanJob status to failed", "nodescanjob", nodeBaseMessage.NodeScanJob.Name)
			return nil
		}
		return fmt.Errorf("failed to update NodeScanJob %s status to failed: %w", nodeScanJob.Name, err)
	}

	h.logger.DebugContext(ctx, "NodeScanJob marked as failed",
		"nodescanjob", nodeScanJob.Name,
		"error_message", errorMessage,
	)
	return nil
}
