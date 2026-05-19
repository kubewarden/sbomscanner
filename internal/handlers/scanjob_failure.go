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

// ScanJobFailureHandler handles failures for messages related to scan jobs.
type ScanJobFailureHandler struct {
	k8sClient client.Client
	logger    *slog.Logger
}

// NewScanJobFailureHandler creates a new instance of ScanJobFailureHandler.
func NewScanJobFailureHandler(
	k8sClient client.Client,
	logger *slog.Logger,
) *ScanJobFailureHandler {
	return &ScanJobFailureHandler{
		k8sClient: k8sClient,
		logger:    logger.With("handler", "scanjob_failure_handler"),
	}
}

// HandleFailure processes message failures and updates the associated ScanJob status.
func (h *ScanJobFailureHandler) HandleFailure(ctx context.Context, message messaging.Message, errorMessage string) error {
	baseMessage := &BaseMessage{}
	if err := json.Unmarshal(message.Data(), baseMessage); err != nil {
		return fmt.Errorf("failed to unmarshal base message: %w", err)
	}
	h.logger.DebugContext(ctx, "Handling ScanJob failure",
		"scanjob", baseMessage.ScanJob.Name,
		"namespace", baseMessage.ScanJob.Namespace,
		"error", errorMessage,
	)

	scanJob := &sbombasticv1alpha1.ScanJob{}

	// It is possible that the controller is slow to set the status condition "Scheduled" to true,
	// so we might encounter conflicts when setting the status conditions.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      baseMessage.ScanJob.Name,
			Namespace: baseMessage.ScanJob.Namespace,
		}, scanJob); err != nil {
			return fmt.Errorf("cannot get scanjob %s/%s: %w", baseMessage.ScanJob.Namespace, baseMessage.ScanJob.Name, err)
		}

		scanJob.MarkFailed(sbombasticv1alpha1.ReasonScanJobInternalError, errorMessage)
		return h.k8sClient.Status().Update(ctx, scanJob)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "ScanJob not found, skipping updating ScanJob status to failed", "scanjob", baseMessage.ScanJob.Name, "namespace", baseMessage.ScanJob.Namespace)
			return nil
		}
		return fmt.Errorf("failed to update ScanJob %s/%s status to failed: %w", scanJob.Namespace, scanJob.Name, err)
	}

	h.logger.DebugContext(ctx, "ScanJob marked as failed",
		"scanjob", scanJob.Name,
		"namespace", scanJob.Namespace,
		"error_message", errorMessage,
	)
	return nil
}
