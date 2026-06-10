package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

// NodeScanSBOMHandler handles SBOM scan requests for nodes.
type NodeScanSBOMHandler struct {
	scanSBOMBase
}

// NewScanNodeSBOMHandler creates a new instance of NodeScanSBOMHandler for nodes.
func NewScanNodeSBOMHandler(
	k8sClient client.Client,
	scheme *runtime.Scheme,
	workDir string,
	trivyDBRepository string,
	trivyJavaDBRepository string,
	logger *slog.Logger,
) *NodeScanSBOMHandler {
	return &NodeScanSBOMHandler{
		scanSBOMBase: scanSBOMBase{
			k8sClient:             k8sClient,
			scheme:                scheme,
			workDir:               workDir,
			trivyDBRepository:     trivyDBRepository,
			trivyJavaDBRepository: trivyJavaDBRepository,
			logger:                logger.With("handler", "scan_node_sbom_handler"),
		},
	}
}

//nolint:funlen
func (h *NodeScanSBOMHandler) Handle(ctx context.Context, message messaging.Message) error {
	scanNodeSBOMMessage := &ScanNodeSBOMMessage{}
	if err := json.Unmarshal(message.Data(), scanNodeSBOMMessage); err != nil {
		return fmt.Errorf("failed to unmarshal scan job message: %w", err)
	}

	nodeScanJobName := scanNodeSBOMMessage.NodeScanJob.Name
	nodeScanJobNamespace := scanNodeSBOMMessage.NodeScanJob.Namespace
	nodeScanJobUID := scanNodeSBOMMessage.NodeScanJob.UID
	nodeSBOMName := scanNodeSBOMMessage.NodeSBOM.Name
	nodeSBOMNamespace := scanNodeSBOMMessage.NodeSBOM.Namespace

	h.logger.InfoContext(ctx, "NodeSBOM scan requested",
		"nodesbom", nodeSBOMName,
		"namespace", nodeSBOMNamespace,
	)

	scanJob := &v1alpha1.NodeScanJob{}
	if err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      nodeScanJobName,
		Namespace: nodeScanJobNamespace,
	}, scanJob); err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.ErrorContext(ctx, "NodeScanJob not found, stopping SBOM scan", "scanJob", nodeScanJobName, "namespace", nodeScanJobNamespace)
			return nil
		}

		return fmt.Errorf("failed to get ScanJob: %w", err)
	}

	if string(scanJob.GetUID()) != nodeScanJobUID {
		h.logger.InfoContext(ctx, "NodeScanJob not found, stopping SBOM generation (UID changed)", "scanjob", nodeScanJobName, "namespace", nodeScanJobNamespace,
			"uid", nodeScanJobUID)
		return nil
	}

	if scanJob.IsFailed() {
		h.logger.InfoContext(ctx, "NodeScanJob is in failed state, stopping SBOM scan", "scanjob", nodeScanJobName, "namespace", nodeScanJobNamespace)
		return nil
	}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      nodeScanJobName,
			Namespace: nodeScanJobNamespace,
		}, scanJob); err != nil {
			return fmt.Errorf("failed to get NodeScanJob: %w", err)
		}

		scanJob.MarkInProgress(v1alpha1.ReasonNodeScanJobSBOMGenerationInProgress, "NodeSBOM vulnerability scan in progress")
		return h.k8sClient.Status().Update(ctx, scanJob)
	})
	if err != nil {
		return fmt.Errorf("failed to update NodeScanJob status to SBOM generation in progress: %w", err)
	}

	sbom := &storagev1alpha1.NodeSBOM{}
	if err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      nodeSBOMName,
		Namespace: nodeSBOMNamespace,
	}, sbom); err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.ErrorContext(ctx, "SBOM not found, stopping SBOM scan", "sbom", nodeSBOMName, "namespace", nodeSBOMNamespace)
			return nil
		}

		return fmt.Errorf("failed to get SBOM: %w", err)
	}

	results, summary, err := h.runTrivyScan(ctx, sbom.SPDX.Raw, message)
	if err != nil {
		return err
	}

	h.logger.InfoContext(ctx, "NodeSBOM scanned",
		"nodesbom", nodeSBOMName,
		"namespace", nodeSBOMNamespace,
	)

	nodeVulnerabilityReport := &storagev1alpha1.NodeVulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeSBOMName,
		},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, h.k8sClient, nodeVulnerabilityReport, func() error {
		if err = controllerutil.SetControllerReference(sbom, nodeVulnerabilityReport, h.scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		nodeVulnerabilityReport.Labels = map[string]string{
			v1alpha1.LabelNodeScanJobUIDKey: nodeScanJobUID,
			api.LabelManagedByKey:           api.LabelManagedByValue,
			api.LabelPartOfKey:              api.LabelPartOfValue,
		}

		nodeVulnerabilityReport.NodeMetadata = sbom.GetNodeMetadata()
		nodeVulnerabilityReport.Report = storagev1alpha1.Report{
			Summary: summary,
			Results: results,
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update nodevulnerabilityreport: %w", err)
	}
	h.logger.InfoContext(ctx, "NodeVulnerabilityReport created or updated",
		"nodesbom", nodeSBOMName,
		"namespace", nodeSBOMNamespace,
	)

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      nodeScanJobName,
			Namespace: nodeScanJobNamespace,
		}, scanJob); err != nil {
			return fmt.Errorf("failed to get ScanJob: %w", err)
		}

		scanJob.MarkComplete(v1alpha1.ReasonNodeScanJobComplete, "NodeSBOM scanned successfully")
		return h.k8sClient.Status().Update(ctx, scanJob)
	})
	if err != nil {
		return fmt.Errorf("failed to update NodeScanJob status: %w", err)
	}
	h.logger.InfoContext(ctx, "NodeSBOM scanned",
		"nodesbom", nodeSBOMName,
		"namespace", nodeSBOMNamespace,
	)

	return nil
}
