package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

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

func (h *NodeScanSBOMHandler) Handle(ctx context.Context, message messaging.Message) error {
	scanNodeSBOMMessage := &ScanNodeSBOMMessage{}
	if err := json.Unmarshal(message.Data(), scanNodeSBOMMessage); err != nil {
		return fmt.Errorf("failed to unmarshal scan job message: %w", err)
	}

	scanJobName := scanNodeSBOMMessage.NodeScanJob.Name
	scanJobNamespace := scanNodeSBOMMessage.NodeScanJob.Namespace
	scanJobUID := scanNodeSBOMMessage.NodeScanJob.UID
	sbomName := scanNodeSBOMMessage.NodeSBOM.Name
	sbomNamespace := scanNodeSBOMMessage.NodeSBOM.Namespace

	h.logger.InfoContext(ctx, "SBOM scan requested",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	scanJob := &v1alpha1.NodeScanJob{}
	if err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      scanJobName,
		Namespace: scanJobNamespace,
	}, scanJob); err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.ErrorContext(ctx, "ScanJob not found, stopping SBOM scan", "scanJob", scanJobName, "namespace", scanJobNamespace)
			return nil
		}

		return fmt.Errorf("failed to get ScanJob: %w", err)
	}

	if string(scanJob.GetUID()) != scanJobUID {
		h.logger.InfoContext(ctx, "ScanJob not found, stopping SBOM generation (UID changed)", "scanjob", scanJobName, "namespace", scanJobNamespace,
			"uid", scanJobUID)
		return nil
	}

	if scanJob.IsFailed() {
		h.logger.InfoContext(ctx, "ScanJob is in failed state, stopping SBOM scan", "scanjob", scanJobName, "namespace", scanJobNamespace)
		return nil
	}

	sbom := &storagev1alpha1.NodeSBOM{}
	if err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      sbomName,
		Namespace: sbomNamespace,
	}, sbom); err != nil {
		if apierrors.IsNotFound(err) {
			h.logger.ErrorContext(ctx, "SBOM not found, stopping SBOM scan", "sbom", sbomName, "namespace", sbomNamespace)
			return nil
		}

		return fmt.Errorf("failed to get SBOM: %w", err)
	}

	results, summary, err := h.runTrivyScan(ctx, sbom.SPDX.Raw, message)
	if err != nil {
		return err
	}

	h.logger.InfoContext(ctx, "SBOM scanned",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	nodeVulnerabilityReport := &storagev1alpha1.NodeVulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbomName,
		},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, h.k8sClient, nodeVulnerabilityReport, func() error {
		if err = controllerutil.SetControllerReference(sbom, nodeVulnerabilityReport, h.scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		nodeVulnerabilityReport.Labels = map[string]string{
			v1alpha1.LabelScanJobUIDKey: string(scanJobUID),
			api.LabelManagedByKey:       api.LabelManagedByValue,
			api.LabelPartOfKey:          api.LabelPartOfValue,
		}

		nodeVulnerabilityReport.NodeMetadata = sbom.GetNodeMetadata()
		nodeVulnerabilityReport.Report = storagev1alpha1.Report{
			Summary: summary,
			Results: results,
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update nodevulnerability report: %w", err)
	}
	h.logger.InfoContext(ctx, "Vulnerability report created or updated",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	scanJob.MarkComplete(v1alpha1.ReasonNodeScanned, "Node SBOM scanned successfully")
	if err := h.k8sClient.Status().Update(ctx, scanJob); err != nil {
		return fmt.Errorf("failed to update NodeScanJob status: %w", err)
	}
	h.logger.InfoContext(ctx, "SBOM scanned",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	return nil
}
