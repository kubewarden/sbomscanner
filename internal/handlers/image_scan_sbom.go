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

// ImageScanSBOMHandler handles SBOM scan requests for container images.
type ImageScanSBOMHandler struct {
	scanSBOMBase
}

// NewScanSBOMHandler creates a new instance of ImageScanSBOMHandler for container images.
func NewScanSBOMHandler(
	k8sClient client.Client,
	scheme *runtime.Scheme,
	workDir string,
	trivyDBRepository string,
	trivyJavaDBRepository string,
	logger *slog.Logger,
) *ImageScanSBOMHandler {
	return &ImageScanSBOMHandler{
		scanSBOMBase: scanSBOMBase{
			k8sClient:             k8sClient,
			scheme:                scheme,
			workDir:               workDir,
			trivyDBRepository:     trivyDBRepository,
			trivyJavaDBRepository: trivyJavaDBRepository,
			logger:                logger.With("handler", "scan_sbom_handler"),
		},
	}
}

func (h *ImageScanSBOMHandler) Handle(ctx context.Context, message messaging.Message) error {
	scanSBOMMessage := &ScanSBOMMessage{}
	if err := json.Unmarshal(message.Data(), scanSBOMMessage); err != nil {
		return fmt.Errorf("failed to unmarshal scan job message: %w", err)
	}

	scanJobName := scanSBOMMessage.ScanJob.Name
	scanJobNamespace := scanSBOMMessage.ScanJob.Namespace
	scanJobUID := scanSBOMMessage.ScanJob.UID
	sbomName := scanSBOMMessage.SBOM.Name
	sbomNamespace := scanSBOMMessage.SBOM.Namespace

	h.logger.InfoContext(ctx, "SBOM scan requested",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	scanJob := &v1alpha1.ScanJob{}
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

	registryData, ok := scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]
	if !ok {
		return fmt.Errorf("scan job %s/%s does not have a registry annotation", scanJobNamespace, scanJobName)
	}

	registry := &v1alpha1.Registry{}
	if err := json.Unmarshal([]byte(registryData), registry); err != nil {
		return fmt.Errorf("cannot unmarshal registry data from scan job %s/%s: %w", scanJobNamespace, scanJobName, err)
	}

	sbom := &storagev1alpha1.SBOM{}
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

	vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sbomName,
			Namespace: sbomNamespace,
		},
	}
	if err = controllerutil.SetControllerReference(sbom, vulnerabilityReport, h.scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	_, err = controllerutil.CreateOrUpdate(ctx, h.k8sClient, vulnerabilityReport, func() error {
		vulnerabilityReport.Labels = map[string]string{
			v1alpha1.LabelScanJobUIDKey: string(scanJobUID),
			api.LabelManagedByKey:       api.LabelManagedByValue,
			api.LabelPartOfKey:          api.LabelPartOfValue,
		}
		if registry.Labels[api.LabelWorkloadScanKey] == api.LabelWorkloadScanValue {
			vulnerabilityReport.Labels[api.LabelWorkloadScanKey] = api.LabelWorkloadScanValue
		}

		vulnerabilityReport.ImageMetadata = sbom.GetImageMetadata()
		vulnerabilityReport.Report = storagev1alpha1.Report{
			Summary: summary,
			Results: results,
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update vulnerability report: %w", err)
	}

	return nil
}
