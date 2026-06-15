package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	corev1 "k8s.io/api/core/v1"
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
	"github.com/kubewarden/sbomscanner/internal/skippatterns"
)

// GenerateNodeSBOMHandler is responsible for handling SBOM generation requests.
type GenerateNodeSBOMHandler struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	workDir               string
	targetDir             string
	trivyJavaDBRepository string
	publisher             messaging.Publisher
	installationNamespace string
	logger                *slog.Logger
}

// NewGenerateNodeSBOMHandler creates a new instance of GenerateNodeSBOMHandler.
func NewGenerateNodeSBOMHandler(
	k8sClient client.Client,
	scheme *runtime.Scheme,
	workDir string,
	targetDir string,
	trivyJavaDBRepository string,
	publisher messaging.Publisher,
	installationNamespace string,
	logger *slog.Logger,
) *GenerateNodeSBOMHandler {
	return &GenerateNodeSBOMHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
		workDir:               workDir,
		targetDir:             targetDir,
		trivyJavaDBRepository: trivyJavaDBRepository,
		publisher:             publisher,
		installationNamespace: installationNamespace,
		logger:                logger.With("handler", "generate_node_sbom_handler"),
	}
}

// Handle processes the GenerateNodeSBOMMessage and generates a SBOM resource from the specified image.
//
//nolint:funlen // This function is responsible for orchestrating multiple steps in the SBOM generation process, making it inherently complex and lengthy.
func (h *GenerateNodeSBOMHandler) Handle(ctx context.Context, message messaging.Message) error {
	generateNodeSBOMMessage := &GenerateNodeSBOMMessage{}
	if err := json.Unmarshal(message.Data(), generateNodeSBOMMessage); err != nil {
		return fmt.Errorf("failed to unmarshal GenerateNodeSBOM message: %w", err)
	}

	h.logger.InfoContext(ctx, "Node SBOM generation requested",
		"node", generateNodeSBOMMessage.Node.Name,
	)

	nodeScanJob := &v1alpha1.NodeScanJob{}
	err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name: generateNodeSBOMMessage.NodeScanJob.Name,
	}, nodeScanJob)
	if err != nil {
		// Stop processing if the scanjob is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "NodeScanJob not found, stopping NodeSBOM generation", "nodescanjob", generateNodeSBOMMessage.NodeScanJob.Name)
			return nil
		}

		return fmt.Errorf("cannot get NodeScanJob %s: %w", generateNodeSBOMMessage.NodeScanJob.Name, err)
	}
	if nodeScanJob.Name != generateNodeSBOMMessage.NodeScanJob.Name {
		h.logger.InfoContext(ctx, "NodeScanJob not found, stopping NodeSBOM generation", "nodescanjob", generateNodeSBOMMessage.NodeScanJob.Name,
			"uid", generateNodeSBOMMessage.NodeScanJob.UID)
		return nil
	}

	node := &corev1.Node{}
	err = h.k8sClient.Get(ctx, client.ObjectKey{
		Name: generateNodeSBOMMessage.Node.Name,
	}, node)
	if err != nil {
		// Stop processing if the node is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "Node not found, stopping NodeSBOM generation", "node", generateNodeSBOMMessage.Node.Name)
			return nil
		}

		return fmt.Errorf("cannot get node %s: %w", generateNodeSBOMMessage.Node.Name, err)
	}
	h.logger.DebugContext(ctx, "Node found", "node", node.Name)

	if nodeScanJob.IsFailed() {
		h.logger.InfoContext(ctx, "NodeScanJob is in failed state, stopping NodeSBOM generation", "nodescanjob", nodeScanJob.Name)
		return nil
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name: generateNodeSBOMMessage.NodeScanJob.Name,
		}, nodeScanJob); err != nil {
			return fmt.Errorf("cannot get NodeScanJob %s: %w", generateNodeSBOMMessage.NodeScanJob.Name, err)
		}

		nodeScanJob.MarkInProgress(v1alpha1.ReasonNodeScanJobInProgress, "Scanning node filesystem and collecting data")
		return h.k8sClient.Status().Update(ctx, nodeScanJob)
	})
	if err != nil {
		return fmt.Errorf("failed to update NodeScanJob status to in progress: %w", err)
	}

	// Get the NodeScanConfiguration to determine where to create the NodeSBOM.
	nodeScanConfiguration := &v1alpha1.NodeScanConfiguration{}
	err = h.k8sClient.Get(ctx, client.ObjectKey{
		Name: v1alpha1.NodeScanConfigurationName,
	}, nodeScanConfiguration)
	if err != nil {
		// Stop processing if the scanjob is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "NodeScanConfiguration not found, stopping NodeSBOM generation", "node name", node.Name)
			return fmt.Errorf("NodeScanConfiguration %s not found: %w", v1alpha1.NodeScanConfigurationName, err)
		}
		return fmt.Errorf("cannot get NodeScanConfiguration: %w", err)
	}

	generated, err := h.generateNodeSBOM(ctx, node, generateNodeSBOMMessage, nodeScanConfiguration)
	if err != nil {
		return fmt.Errorf("failed to generate NodeSBOM: %w", err)
	}

	if err = message.InProgress(); err != nil {
		return fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	nodeSBOM := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name: generated.Name,
		},
	}
	if _, err = controllerutil.CreateOrUpdate(ctx, h.k8sClient, nodeSBOM, func() error {
		nodeSBOM.Labels = generated.Labels
		nodeSBOM.NodeMetadata = generated.NodeMetadata
		nodeSBOM.SPDX = generated.SPDX
		return controllerutil.SetControllerReference(nodeScanConfiguration, nodeSBOM, h.scheme)
	}); err != nil {
		return fmt.Errorf("failed to create or update NodeSBOM: %w", err)
	}

	scanNodeSBOMMessageID := fmt.Sprintf("nodeScanSBOM/%s/%s", nodeScanJob.GetUID(), generateNodeSBOMMessage.Node.Name)
	scanNodeSBOMMessage, err := json.Marshal(&ScanNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: generateNodeSBOMMessage.NodeScanJob,
		},
		NodeSBOM: ObjectRef{
			Name: generateNodeSBOMMessage.Node.Name,
		},
	})
	if err != nil {
		return fmt.Errorf("cannot marshal scan NodeSBOM message: %w", err)
	}

	if err = h.publisher.Publish(ctx, ScanNodeSBOMSubject+"."+nodeScanJob.Spec.NodeName, scanNodeSBOMMessageID, scanNodeSBOMMessage); err != nil {
		return fmt.Errorf("failed to publish scan NodeSBOM message: %w", err)
	}

	return nil
}

// generateNodeSBOM generates a fresh SBOM for the given node.
func (h *GenerateNodeSBOMHandler) generateNodeSBOM(ctx context.Context, node *corev1.Node, message *GenerateNodeSBOMMessage, config *v1alpha1.NodeScanConfiguration) (*storagev1alpha1.NodeSBOM, error) {
	h.logger.InfoContext(ctx, "Generating new NodeSBOM", "node name", node.Name)
	spdxBytes, err := h.generateSPDX(ctx, config.Spec.SkipPatterns)
	if err != nil {
		return nil, err
	}

	sbomLabels := map[string]string{
		api.LabelManagedByKey: api.LabelManagedByValue,
		api.LabelPartOfKey:    api.LabelPartOfValue,
	}

	nodePlatform := fmt.Sprintf("%s/%s", node.Status.NodeInfo.OperatingSystem, node.Status.NodeInfo.Architecture)
	nodeSbom := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:   message.Node.Name,
			Labels: sbomLabels,
		},
		NodeMetadata: storagev1alpha1.NodeMetadata{
			Name:     node.Name,
			Platform: nodePlatform,
		},
		SPDX: runtime.RawExtension{Raw: spdxBytes},
	}

	return nodeSbom, nil
}

// generateSPDX generates SPDX JSON content for an image using Trivy.
func (h *GenerateNodeSBOMHandler) generateSPDX(ctx context.Context, skipPats []string) ([]byte, error) {
	sbomFile, err := os.CreateTemp(h.workDir, "trivy.sbom.*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			h.logger.ErrorContext(ctx, "failed to close temporary SBOM file", "error", err)
		}
		if err = os.Remove(sbomFile.Name()); err != nil {
			h.logger.ErrorContext(ctx, "failed to remove temporary SBOM file", "error", err)
		}
	}()

	args := []string{
		"filesystem",
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--skip-version-check",
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--disable-telemetry",
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--cache-dir", h.workDir,
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--format", "spdx-json",
		"--skip-db-update",
		// The Java DB is needed to generate SBOMs for images containing Java components
		// See: https://github.com/aquasecurity/trivy/discussions/9666
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--java-db-repository", h.trivyJavaDBRepository,
		//nolint:goconst // These are specific Trivy command arguments, not constant values used elsewhere
		"--output", sbomFile.Name(),
	}

	parsed := skippatterns.Parse(skipPats)
	for _, dir := range parsed.SkipDirs {
		args = append(args, "--skip-dirs", path.Join(h.targetDir, dir))
	}
	for _, file := range parsed.SkipFiles {
		args = append(args, "--skip-files", path.Join(h.targetDir, file))
	}

	args = append(args, h.targetDir)

	app := trivyCommands.NewApp()
	app.SetArgs(args)

	h.logger.DebugContext(ctx, "Executing Trivy to generate SPDX SBOM", "args", args)

	if err = app.ExecuteContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to execute trivy: %w", err)
	}

	spdxBytes, err := io.ReadAll(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read NodeSBOM output: %w", err)
	}

	return spdxBytes, nil
}
