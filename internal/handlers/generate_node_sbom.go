package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	corev1 "k8s.io/api/core/v1"
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

// GenerateNodeSBOMHandler is responsible for handling SBOM generation requests.
type GenerateNodeSBOMHandler struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	workDir               string
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
	trivyJavaDBRepository string,
	publisher messaging.Publisher,
	installationNamespace string,
	logger *slog.Logger,
) *GenerateNodeSBOMHandler {
	return &GenerateNodeSBOMHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
		workDir:               workDir,
		trivyJavaDBRepository: trivyJavaDBRepository,
		publisher:             publisher,
		installationNamespace: installationNamespace,
		logger:                logger.With("handler", "generate_node_sbom_handler"),
	}
}

// Handle processes the GenerateNodeSBOMMessage and generates a SBOM resource from the specified image.
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
		Name:      generateNodeSBOMMessage.NodeScanJob.Name,
		Namespace: generateNodeSBOMMessage.NodeScanJob.Namespace,
	}, nodeScanJob)
	if err != nil {
		// Stop processing if the scanjob is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "NodeScanJob not found, stopping node SBOM generation", "nodescanjob", generateNodeSBOMMessage.NodeScanJob.Name, "namespace", generateNodeSBOMMessage.NodeScanJob.Namespace)
			return nil
		}

		return fmt.Errorf("cannot get NodeScanJob %s/%s: %w", generateNodeSBOMMessage.NodeScanJob.Name, generateNodeSBOMMessage.NodeScanJob.Namespace, err)
	}
	if string(nodeScanJob.GetUID()) != generateNodeSBOMMessage.NodeScanJob.UID {
		h.logger.InfoContext(ctx, "NodeScanJob not found, stopping node SBOM generation (UID changed)", "nodescanjob", generateNodeSBOMMessage.NodeScanJob.Name, "namespace", generateNodeSBOMMessage.NodeScanJob.Namespace,
			"uid", generateNodeSBOMMessage.NodeScanJob.UID)
		return nil
	}

	h.logger.DebugContext(ctx, "NodeScanJob found", "nodescanjob", nodeScanJob)

	node := &corev1.Node{}
	err = h.k8sClient.Get(ctx, client.ObjectKey{
		Name: generateNodeSBOMMessage.Node.Name,
	}, node)
	if err != nil {
		// Stop processing if the image is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.InfoContext(ctx, "Image not found, stopping SBOM generation", "image", generateNodeSBOMMessage.Node.Name)
			return nil
		}

		return fmt.Errorf("cannot get node %s: %w", generateNodeSBOMMessage.Node.Name, err)
	}
	h.logger.DebugContext(ctx, "Node found", "node", node)

	if nodeScanJob.IsFailed() {
		h.logger.InfoContext(ctx, "NodeScanJob is in failed state, stopping node SBOM generation", "nodescanjob", nodeScanJob.Name, "namespace", nodeScanJob.Namespace)
		return nil
	}

	nodeSbom, err := h.getOrGenerateNodeSBOM(ctx, node, generateNodeSBOMMessage)
	if err != nil {
		return fmt.Errorf("failed to get or generate node SBOM: %w", err)
	}

	if err = message.InProgress(); err != nil {
		return fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	if err = h.k8sClient.Create(ctx, nodeSbom); err != nil {
		if apierrors.IsAlreadyExists(err) {
			h.logger.InfoContext(ctx, "node SBOM already exists, skipping creation", "nodesbom", generateNodeSBOMMessage.Node.Name)
		} else {
			return fmt.Errorf("failed to create node SBOM: %w", err)
		}
	}

	scanNodeSBOMMessageID := fmt.Sprintf("nodeScanSBOM/%s/%s", nodeScanJob.UID, generateNodeSBOMMessage.Node.Name)
	scanNodeSBOMMessage, err := json.Marshal(&ScanNodeSBOMMessage{
		NodeBaseMessage: NodeBaseMessage{
			NodeScanJob: generateNodeSBOMMessage.NodeScanJob,
		},
		NodeSBOM: ObjectRef{
			Name: generateNodeSBOMMessage.Node.Name,
		},
	})
	if err != nil {
		return fmt.Errorf("cannot marshal scan node SBOM message: %w", err)
	}

	if err = h.publisher.Publish(ctx, ScanNodeSBOMSubject, scanNodeSBOMMessageID, scanNodeSBOMMessage); err != nil {
		return fmt.Errorf("failed to publish scan node SBOM message: %w", err)
	}

	return nil
}

// getOrGenerateNodeSBOM checks if an SBOM with the same machine ID exists and reuses it, or generates a new one.
func (h *GenerateNodeSBOMHandler) getOrGenerateNodeSBOM(ctx context.Context, node *corev1.Node, message *GenerateNodeSBOMMessage) (*storagev1alpha1.NodeSBOM, error) {
	// Check if an SBOM with the same machine ID already exists
	existingSBOM, err := h.findSBOMByMachineID(ctx, node.Status.NodeInfo.MachineID)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check for existing node SBOM: %w", err)
	}

	var spdxBytes []byte
	if existingSBOM != nil {
		h.logger.InfoContext(ctx, "Found existing node SBOM with matching machine ID, reusing content",
			"sbom", existingSBOM.Name,
			"machineID", node.Status.NodeInfo.MachineID,
		)
		spdxBytes = existingSBOM.SPDX.Raw
	} else {
		h.logger.InfoContext(ctx, "No existing node SBOM found, generating new one", "machineID", node.Status.NodeInfo.MachineID)
		spdxBytes, err = h.generateSPDX(ctx, node)
		if err != nil {
			return nil, err
		}
	}

	sbomLabels := map[string]string{
		api.LabelManagedByKey: api.LabelManagedByValue,
		api.LabelPartOfKey:    api.LabelPartOfValue,
	}

	nodeSbom := &storagev1alpha1.NodeSBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      message.Node.Name,
			Namespace: message.Node.Namespace,
			Labels:    sbomLabels,
		},
		NodeMetadata: storagev1alpha1.NodeMetadata{
			MachineID: node.Status.NodeInfo.MachineID,
			Platform:  node.Status.NodeInfo.Architecture,
		},
		SPDX: runtime.RawExtension{Raw: spdxBytes},
	}

	if err := controllerutil.SetControllerReference(node, nodeSbom, h.scheme); err != nil {
		return nil, fmt.Errorf("failed to set owner reference: %w", err)
	}

	return nodeSbom, nil
}

// findSBOMByMachineID searches for an existing SBOM with the given machine ID.
func (h *GenerateNodeSBOMHandler) findSBOMByMachineID(ctx context.Context, machineID string) (*storagev1alpha1.NodeSBOM, error) {
	sbomList := &storagev1alpha1.NodeSBOMList{}
	err := h.k8sClient.List(ctx, sbomList,
		//client.InNamespace(namespace),
		client.MatchingFields{storagev1alpha1.IndexNodeMetadataMachineID: machineID},
		client.Limit(1),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to find SBOM by machine ID: %w", err)
	}

	if len(sbomList.Items) == 0 {
		return nil, apierrors.NewNotFound(storagev1alpha1.Resource("nodesbom"), machineID)
	}

	return &sbomList.Items[0], nil
}

// generateSPDX generates SPDX JSON content for an image using Trivy.
//
//nolint:gocognit // This function can't be easily split into smaller parts.
func (h *GenerateNodeSBOMHandler) generateSPDX(ctx context.Context, node *corev1.Node) ([]byte, error) {
	sbomFile, err := os.CreateTemp(h.workDir, "trivy.sbom.*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			h.logger.Error("failed to close temporary SBOM file", "error", err)
		}
		if err = os.Remove(sbomFile.Name()); err != nil {
			h.logger.Error("failed to remove temporary SBOM file", "error", err)
		}
	}()

	args := []string{
		"filesystem",
		"--skip-version-check",
		"--disable-telemetry",
		"--cache-dir", h.workDir,
		"--format", "spdx-json",
		"--skip-db-update",
		// The Java DB is needed to generate SBOMs for images containing Java components
		// See: https://github.com/aquasecurity/trivy/discussions/9666
		"--java-db-repository", h.trivyJavaDBRepository,
		"--output", sbomFile.Name(),
		"/", // Scan the entire filesystem of the node
	}

	app := trivyCommands.NewApp()
	app.SetArgs(args)

	if err = app.ExecuteContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to execute trivy: %w", err)
	}

	h.logger.DebugContext(ctx, "SPDX generated", "node", node.Name, "namespace", node.Namespace)

	spdxBytes, err := io.ReadAll(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read node SBOM output: %w", err)
	}

	return spdxBytes, nil
}
