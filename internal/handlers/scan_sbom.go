package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"

	"go.yaml.in/yaml/v3"
	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	vexrepo "github.com/aquasecurity/trivy/pkg/vex/repo"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	trivyreport "github.com/kubewarden/sbomscanner/internal/handlers/trivyreport"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

const (
	// trivyVEXSubPath is the directory used by trivy to hold VEX repositories.
	trivyVEXSubPath = ".trivy/vex"
	// trivyVEXRepoFile is the file used by trivy to hold VEX repositories.
	trivyVEXRepoFile = "repository.yaml"
)

// ScanSBOMHandler is responsible for handling SBOM scan requests.
type ScanSBOMHandler struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	workDir               string
	trivyDBRepository     string
	trivyJavaDBRepository string
	logger                *slog.Logger
	isNodeMode            bool
}

// NewScanSBOMHandler creates a new instance of ScanSBOMHandler for container images.
func NewScanSBOMHandler(
	k8sClient client.Client,
	scheme *runtime.Scheme,
	workDir string,
	trivyDBRepository string,
	trivyJavaDBRepository string,
	logger *slog.Logger,
) *ScanSBOMHandler {
	return &ScanSBOMHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
		workDir:               workDir,
		trivyDBRepository:     trivyDBRepository,
		trivyJavaDBRepository: trivyJavaDBRepository,
		logger:                logger.With("handler", "scan_sbom_handler"),
		isNodeMode:            false,
	}
}

// NewScanNodeSBOMHandler creates a new instance of ScanSBOMHandler for nodes.
func NewScanNodeSBOMHandler(
	k8sClient client.Client,
	scheme *runtime.Scheme,
	workDir string,
	trivyDBRepository string,
	trivyJavaDBRepository string,
	logger *slog.Logger,
) *ScanSBOMHandler {
	return &ScanSBOMHandler{
		k8sClient:             k8sClient,
		scheme:                scheme,
		workDir:               workDir,
		trivyDBRepository:     trivyDBRepository,
		trivyJavaDBRepository: trivyJavaDBRepository,
		logger:                logger.With("handler", "scan_node_sbom_handler"),
		isNodeMode:            true,
	}
}

// Handle processes the ScanSBOMMessage or ScanNodeSBOMMessage and scans the specified SBOM resource for vulnerabilities.
func (h *ScanSBOMHandler) Handle(ctx context.Context, message messaging.Message) error { //nolint:funlen,gocognit,gocyclo,cyclop // TODO: refactor this function in smaller ones
	var scanJobName, scanJobNamespace, scanJobUID string
	var sbomName, sbomNamespace string
	var rawSPDX []byte

	if h.isNodeMode {
		scanNodeSBOMMessage := &ScanNodeSBOMMessage{}
		if err := json.Unmarshal(message.Data(), scanNodeSBOMMessage); err != nil {
			return fmt.Errorf("failed to unmarshal scan job message: %w", err)
		}
		scanJobName = scanNodeSBOMMessage.NodeScanJob.Name
		scanJobNamespace = scanNodeSBOMMessage.NodeScanJob.Namespace
		scanJobUID = scanNodeSBOMMessage.NodeScanJob.UID
		sbomName = scanNodeSBOMMessage.NodeSBOM.Name
		sbomNamespace = scanNodeSBOMMessage.NodeSBOM.Namespace
	} else {
		scanSBOMMessage := &ScanSBOMMessage{}
		if err := json.Unmarshal(message.Data(), scanSBOMMessage); err != nil {
			return fmt.Errorf("failed to unmarshal scan job message: %w", err)
		}
		scanJobName = scanSBOMMessage.ScanJob.Name
		scanJobNamespace = scanSBOMMessage.ScanJob.Namespace
		scanJobUID = scanSBOMMessage.ScanJob.UID
		sbomName = scanSBOMMessage.SBOM.Name
		sbomNamespace = scanSBOMMessage.SBOM.Namespace
	}

	h.logger.InfoContext(ctx, "SBOM scan requested",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	var isFailed bool
	var registry *v1alpha1.Registry

	if h.isNodeMode {
		scanJob := &v1alpha1.NodeScanJob{}
		err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      scanJobName,
			Namespace: scanJobNamespace,
		}, scanJob)
		if err != nil {
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
		isFailed = scanJob.IsFailed()
	} else {
		scanJob := &v1alpha1.ScanJob{}
		err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      scanJobName,
			Namespace: scanJobNamespace,
		}, scanJob)
		if err != nil {
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
		isFailed = scanJob.IsFailed()

		// Retrieve the registry from the scan job annotations.
		registryData, ok := scanJob.Annotations[v1alpha1.AnnotationScanJobRegistryKey]
		if !ok {
			return fmt.Errorf("scan job %s/%s does not have a registry annotation", scanJobNamespace, scanJobName)
		}
		registry = &v1alpha1.Registry{}
		if err = json.Unmarshal([]byte(registryData), registry); err != nil {
			return fmt.Errorf("cannot unmarshal registry data from scan job %s/%s: %w", scanJobNamespace, scanJobName, err)
		}
	}

	if isFailed {
		h.logger.InfoContext(ctx, "ScanJob is in failed state, stopping SBOM scan", "scanjob", scanJobName, "namespace", scanJobNamespace)
		return nil
	}

	var owner client.Object
	var getImageMetadata func() storagev1alpha1.ImageMetadata
	var getNodeMetadata func() storagev1alpha1.NodeMetadata

	if h.isNodeMode {
		sbom := &storagev1alpha1.NodeSBOM{}
		err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      sbomName,
			Namespace: sbomNamespace,
		}, sbom)
		if err != nil {
			if apierrors.IsNotFound(err) {
				h.logger.ErrorContext(ctx, "SBOM not found, stopping SBOM scan", "sbom", sbomName, "namespace", sbomNamespace)
				return nil
			}
			return fmt.Errorf("failed to get SBOM: %w", err)
		}
		rawSPDX = sbom.SPDX.Raw
		owner = sbom
		getNodeMetadata = sbom.GetNodeMetadata
	} else {
		sbom := &storagev1alpha1.SBOM{}
		err := h.k8sClient.Get(ctx, client.ObjectKey{
			Name:      sbomName,
			Namespace: sbomNamespace,
		}, sbom)
		if err != nil {
			if apierrors.IsNotFound(err) {
				h.logger.ErrorContext(ctx, "SBOM not found, stopping SBOM scan", "sbom", sbomName, "namespace", sbomNamespace)
				return nil
			}
			return fmt.Errorf("failed to get SBOM: %w", err)
		}
		rawSPDX = sbom.SPDX.Raw
		owner = sbom
		getImageMetadata = sbom.GetImageMetadata
	}

	vexHubList := &v1alpha1.VEXHubList{}
	err := h.k8sClient.List(ctx, vexHubList, &client.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list VEXHub: %w", err)
	}

	sbomFile, err := os.CreateTemp(h.workDir, "trivy.sbom.*.json")
	if err != nil {
		return fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			h.logger.Error("failed to close temporary SBOM file", "error", err)
		}

		if err = os.Remove(sbomFile.Name()); err != nil {
			h.logger.Error("failed to remove temporary SBOM file", "error", err)
		}
	}()

	_, err = sbomFile.Write(rawSPDX)
	if err != nil {
		return fmt.Errorf("failed to write SBOM file: %w", err)
	}
	reportFile, err := os.CreateTemp(h.workDir, "trivy.report.*.json")
	if err != nil {
		return fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			h.logger.Error("failed to close temporary report file", "error", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			h.logger.Error("failed to remove temporary repoort file", "error", err)
		}
	}()

	trivyArgs := []string{
		"sbom",
		"--skip-version-check",
		"--disable-telemetry",
		"--cache-dir", h.workDir,
		"--format", "json",
		"--db-repository", h.trivyDBRepository,
		"--java-db-repository", h.trivyJavaDBRepository,
		"--output", reportFile.Name(),
	}
	// Set XDG_DATA_HOME environment variable to /tmp because trivy expects
	// the repository file in that location and there is no way to change it
	// through input flags:
	// https://trivy.dev/v0.64/docs/supply-chain/vex/repo/#default-configuration
	// TODO(alegrey91): fix upstream
	trivyHome, err := os.MkdirTemp("/tmp", "trivy-")
	if err != nil {
		return fmt.Errorf("failed to create temporary trivy home: %w", err)
	}
	err = os.Setenv("XDG_DATA_HOME", trivyHome)
	if err != nil {
		return fmt.Errorf("failed to set XDG_DATA_HOME to %s: %w", trivyHome, err)
	}

	if len(vexHubList.Items) > 0 {
		trivyVEXPath := path.Join(trivyHome, trivyVEXSubPath)
		vexRepoPath := path.Join(trivyVEXPath, trivyVEXRepoFile)
		if err = h.setupVEXHubRepositories(vexHubList, trivyVEXPath, vexRepoPath); err != nil {
			return fmt.Errorf("failed to setup VEX Hub repositories: %w", err)
		}
		// Clean up the trivy home directory after each handler execution to
		// ensure VEX repositories are refreshed on every run.
		defer func() {
			h.logger.Debug("Removing trivy home")
			if err = os.RemoveAll(trivyHome); err != nil {
				h.logger.Error("failed to remove temporary trivy home", "error", err)
			}
		}()

		// We explicitly set the `--vex` option only when needed
		// (VEXHub resources are found). This is because trivy automatically
		// fills the repository file with aquasecurity VEX files, when
		// `--vex` is specificed.
		trivyArgs = append(trivyArgs, "--vex", "repo", "--show-suppressed")
	}

	app := trivyCommands.NewApp()
	// add SBOM file name at the end.
	trivyArgs = append(trivyArgs, sbomFile.Name())
	app.SetArgs(trivyArgs)

	if err = app.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("failed to execute trivy: %w", err)
	}

	h.logger.InfoContext(ctx, "SBOM scanned",
		"sbom", sbomName,
		"namespace", sbomNamespace,
	)

	if err = message.InProgress(); err != nil {
		return fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return fmt.Errorf("failed to read SBOM output: %w", err)
	}

	reportOrig := trivyTypes.Report{}
	err = json.Unmarshal(reportBytes, &reportOrig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal report: %w", err)
	}

	results, err := trivyreport.NewResultsFromTrivyReport(reportOrig)
	if err != nil {
		return fmt.Errorf("failed to convert from trivy results: %w", err)
	}
	summary := storagev1alpha1.NewSummaryFromResults(results)

	if h.isNodeMode {
		nodeVulnerabilityReport := &storagev1alpha1.NodeVulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sbomName,
				Namespace: sbomNamespace,
			},
		}
		if err = controllerutil.SetControllerReference(owner, nodeVulnerabilityReport, h.scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		_, err = controllerutil.CreateOrUpdate(ctx, h.k8sClient, nodeVulnerabilityReport, func() error {
			nodeVulnerabilityReport.Labels = map[string]string{
				v1alpha1.LabelScanJobUIDKey: string(scanJobUID),
				api.LabelManagedByKey:       api.LabelManagedByValue,
				api.LabelPartOfKey:          api.LabelPartOfValue,
			}

			nodeVulnerabilityReport.NodeMetadata = getNodeMetadata()
			nodeVulnerabilityReport.Report = storagev1alpha1.Report{
				Summary: summary,
				Results: results,
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update vulnerability report: %w", err)
		}
	} else {
		vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sbomName,
				Namespace: sbomNamespace,
			},
		}
		if err = controllerutil.SetControllerReference(owner, vulnerabilityReport, h.scheme); err != nil {
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

			vulnerabilityReport.ImageMetadata = getImageMetadata()
			vulnerabilityReport.Report = storagev1alpha1.Report{
				Summary: summary,
				Results: results,
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update vulnerability report: %w", err)
		}
	}

	return nil
}

// setupVEXHubRepositories creates all the necessary files and directories
// to use VEX Hub repositories.
func (h *ScanSBOMHandler) setupVEXHubRepositories(vexHubList *v1alpha1.VEXHubList, trivyVEXPath, vexRepoPath string) error {
	config := vexrepo.Config{}
	var err error
	for _, repo := range vexHubList.Items {
		repo := vexrepo.Repository{
			Name:    repo.Name,
			URL:     repo.Spec.URL,
			Enabled: repo.Spec.Enabled,
		}
		config.Repositories = append(config.Repositories, repo)
	}

	var repositories []byte
	repositories, err = yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal struct: %w", err)
	}

	h.logger.Debug("Creating VEX repository directory", "vexhub", trivyVEXPath)
	err = os.MkdirAll(trivyVEXPath, 0o750)
	if err != nil {
		return fmt.Errorf("failed to create VEX configuration directory: %w", err)
	}

	h.logger.Debug("Creating VEX repository file", "vexhub", vexRepoPath)
	err = os.WriteFile(vexRepoPath, repositories, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create VEX repository file: %w", err)
	}

	return nil
}
