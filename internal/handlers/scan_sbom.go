package handlers

import (
	"bytes"
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
	"k8s.io/client-go/util/retry"

	"github.com/aquasecurity/trivy/pkg/version"
	vexrepo "github.com/aquasecurity/trivy/pkg/vex/repo"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	vulnReport "github.com/kubewarden/sbomscanner/internal/handlers/vulnerabilityreport"
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
}

// NewScanSBOMHandler creates a new instance of ScanSBOMHandler.
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
	}
}

// Handle processes the ScanSBOMMessage and scans the specified SBOM resource for vulnerabilities.
func (h *ScanSBOMHandler) Handle(ctx context.Context, message messaging.Message) error { //nolint:funlen,gocognit
	scanSBOMMessage := &ScanSBOMMessage{}
	if err := json.Unmarshal(message.Data(), scanSBOMMessage); err != nil {
		return fmt.Errorf("failed to unmarshal scan job message: %w", err)
	}

	h.logger.InfoContext(ctx, "SBOM scan requested",
		"sbom", scanSBOMMessage.SBOM.Name,
		"namespace", scanSBOMMessage.SBOM.Namespace,
	)

	scanJob := &v1alpha1.ScanJob{}
	err := h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      scanSBOMMessage.ScanJob.Name,
		Namespace: scanSBOMMessage.ScanJob.Namespace,
	}, scanJob)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Stop processing if the scanjob is not found, since it might have been deleted.
			h.logger.ErrorContext(ctx, "ScanJob not found, stopping SBOM scan", "scanJob", scanSBOMMessage.ScanJob.Name, "namespace", scanSBOMMessage.ScanJob.Namespace)
			return nil
		}
		return fmt.Errorf("failed to get ScanJob: %w", err)
	}
	if string(scanJob.GetUID()) != scanSBOMMessage.ScanJob.UID {
		h.logger.InfoContext(ctx, "ScanJob not found, stopping SBOM generation (UID changed)", "scanjob", scanSBOMMessage.ScanJob.Name, "namespace", scanSBOMMessage.ScanJob.Namespace,
			"uid", scanSBOMMessage.ScanJob.UID)
		return nil
	}

	h.logger.DebugContext(ctx, "ScanJob found", "scanjob", scanJob)

	if scanJob.IsFailed() {
		h.logger.InfoContext(ctx, "ScanJob is in failed state, stopping SBOM scan", "scanjob", scanJob.Name, "namespace", scanJob.Namespace)
		return nil
	}

	sbom := &storagev1alpha1.SBOM{}
	err = h.k8sClient.Get(ctx, client.ObjectKey{
		Name:      scanSBOMMessage.SBOM.Name,
		Namespace: scanSBOMMessage.SBOM.Namespace,
	}, sbom)
	if err != nil {
		// Stop processing if the SBOM is not found, since it might have been deleted.
		if apierrors.IsNotFound(err) {
			h.logger.ErrorContext(ctx, "SBOM not found, stopping SBOM scan", "sbom", scanSBOMMessage.SBOM.Name, "namespace", scanSBOMMessage.SBOM.Namespace)
			return nil
		}
		return fmt.Errorf("failed to get SBOM: %w", err)
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

	// update trivy databases
	if err = h.updateTrivyVulnerabilityDB(ctx, h.trivyDBRepository); err != nil {
		return fmt.Errorf("could not update trivy-db: %w", err)
	}
	//if err = h.updateTrivyJavaDB(ctx, h.trivyJavaDBRepository); err != nil {
	//	return fmt.Errorf("could not update trivy-java-db: %w", err)
	//}

	trivyDBVersions, err := h.getTrivyDBVersions(ctx)
	if err != nil {
		return fmt.Errorf("could not get trivy DB versions: %w", err)
	}

	var report *storagev1alpha1.Report
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sbom.Name,
				Namespace: sbom.Namespace,
			},
		}

		workerVulnDBVersion := metav1.Time{Time: trivyDBVersions.VulnerabilityDB.UpdatedAt}
		workerJavaDBVersion := metav1.Time{Time: trivyDBVersions.JavaDB.UpdatedAt}

		_, err := controllerutil.CreateOrUpdate(ctx, h.k8sClient, vulnerabilityReport, func() error {
			// check if this is an update and we should skip based on DB versions
			if h.shouldSkipTrivyScan(vulnerabilityReport, workerVulnDBVersion, workerJavaDBVersion) {
				foundVulnDBVersion := vulnerabilityReport.ScannerDBVersion[storagev1alpha1.ScannerTrivyDB]
				foundJavaDBVersion := vulnerabilityReport.ScannerDBVersion[storagev1alpha1.ScannerTrivyJavaDB]
				h.logger.Info("skipping scan: found report uses newer or same DB version(s)",
					"scanner", storagev1alpha1.ScannerTrivyDB,
					"found VulnerabilityDB", foundVulnDBVersion, "worker VulnerabilityDB", workerVulnDBVersion,
					"found JavaDB", foundJavaDBVersion, "worker JavaDB", workerJavaDBVersion)
				return nil
			}

			if report == nil {
				reportOrig, err := h.scanSBOM(ctx, sbom, trivyHome)
				if err != nil {
					return fmt.Errorf("failed to scan SBOM: %w", err)
				}

				h.logger.InfoContext(ctx, "SBOM scanned",
					"sbom", scanSBOMMessage.SBOM.Name,
					"namespace", scanSBOMMessage.SBOM.Namespace,
				)

				if err = message.InProgress(); err != nil {
					return fmt.Errorf("failed to ack message as in progress: %w", err)
				}

				results, err := vulnReport.NewFromTrivyResults(reportOrig)
				if err != nil {
					return fmt.Errorf("failed to convert from trivy results: %w", err)
				}
				summary := vulnReport.ComputeSummary(results)
				report = &storagev1alpha1.Report{
					Summary: summary,
					Results: results,
				}
			}

			scannerDBVersion := map[string]metav1.Time{}
			if trivyDBVersions != nil {
				scannerDBVersion[storagev1alpha1.ScannerTrivyDB] = workerVulnDBVersion
				scannerDBVersion[storagev1alpha1.ScannerTrivyJavaDB] = workerJavaDBVersion
			}

			// Mutate the object
			vulnerabilityReport.Labels = map[string]string{
				v1alpha1.LabelScanJobUIDKey: string(scanJob.UID),
				api.LabelManagedByKey:       api.LabelManagedByValue,
				api.LabelPartOfKey:          api.LabelPartOfValue,
			}
			vulnerabilityReport.ImageMetadata = sbom.GetImageMetadata()
			vulnerabilityReport.ScannerDBVersion = scannerDBVersion
			vulnerabilityReport.Report = *report

			return controllerutil.SetControllerReference(sbom, vulnerabilityReport, h.scheme)
		})

		return fmt.Errorf("failed to create or update VulnerabilityReport: %w", err)
	})
	if err != nil {
		return fmt.Errorf("failed to create or update the VulnerabilityReport: %w", err)
	}

	return nil
}

// scanSBOM scans the provided SBOM using trivy and returns the vulnerability report.
//
//gocognit:ignore
func (h *ScanSBOMHandler) scanSBOM(ctx context.Context, sbom *storagev1alpha1.SBOM, trivyHome string) (trivyTypes.Report, error) {
	vexHubList := &v1alpha1.VEXHubList{}
	err := h.k8sClient.List(ctx, vexHubList, &client.ListOptions{})
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to list VEXHub: %w", err)
	}

	sbomFile, err := os.CreateTemp(h.workDir, "trivy.sbom.*.json")
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			h.logger.Error("failed to close temporary SBOM file", "error", err)
		}

		if err = os.Remove(sbomFile.Name()); err != nil {
			h.logger.Error("failed to remove temporary SBOM file", "error", err)
		}
	}()

	_, err = sbomFile.Write(sbom.SPDX.Raw)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to write SBOM file: %w", err)
	}
	reportFile, err := os.CreateTemp(h.workDir, "trivy.report.*.json")
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			h.logger.Error("failed to close temporary report file", "error", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			h.logger.Error("failed to remove temporary repoort file", "error", err)
		}
	}()

	app := trivyCommands.NewApp()
	trivyArgs := []string{
		"sbom",
		"--skip-version-check",
		"--skip-db-update",
		"--skip-java-db-update",
		"--disable-telemetry",
		"--cache-dir", h.workDir,
		"--format", "json",
		"--output", reportFile.Name(),
	}

	if len(vexHubList.Items) > 0 {
		trivyVEXPath := path.Join(trivyHome, trivyVEXSubPath)
		vexRepoPath := path.Join(trivyVEXPath, trivyVEXRepoFile)
		if err := h.setupVEXHubRepositories(vexHubList, trivyVEXPath, vexRepoPath); err != nil {
			return trivyTypes.Report{}, fmt.Errorf("failed to setup VEX Hub repositories: %w", err)
		}
		// Clean up the trivy home directory after each handler execution to
		// ensure VEX repositories are refreshed on every run.
		defer func() {
			h.logger.Debug("Removing trivy home")
			if err := os.RemoveAll(trivyHome); err != nil {
				h.logger.Error("failed to remove temporary trivy home", "error", err)
			}
		}()

		// We explicitly set the `--vex` option only when needed
		// (VEXHub resources are found). This is because trivy automatically
		// fills the repository file with aquasecurity VEX files, when
		// `--vex` is specificed.
		trivyArgs = append(trivyArgs, "--vex", "repo", "--show-suppressed")
	}

	// add SBOM file name at the end.
	trivyArgs = append(trivyArgs, sbomFile.Name())
	app.SetArgs(trivyArgs)

	if err := app.ExecuteContext(ctx); err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to execute trivy: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	reportOrig := trivyTypes.Report{}
	err = json.Unmarshal(reportBytes, &reportOrig)
	if err != nil {
		return trivyTypes.Report{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return reportOrig, nil
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

// updateTrivyVulnerabilityDB executes the Trivy VulnerabilityDB check command and returns the parsed metadata.Metadata
func (h *ScanSBOMHandler) updateTrivyVulnerabilityDB(ctx context.Context, trivyDBRepository string) error {
	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"image",
		"--download-db-only",
		"--db-repository", trivyDBRepository,
		"--format", "json",
		"--cache-dir", h.workDir,
	})
	if err := app.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("failed to update Trivy VulnerabilityDB: %w", err)
	}
	return nil
}

// updateTrivyJavaDB executes the Trivy JavaDB check command and returns the parsed metadata.Metadata
func (h *ScanSBOMHandler) updateTrivyJavaDB(ctx context.Context, trivyJavaDBRepository string) error {
	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"image",
		"--download-java-db-only",
		"--java-db-repository", trivyJavaDBRepository,
		"--format", "json",
		"--cache-dir", h.workDir,
	})
	if err := app.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("failed to update Trivy JavaDB: %w", err)
	}
	return nil
}

// getTrivyVulnerabilityDBVersion executes the Trivy command and returns the parsed metadata.Metadata
func (h *ScanSBOMHandler) getTrivyDBVersions(ctx context.Context) (*version.VersionInfo, error) {
	app := trivyCommands.NewApp()
	buf := new(bytes.Buffer)
	app.SetOut(buf)
	app.SetArgs([]string{
		"version",
		"--format", "json",
		"--cache-dir", h.workDir,
	})
	if err := app.ExecuteContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to get Trivy DB versions: %w", err)
	}
	var versionInfo *version.VersionInfo
	if err := json.NewDecoder(buf).Decode(&versionInfo); err != nil {
		return nil, fmt.Errorf("failed to decode Trivy DB versions: %w", err)
	}
	return versionInfo, nil
}

// shouldSkipScan determines if we should skip the scan based on DB versions.
// It currently returns true (skip) if the existing report's DB is older
// or equal to the worker's DB.
func (h *ScanSBOMHandler) shouldSkipTrivyScan(
	report *storagev1alpha1.VulnerabilityReport,
	workerVulnDB metav1.Time,
	workerJavaDB metav1.Time,
) bool {
	// first scan ever (report doesn't exist or has no timestamp)
	if report == nil || report.CreationTimestamp.IsZero() {
		return false
	}

	foundVulnDBVersion := report.ScannerDBVersion[storagev1alpha1.ScannerTrivyDB]
	foundJavaDBVersion := report.ScannerDBVersion[storagev1alpha1.ScannerTrivyJavaDB]

	// skips if the Report DB is
	// older or equal to the current DB.
	vulnSkip := foundVulnDBVersion.Before(&workerVulnDB) || foundVulnDBVersion.Equal(&workerVulnDB)
	javaSkip := foundJavaDBVersion.Before(&workerJavaDB) || foundJavaDBVersion.Equal(&workerJavaDB)

	return vulnSkip && javaSkip
}
