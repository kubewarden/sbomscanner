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

	"k8s.io/apimachinery/pkg/runtime"

	vexrepo "github.com/aquasecurity/trivy/pkg/vex/repo"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	trivyreport "github.com/kubewarden/sbomscanner/internal/handlers/trivyreport"
	"github.com/kubewarden/sbomscanner/internal/messaging"
)

const (
	trivyVEXSubPath  = ".trivy/vex"
	trivyVEXRepoFile = "repository.yaml"
)

type scanSBOMBase struct {
	k8sClient             client.Client
	scheme                *runtime.Scheme
	workDir               string
	trivyDBRepository     string
	trivyJavaDBRepository string
	logger                *slog.Logger
}

// runTrivyScan executes a trivy scan on the given SPDX data and returns the parsed results and summary.
func (b *scanSBOMBase) runTrivyScan(ctx context.Context, rawSPDX []byte, message messaging.Message) ([]storagev1alpha1.Result, storagev1alpha1.Summary, error) { //nolint:funlen,cyclop // trivy setup requires sequential steps
	vexHubList := &v1alpha1.VEXHubList{}
	if err := b.k8sClient.List(ctx, vexHubList, &client.ListOptions{}); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to list VEXHub: %w", err)
	}

	sbomFile, err := os.CreateTemp(b.workDir, "trivy.sbom.*.json")
	if err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to create temporary SBOM file: %w", err)
	}
	defer func() {
		if err = sbomFile.Close(); err != nil {
			b.logger.Error("failed to close temporary SBOM file", "error", err)
		}

		if err = os.Remove(sbomFile.Name()); err != nil {
			b.logger.Error("failed to remove temporary SBOM file", "error", err)
		}
	}()

	if _, err = sbomFile.Write(rawSPDX); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to write SBOM file: %w", err)
	}

	reportFile, err := os.CreateTemp(b.workDir, "trivy.report.*.json")
	if err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to create temporary report file: %w", err)
	}
	defer func() {
		if err = reportFile.Close(); err != nil {
			b.logger.Error("failed to close temporary report file", "error", err)
		}

		if err = os.Remove(reportFile.Name()); err != nil {
			b.logger.Error("failed to remove temporary repoort file", "error", err)
		}
	}()

	trivyArgs := []string{
		"sbom",
		"--skip-version-check",
		"--disable-telemetry",
		"--cache-dir", b.workDir,
		"--format", "json",
		"--db-repository", b.trivyDBRepository,
		"--java-db-repository", b.trivyJavaDBRepository,
		"--output", reportFile.Name(),
	}

	trivyHome, err := os.MkdirTemp("/tmp", "trivy-")
	if err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to create temporary trivy home: %w", err)
	}
	if err = os.Setenv("XDG_DATA_HOME", trivyHome); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to set XDG_DATA_HOME to %s: %w", trivyHome, err)
	}

	if len(vexHubList.Items) > 0 {
		trivyVEXPath := path.Join(trivyHome, trivyVEXSubPath)
		vexRepoPath := path.Join(trivyVEXPath, trivyVEXRepoFile)
		if err = b.setupVEXHubRepositories(vexHubList, trivyVEXPath, vexRepoPath); err != nil {
			return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to setup VEX Hub repositories: %w", err)
		}
		defer func() {
			b.logger.Debug("Removing trivy home")
			if err = os.RemoveAll(trivyHome); err != nil {
				b.logger.Error("failed to remove temporary trivy home", "error", err)
			}
		}()

		trivyArgs = append(trivyArgs, "--vex", "repo", "--show-suppressed")
	}

	app := trivyCommands.NewApp()
	trivyArgs = append(trivyArgs, sbomFile.Name())
	app.SetArgs(trivyArgs)

	if err = app.ExecuteContext(ctx); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to execute trivy: %w", err)
	}

	if err = message.InProgress(); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to ack message as in progress: %w", err)
	}

	reportBytes, err := io.ReadAll(reportFile)
	if err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to read SBOM output: %w", err)
	}

	reportOrig := trivyTypes.Report{}
	if err = json.Unmarshal(reportBytes, &reportOrig); err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	results, err := trivyreport.NewResultsFromTrivyReport(reportOrig)
	if err != nil {
		return nil, storagev1alpha1.Summary{}, fmt.Errorf("failed to convert from trivy results: %w", err)
	}

	summary := storagev1alpha1.NewSummaryFromResults(results)

	return results, summary, nil
}

func (b *scanSBOMBase) setupVEXHubRepositories(vexHubList *v1alpha1.VEXHubList, trivyVEXPath, vexRepoPath string) error {
	config := vexrepo.Config{}
	for _, repo := range vexHubList.Items {
		repo := vexrepo.Repository{
			Name:    repo.Name,
			URL:     repo.Spec.URL,
			Enabled: repo.Spec.Enabled,
		}
		config.Repositories = append(config.Repositories, repo)
	}

	repositories, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal struct: %w", err)
	}

	b.logger.Debug("Creating VEX repository directory", "vexhub", trivyVEXPath)
	if err = os.MkdirAll(trivyVEXPath, 0o750); err != nil {
		return fmt.Errorf("failed to create VEX configuration directory: %w", err)
	}

	b.logger.Debug("Creating VEX repository file", "vexhub", vexRepoPath)
	if err = os.WriteFile(vexRepoPath, repositories, 0o600); err != nil {
		return fmt.Errorf("failed to create VEX repository file: %w", err)
	}

	return nil
}
