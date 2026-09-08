//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/handlers/trivyreport"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

const (
	testTrivyDBRepository       = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-db:2"
	testTrivyJavaDBRepository   = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-java-db:1"
	testSBOMScannerDBRepository = "ghcr.io/kubewarden/sbomscanner/test-assets/sbomscannerdb:1"
)

func main() {
	reportsOnly := flag.Bool("reports-only", false, "keep the SPDX files and regenerate only the *.sbomscanner.json reports")
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("Usage: go run generate_fixtures.go [--reports-only] <fixtures-directory>")
	}

	dir := flag.Arg(0)
	files, err := filepath.Glob(filepath.Join(dir, "*.spdx.json"))
	if err != nil {
		log.Fatalf("failed to glob files: %v", err)
	}

	if len(files) == 0 {
		log.Printf("No *.spdx.json files found in %s", dir)
		return
	}

	log.Printf("Found %d SPDX files to update", len(files))

	if !*reportsOnly {
		for _, file := range files {
			if err := processFile(file); err != nil {
				log.Printf("Failed to process %s: %v", file, err)
			}
		}
	}

	cacheDir, err := os.MkdirTemp("", "sbomscanner-fixtures-*")
	if err != nil {
		log.Fatalf("failed to create cache dir: %v", err)
	}
	defer os.RemoveAll(cacheDir)
	db := sbomscannerdb.New(testSBOMScannerDBRepository, cacheDir, oci.Config{}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	for _, file := range files {
		if err := generateReport(context.Background(), db, cacheDir, file); err != nil {
			log.Printf("Failed to generate report for %s: %v", file, err)
		}
	}

	log.Println("Done!")
}

func processFile(file string) error {
	log.Printf("Processing: %s", file)

	// Read existing file to get image name
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var spdx struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &spdx); err != nil {
		return fmt.Errorf("failed to parse SPDX JSON: %w", err)
	}

	if spdx.Name == "" {
		return errors.New("no image name found in file")
	}

	log.Printf("  Image: %s", spdx.Name)

	// Generate new SBOM using same code path as production
	if err := generateSBOM(context.Background(), spdx.Name, file); err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	log.Printf("  ✓ Updated")
	return nil
}

func generateSBOM(ctx context.Context, imageName, outputFile string) error {
	// Create temp file for output (same pattern as production code)
	tmpFile, err := os.CreateTemp("", "trivy.sbom.*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	defer os.Remove(tmpPath)

	// Use the same trivy invocation as generateSPDX in handlers
	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"image",
		"--debug",
		"--skip-version-check",
		"--disable-telemetry",
		"--cache-dir", os.TempDir(),
		"--format", "spdx-json",
		"--skip-db-update",
		"--java-db-repository", testTrivyJavaDBRepository,
		"--output", tmpPath,
		imageName,
	})

	// Capture stdout/stderr
	app.SetOut(os.Stdout)
	app.SetErr(os.Stderr)

	if err := app.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("trivy failed: %w", err)
	}

	// Read generated SBOM
	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to open temp file: %w", err)
	}
	defer f.Close()

	spdxBytes, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read SBOM: %w", err)
	}

	// Write to output file
	if err := os.WriteFile(outputFile, spdxBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// generateReport scans the SPDX file with trivy and the sbomscanner database and
// writes the expected report next to it, as the scan handler would produce it.
// The trivy target is a temp path that differs on every run, so an existing
// report keeps its target.
func generateReport(ctx context.Context, db *sbomscannerdb.DB, cacheDir, spdxFile string) error {
	reportFile := strings.TrimSuffix(spdxFile, ".spdx.json") + ".sbomscanner.json"
	log.Printf("Generating report: %s", reportFile)

	tmpFile, err := os.CreateTemp("", "trivy.report.*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	defer os.Remove(tmpPath)

	// Use the same trivy invocation as runTrivyScan in handlers
	app := trivyCommands.NewApp()
	app.SetArgs([]string{
		"sbom",
		"--skip-version-check",
		"--disable-telemetry",
		"--cache-dir", cacheDir,
		"--format", "json",
		"--db-repository", testTrivyDBRepository,
		"--java-db-repository", testTrivyJavaDBRepository,
		"--output", tmpPath,
		spdxFile,
	})
	app.SetOut(os.Stdout)
	app.SetErr(os.Stderr)
	if err := app.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("trivy failed: %w", err)
	}

	reportBytes, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to read trivy report: %w", err)
	}
	var trivyReport trivyTypes.Report
	if err := json.Unmarshal(reportBytes, &trivyReport); err != nil {
		return fmt.Errorf("failed to unmarshal trivy report: %w", err)
	}
	results, err := trivyreport.NewResultsFromTrivyReport(trivyReport)
	if err != nil {
		return fmt.Errorf("failed to convert trivy results: %w", err)
	}

	// Same enrichment as enrichResults in handlers
	if err := db.Update(ctx); err != nil {
		return fmt.Errorf("failed to update sbomscanner DB: %w", err)
	}
	for i := range results {
		for j := range results[i].Vulnerabilities {
			vuln := &results[i].Vulnerabilities[j]
			record := db.Lookup(vuln.CVE)
			vuln.KEV = record.KEV
			vuln.EPSS = record.EPSS
		}
	}

	if previous, err := os.ReadFile(reportFile); err == nil {
		var old storagev1alpha1.Report
		if err := json.Unmarshal(previous, &old); err == nil && len(old.Results) > 0 && len(results) > 0 {
			results[0].Target = old.Results[0].Target
		}
	}

	report := storagev1alpha1.Report{
		Summary: storagev1alpha1.NewSummaryFromResults(results),
		Results: results,
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(reportFile, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	return nil
}
