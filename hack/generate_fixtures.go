//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	trivyCommands "github.com/aquasecurity/trivy/pkg/commands"
)

const (
	testTrivyDBRepository     = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-db:2"
	testTrivyJavaDBRepository = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-java-db:1"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: go run generate_fixtures.go <fixtures-directory>")
	}

	dir := os.Args[1]
	files, err := filepath.Glob(filepath.Join(dir, "*.spdx.json"))
	if err != nil {
		log.Fatalf("failed to glob files: %v", err)
	}

	if len(files) == 0 {
		log.Printf("No *.spdx.json files found in %s", dir)
		return
	}

	log.Printf("Found %d SPDX files to update", len(files))

	for _, file := range files {
		if err := processFile(file); err != nil {
			log.Printf("Failed to process %s: %v", file, err)
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
