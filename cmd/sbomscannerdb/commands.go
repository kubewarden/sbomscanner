package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// runBuild builds a SQLite database per feed, packs them as an OCI artifact, and tags it in the local store.
// The upstream feed files are downloaded, or read from dataDir when it is set.
// nextUpdateInterval is the shortest cadence among the feeds. It sets how far ahead nextUpdate points.
func runBuild(ctx context.Context, ref, dataDir string, nextUpdateInterval time.Duration, logger *slog.Logger) error {
	workDir, err := os.MkdirTemp("", "sbomscannerdb-build-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	srcDir := dataDir
	if srcDir == "" {
		srcDir = workDir
	}

	var layers []oci.Layer
	for _, source := range datafeed.AllSources(datafeed.NewHTTPDownloader(), logger) {
		if dataDir == "" {
			if err := source.Download(ctx, srcDir); err != nil {
				return fmt.Errorf("download %s: %w", source.Name(), err)
			}
		}
		fileName, err := source.BuildSQLite(ctx, srcDir, workDir)
		if err != nil {
			return fmt.Errorf("%s: %w", source.Name(), err)
		}
		layers = append(layers, oci.Layer{
			Name:      source.Name(),
			FileName:  fileName,
			MediaType: oci.DataLayerMediaType(source.Name()),
		})
	}

	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	artifact, err := oci.NewBuilder(store, logger, os.Getenv(oci.SourceDateEpochEnv)).
		Build(ctx, ref, workDir, layers, nextUpdateInterval)
	if err != nil {
		return fmt.Errorf("build artifact: %w", err)
	}
	fmt.Fprintf(os.Stdout, "built %s (%s)\n", artifact.Ref, artifact.Digest)
	return nil
}

// runList prints the artifacts in the local store as a table.
func runList(logger *slog.Logger) error {
	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	artifacts, err := store.List()
	if err != nil {
		return fmt.Errorf("list artifacts: %w", err)
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "REFERENCE\tDIGEST\tSIZE")
	for _, artifact := range artifacts {
		fmt.Fprintf(writer, "%s\t%s\t%d\n", artifact.Ref, artifact.Digest, artifact.Size)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	return nil
}

// runPush publishes a previously built artifact from the local store.
func runPush(ctx context.Context, ref string, config oci.Config, logger *slog.Logger) error {
	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	artifact, err := oci.NewRemote(config, logger).Push(ctx, store, ref)
	if err != nil {
		return fmt.Errorf("push artifact: %w", err)
	}
	fmt.Fprintf(os.Stdout, "pushed %s (%s)\n", artifact.Ref, artifact.Digest)
	return nil
}

// runPull copies the artifact from the registry into the local store.
func runPull(ctx context.Context, ref string, config oci.Config, logger *slog.Logger) error {
	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	artifact, err := oci.NewRemote(config, logger).Pull(ctx, store, ref)
	if err != nil {
		return fmt.Errorf("pull artifact: %w", err)
	}
	fmt.Fprintf(os.Stdout, "pulled %s (%s)\n", artifact.Ref, artifact.Digest)
	return nil
}

// runExport writes the data files of an artifact in the local store into outputDir.
func runExport(ctx context.Context, ref, outputDir string, logger *slog.Logger) error {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return fmt.Errorf("create output dir %s: %w", outputDir, err)
	}
	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	paths, err := store.Export(ctx, ref, outputDir)
	if err != nil {
		return fmt.Errorf("export artifact: %w", err)
	}
	for _, path := range paths {
		fmt.Fprintf(os.Stdout, "exported %s\n", path)
	}
	return nil
}

// runInspect resolves the artifact's manifest — from the local store when local
// is set, otherwise from the registry — and renders it as JSON.
func runInspect(ctx context.Context, ref string, local bool, config oci.Config, logger *slog.Logger) error {
	var view oci.ManifestView
	var err error
	if local {
		var store *oci.Store
		if store, err = oci.NewDefaultStore(logger); err != nil {
			return fmt.Errorf("open local store: %w", err)
		}
		view, err = store.Inspect(ctx, ref)
	} else {
		view, err = oci.NewRemote(config, logger).Inspect(ctx, ref)
	}
	if err != nil {
		return fmt.Errorf("inspect artifact: %w", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(view); err != nil {
		return fmt.Errorf("encode manifest as json: %w", err)
	}
	return nil
}
