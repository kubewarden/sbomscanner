package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// runBuild downloads the data feeds into a temp dir,
// packs them as an OCI artifact, and tags it in the local store.
// nextUpdateInterval is the shortest cadence among the bundled feeds; it sets
// how far ahead the artifact's nextUpdate annotation points from build time.
func runBuild(ctx context.Context, ref string, nextUpdateInterval time.Duration, logger *slog.Logger) error {
	dataDir, err := os.MkdirTemp("", "sbomscannerdb-data-*")
	if err != nil {
		return fmt.Errorf("create temp data dir: %w", err)
	}
	defer os.RemoveAll(dataDir)

	httpDownloader := datafeed.NewHTTPDownloader()
	var layers []oci.Layer
	for _, source := range datafeed.AllSources(httpDownloader, logger) {
		if err := source.Download(ctx, dataDir); err != nil {
			return fmt.Errorf("download %s: %w", source.Name(), err)
		}
		layers = append(layers, oci.Layer{
			Name:      source.Name(),
			FileName:  source.FileName(),
			MediaType: oci.DataLayerMediaType(source.Name(), source.Format()),
		})
	}

	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	artifact, err := oci.NewBuilder(store, logger, os.Getenv(oci.SourceDateEpochEnv)).
		Build(ctx, ref, dataDir, layers, nextUpdateInterval)
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

// runPull fetches the artifact and writes its data files to the current directory.
func runPull(ctx context.Context, ref string, config oci.Config, logger *slog.Logger) error {
	paths, err := oci.NewRemote(config, logger).Pull(ctx, ref, ".")
	if err != nil {
		return fmt.Errorf("pull artifact: %w", err)
	}
	for _, dst := range paths {
		fmt.Fprintf(os.Stdout, "pulled %s from %s\n", dst, ref)
	}
	return nil
}

// runInspect resolves the artifact's manifest — from the local store when local
// is set, otherwise from the registry — and renders it in the requested format.
func runInspect(ctx context.Context, ref, format string, local bool, config oci.Config, logger *slog.Logger) error {
	render, ok := inspectFormats[format]
	if !ok {
		return fmt.Errorf("unknown format %q (supported: %s)", format, supportedInspectFormats())
	}

	var (
		view oci.ManifestView
		err  error
	)
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

	return render(os.Stdout, view)
}
