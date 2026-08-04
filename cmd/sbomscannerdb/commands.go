package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/datafeed"
	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// sourceDateEpochEnv is the well-known variable used to pin a build's timestamp
// for reproducible builds. When set, it overrides the wall-clock build time.
const sourceDateEpochEnv = "SOURCE_DATE_EPOCH"

// buildTime returns the timestamp to stamp on the artifact. It honors
// SOURCE_DATE_EPOCH (Unix seconds) so CI can produce byte-identical, reproducible
// artifacts; otherwise it falls back to the current wall-clock time.
func buildTime() (time.Time, error) {
	raw := os.Getenv(sourceDateEpochEnv)
	if raw == "" {
		return time.Now().UTC(), nil
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q: %w", sourceDateEpochEnv, raw, err)
	}
	return time.Unix(secs, 0).UTC(), nil
}

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
	if err := datafeed.NewKEVDownloader(httpDownloader, logger).Download(ctx, dataDir); err != nil {
		return fmt.Errorf("download data feeds: %w", err)
	}
	if err := datafeed.NewEPSSDownloader(httpDownloader, logger).Download(ctx, dataDir); err != nil {
		return fmt.Errorf("download data feeds: %w", err)
	}

	store, err := oci.NewDefaultStore(logger)
	if err != nil {
		return fmt.Errorf("open local store: %w", err)
	}
	layers := []oci.Layer{
		{Name: "kev", FileName: datafeed.KEVFileName, MediaType: oci.LayerMediaTypeKEV},
		{Name: "epss", FileName: datafeed.EPSSFileName, MediaType: oci.LayerMediaTypeEPSS},
	}
	now, err := buildTime()
	if err != nil {
		return err
	}
	window := oci.UpdateWindow{LastUpdate: now, NextUpdate: now.Add(nextUpdateInterval)}
	artifact, err := oci.NewBuilder(store, logger).Build(ctx, ref, dataDir, layers, window)
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
