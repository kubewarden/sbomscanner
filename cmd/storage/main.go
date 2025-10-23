package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubewarden/sbomscanner/internal/apiserver"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	"github.com/kubewarden/sbomscanner/internal/storage"
)

func main() {
	var certFile string
	var keyFile string
	var pgURIFile string
	var pgTLSCAFile string
	var logLevel string

	flag.StringVar(&certFile, "cert-file", "/tls/tls.crt", "Path to the TLS certificate file for serving HTTPS requests.")
	flag.StringVar(&keyFile, "key-file", "/tls/tls.key", "Path to the TLS private key file for serving HTTPS requests.")
	flag.StringVar(&pgURIFile, "pg-uri-file", "/pg/uri", "Path to file containing the PostgreSQL connection URI (format: postgresql://username:password@hostname:5432/dbname). Any sslmode or ssl* parameters in the URI are ignored. TLS with CA verification is always enforced using the certificate from pg-tls-ca-file.")
	flag.StringVar(&pgTLSCAFile, "pg-tls-ca-file", "/pg/tls/server/ca.crt", "Path to PostgreSQL server CA certificate for TLS verification.")
	flag.StringVar(&logLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.Parse()

	slogLevel, err := cmdutil.ParseLogLevel(logLevel)
	if err != nil {
		//nolint:sloglint // Use the global logger since the logger is not yet initialized
		slog.Error("error initializing the logger", "error", err)
		os.Exit(1)
	}

	opts := slog.HandlerOptions{
		Level: slogLevel,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &opts)).With("component", "storage")
	logger.Info("Starting storage")

	// Kubernetes components use klog for logging, so we need to redirect it to our slog logger.
	klog.SetSlogLogger(logger)

	ctx := genericapiserver.SetupSignalContext()

	if err := run(ctx, certFile, keyFile, pgURIFile, pgTLSCAFile, logger); err != nil {
		logger.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, certFile, keyFile, pgURIFile, pgTLSCAFile string, logger *slog.Logger) error {
	connString, err := os.ReadFile(pgURIFile)
	if err != nil {
		return fmt.Errorf("reading database URI: %w", err)
	}

	config, err := pgxpool.ParseConfig(string(connString))
	if err != nil {
		return fmt.Errorf("parsing database URI: %w", err)
	}

	// Use the BeforeConnect callback so that whenever a connection is created or reset,
	// the TLS configuration is reapplied.
	// This ensures that certificates are reloaded from disk if they have been updated.
	// See https://github.com/jackc/pgx/discussions/2103
	config.BeforeConnect = func(_ context.Context, connConfig *pgx.ConnConfig) error {
		connConfig.Fallbacks = nil // disable TLS fallback to force TLS connection

		serverCA, err := os.ReadFile(pgTLSCAFile)
		if err != nil {
			return fmt.Errorf("reading database server CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(serverCA) {
			return errors.New("appending database server CA certificate to pool")
		}

		connConfig.TLSConfig = &tls.Config{
			RootCAs:            caCertPool,
			ServerName:         config.ConnConfig.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}

		return nil
	}

	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}
	defer db.Close()

	// Run migrations
	if _, err := db.Exec(ctx, storage.CreateImageTableSQL); err != nil {
		return fmt.Errorf("creating image table: %w", err)
	}
	if _, err := db.Exec(ctx, storage.CreateSBOMTableSQL); err != nil {
		return fmt.Errorf("creating sbom table: %w", err)
	}
	if _, err := db.Exec(ctx, storage.CreateVulnerabilityReportTableSQL); err != nil {
		return fmt.Errorf("creating vulnerability report table: %w", err)
	}

	srv, err := apiserver.NewStorageAPIServer(db, certFile, keyFile, logger)
	if err != nil {
		return fmt.Errorf("creating storage server: %w", err)
	}

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("starting storage server: %w", err)
	}

	return nil
}
