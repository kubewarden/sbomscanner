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
	"time"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"

	"github.com/avast/retry-go/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kubewarden/sbomscanner/internal/apiserver"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	"github.com/kubewarden/sbomscanner/internal/storage"
)

func main() {
	if err := run(); err != nil {
		//nolint:sloglint // Use the global logger since the logger is not yet initialized
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		certFile    string
		keyFile     string
		pgURIFile   string
		pgTLSCAFile string
		logLevel    string
		migrate     bool
	)

	flag.StringVar(&certFile, "cert-file", "/tls/tls.crt", "Path to the TLS certificate file for serving HTTPS requests.")
	flag.StringVar(&keyFile, "key-file", "/tls/tls.key", "Path to the TLS private key file for serving HTTPS requests.")
	flag.StringVar(&pgURIFile, "pg-uri-file", "/pg/uri", "Path to file containing the PostgreSQL connection URI (format: postgresql://username:password@hostname:5432/dbname). Any sslmode or ssl* parameters in the URI are ignored. TLS with CA verification is always enforced using the certificate from pg-tls-ca-file.")
	flag.StringVar(&pgTLSCAFile, "pg-tls-ca-file", "/pg/tls/server/ca.crt", "Path to PostgreSQL server CA certificate for TLS verification.")
	flag.StringVar(&logLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.BoolVar(&migrate, "migrate", false, "Run database migrations and exit.")
	flag.Parse()

	slogLevel, err := cmdutil.ParseLogLevel(logLevel)
	if err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}

	opts := slog.HandlerOptions{
		Level: slogLevel,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &opts)).With("component", "storage")
	logger.Info("Starting storage")

	// Kubernetes components use klog for logging, so we need to redirect it to our slog logger.
	klog.SetSlogLogger(logger)

	ctx := genericapiserver.SetupSignalContext()

	db, err := newDB(ctx, pgURIFile, pgTLSCAFile)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()

	if migrate {
		if err := runMigrations(ctx, db, logger); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
		logger.Info("migrations completed successfully")
		return nil
	}

	if err := runServer(ctx, db, certFile, keyFile, logger); err != nil {
		return fmt.Errorf("running server: %w", err)
	}

	return nil
}

func newDB(ctx context.Context, pgURIFile, pgTLSCAFile string) (*pgxpool.Pool, error) {
	connString, err := os.ReadFile(pgURIFile)
	if err != nil {
		return nil, fmt.Errorf("reading database URI: %w", err)
	}

	config, err := pgxpool.ParseConfig(string(connString))
	if err != nil {
		return nil, fmt.Errorf("parsing database URI: %w", err)
	}

	// Use the BeforeConnect callback so that whenever a connection is created or reset,
	// the TLS configuration is reapplied.
	// This ensures that certificates are reloaded from disk if they have been updated.
	// See https://github.com/jackc/pgx/discussions/2103
	config.BeforeConnect = func(_ context.Context, connConfig *pgx.ConnConfig) error {
		connConfig.Fallbacks = nil // disable TLS fallback to force TLS connectio

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
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	return db, nil
}

func runMigrations(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	logger.InfoContext(ctx, "running migrations")

	err := retry.Do(
		func() error {
			if _, err := db.Exec(ctx, storage.CreateImageTableSQL); err != nil {
				return fmt.Errorf("creating image table: %w", err)
			}
			if _, err := db.Exec(ctx, storage.CreateSBOMTableSQL); err != nil {
				return fmt.Errorf("creating sbom table: %w", err)
			}
			if _, err := db.Exec(ctx, storage.CreateVulnerabilityReportTableSQL); err != nil {
				return fmt.Errorf("creating vulnerability report table: %w", err)
			}
			logger.Info("migration step succeeded")
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(20),
		retry.Delay(2*time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(10*time.Second),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			logger.Warn("migration retrying", "attempt", n+1, "error", err)
		}),
	)
	if err != nil {
		return fmt.Errorf("error while running migrations: %w", err)
	}

	return nil
}

func runServer(ctx context.Context, db *pgxpool.Pool, certFile, keyFile string, logger *slog.Logger) error {
	srv, err := apiserver.NewStorageAPIServer(db, certFile, keyFile, logger)
	if err != nil {
		return fmt.Errorf("creating storage API server: %w", err)
	}

	logger.InfoContext(ctx, "starting storage API server")
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("starting storage storage API server: %w", err)
	}

	return nil
}
