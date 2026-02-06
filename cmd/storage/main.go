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

	"github.com/docker/go-units"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

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
		certFile                string
		keyFile                 string
		pgURIFile               string
		pgTLSCAFile             string
		natsURL                 string
		natsCertFile            string
		natsKeyFile             string
		natsCAFile              string
		maxRequestBodySize      string
		serviceAccountNamespace string
		serviceAccountName      string
		logLevel                string
		init                    bool
	)

	flag.StringVar(&certFile, "cert-file", "/tls/tls.crt", "Path to the TLS certificate file for serving HTTPS requests.")
	flag.StringVar(&keyFile, "key-file", "/tls/tls.key", "Path to the TLS private key file for serving HTTPS requests.")
	flag.StringVar(&pgURIFile, "pg-uri-file", "/pg/uri", "Path to file containing the PostgreSQL connection URI (format: postgresql://username:password@hostname:5432/dbname). Any sslmode or ssl* parameters in the URI are ignored. TLS with CA verification is always enforced using the certificate from pg-tls-ca-file.")
	flag.StringVar(&pgTLSCAFile, "pg-tls-ca-file", "/pg/tls/server/ca.crt", "Path to PostgreSQL server CA certificate for TLS verification.")
	flag.StringVar(&natsURL, "nats-url", "localhost:4222", "The URL of the NATS server.")
	flag.StringVar(&natsCertFile, "nats-cert-file", "/nats/tls/tls.crt", "The path to the NATS client certificate.")
	flag.StringVar(&natsKeyFile, "nats-key-file", "/nats/tls/tls.key", "The path to the NATS client key.")
	flag.StringVar(&natsCAFile, "nats-ca-file", "/nats/tls/ca.crt", "The path to the NATS CA certificate.")
	flag.StringVar(&maxRequestBodySize, "max-request-body-size", "100MB", "The maximum size of request bodies accepted by the server. 0 means no limit.")
	flag.StringVar(&serviceAccountNamespace, "service-account-namespace", "sbomscanner", "The namespace of the service account used by the controller. This is used by the admission plugins.")
	flag.StringVar(&serviceAccountName, "service-account-name", "sbomscanner-controller", "The name of the service account used by the controller. This is used by the admission plugins.")
	flag.StringVar(&logLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.BoolVar(&init, "init", false, "Run initialization tasks and exit.")
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

	maxRequestBodyBytes, err := units.FromHumanSize(maxRequestBodySize)
	if err != nil {
		return fmt.Errorf("invalid max request body size: %w", err)
	}

	serverConfig := apiserver.StorageAPIServerConfig{
		CertFile:                certFile,
		KeyFile:                 keyFile,
		MaxRequestBodyBytes:     maxRequestBodyBytes,
		ServiceAccountNamespace: serviceAccountNamespace,
		ServiceAccountName:      serviceAccountName,
	}

	db, err := newDB(ctx, pgURIFile, pgTLSCAFile)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer db.Close()

	natsOpts := []nats.Option{
		nats.RootCAs(natsCAFile),
		nats.ClientCert(natsCertFile, natsKeyFile),
	}

	if init {
		logger = logger.With("task", "init")

		if err := cmdutil.WaitForPostgres(ctx, db, logger); err != nil {
			return fmt.Errorf("error waiting for postgres: %w", err)
		}

		logger.Info("Running migrations.")
		if err := storage.RunMigrations(ctx, db); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
		logger.Info("Migrations completed successfully.")

		if err := cmdutil.WaitForNATS(ctx, natsURL, natsOpts, logger); err != nil {
			logger.Error("Error waiting for NATS", "error", err)
			return fmt.Errorf("waiting for Nats: %w", err)
		}
		logger.Info("Initialization tasks completed successfully.")

		return nil
	}

	nc, err := nats.Connect(natsURL,
		natsOpts...,
	)
	if err != nil {
		logger.Error("Unable to connect to NATS server", "error", err, "natsURL", natsURL)
		return fmt.Errorf("connecting to NATS server: %w", err)
	}

	if err := runServer(ctx, db, nc, logger, serverConfig); err != nil {
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

func runServer(ctx context.Context, db *pgxpool.Pool, nc *nats.Conn, logger *slog.Logger, cfg apiserver.StorageAPIServerConfig) error {
	srv, err := apiserver.NewStorageAPIServer(db, nc, logger, cfg)
	if err != nil {
		return fmt.Errorf("creating storage API server: %w", err)
	}

	logger.InfoContext(ctx, "starting storage API server")
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("starting storage storage API server: %w", err)
	}

	return nil
}
