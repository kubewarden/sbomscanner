package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	"github.com/kubewarden/sbomscanner/internal/handlers"
	"github.com/kubewarden/sbomscanner/internal/handlers/registry"
	"github.com/kubewarden/sbomscanner/internal/messaging"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
	"github.com/kubewarden/sbomscanner/internal/version"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	"github.com/nats-io/nats.go"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

const (
	targetDir    = "/host"
	nodeMode     = "node"
	registryMode = "registry"
)

type Config struct {
	NatsURL               string
	NatsCertFile          string
	NatsKeyFile           string
	NatsCAFile            string
	RunDir                string
	TrivyDBRepository     string
	TrivyJavaDBRepository string
	InstallationNamespace string
	Init                  bool
	LogLevel              string
	Mode                  string
	NodeName              string
}

func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.NatsURL, "nats-url", "localhost:4222", "The URL of the NATS server.")
	flag.StringVar(&cfg.NatsCertFile, "nats-cert-file", "/nats/tls/tls.crt", "The path to the NATS client certificate.")
	flag.StringVar(&cfg.NatsKeyFile, "nats-key-file", "/nats/tls/tls.key", "The path to the NATS client key.")
	flag.StringVar(&cfg.NatsCAFile, "nats-ca-file", "/nats/tls/ca.crt", "The path to the NATS CA certificate.")
	flag.StringVar(&cfg.RunDir, "run-dir", "/var/run/worker", "Directory to store temporary files.")
	flag.StringVar(&cfg.TrivyDBRepository, "trivy-db-repository", "public.ecr.aws/aquasecurity/trivy-db", "OCI repository to retrieve trivy-db.")
	flag.StringVar(&cfg.TrivyJavaDBRepository, "trivy-java-db-repository", "public.ecr.aws/aquasecurity/trivy-java-db", "OCI repository to retrieve trivy-java-db.")
	flag.StringVar(&cfg.InstallationNamespace, "installation-namespace", "sbomscanner", "The namespace where sbomscanner is installed.")
	flag.BoolVar(&cfg.Init, "init", false, "Run initialization tasks and exit.")
	flag.StringVar(&cfg.LogLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.StringVar(&cfg.Mode, "mode", "registry", "Mode of operation ('registry' or 'node').")
	flag.StringVar(&cfg.NodeName, "node-name", "", "The name of the node (required if mode is 'node').")
	flag.Parse()
	return cfg
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		//nolint:sloglint // No structured logger is available at this scope: run() owns the logger lifecycle.
		slog.Error("worker exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg Config) error {
	slogLevel, err := cmdutil.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}
	opts := slog.HandlerOptions{
		Level: slogLevel,
	}
	logger := slog.New(telemetry.NewTraceContextHandler(slog.NewJSONHandler(os.Stdout, &opts))).With("component", "worker")
	logger.Info("Starting worker")

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		cancel()
	}()

	// Initialize OpenTelemetry. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	shutdownTelemetry, err := telemetry.Setup(ctx, "sbomscanner-worker", version.Version)
	if err != nil {
		return fmt.Errorf("initializing telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := shutdownTelemetry(shutdownCtx); err != nil {
			logger.Error("Telemetry shutdown error", "error", err)
		}
	}()

	config := ctrl.GetConfigOrDie()
	natsOpts := []nats.Option{
		nats.RootCAs(cfg.NatsCAFile),
		nats.ClientCert(cfg.NatsCertFile, cfg.NatsKeyFile),
	}

	if cfg.Init {
		logger = logger.With("task", "init")

		if err := cmdutil.WaitForStorageTypes(ctx, config, logger); err != nil {
			return fmt.Errorf("waiting for storage types: %w", err)
		}

		if err := cmdutil.WaitForJetStream(ctx, cfg.NatsURL, natsOpts, logger); err != nil {
			return fmt.Errorf("waiting for JetStream: %w", err)
		}

		logger.Info("Initialization tasks completed successfully.")
		return nil
	}

	if cfg.Mode == nodeMode && cfg.NodeName == "" {
		return errors.New("node name required in node mode")
	}

	nc, err := nats.Connect(cfg.NatsURL,
		natsOpts...,
	)
	if err != nil {
		return fmt.Errorf("connecting to NATS server %q: %w", cfg.NatsURL, err)
	}

	publisher, err := messaging.NewNatsPublisher(ctx, nc, logger)
	if err != nil {
		return fmt.Errorf("creating NATS publisher: %w", err)
	}

	scheme := scheme.Scheme
	if err = v1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("adding v1alpha1 to scheme: %w", err)
	}
	if err = storagev1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("adding storagev1alpha1 to scheme: %w", err)
	}
	if err = k8sscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("adding kubernetes to scheme: %w", err)
	}
	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}
	registryClientFactory := func(transport http.RoundTripper) *registry.Client {
		return registry.NewClient(transport, logger)
	}

	var scanMode messaging.HandlerRegistry
	durableName := "worker"
	switch cfg.Mode {
	case registryMode:
		scanMode = messaging.HandlerRegistry{
			handlers.CreateCatalogSubject: handlers.NewCreateCatalogHandler(registryClientFactory, k8sClient, scheme, publisher, cfg.InstallationNamespace, logger),
			handlers.GenerateSBOMSubject:  handlers.NewGenerateSBOMHandler(k8sClient, scheme, cfg.RunDir, cfg.TrivyJavaDBRepository, publisher, cfg.InstallationNamespace, logger),
			handlers.ScanSBOMSubject:      handlers.NewScanSBOMHandler(k8sClient, scheme, cfg.RunDir, cfg.TrivyDBRepository, cfg.TrivyJavaDBRepository, logger),
		}
	case nodeMode:
		scanMode = messaging.HandlerRegistry{
			handlers.GenerateNodeSBOMSubject + "." + cfg.NodeName: handlers.NewGenerateNodeSBOMHandler(k8sClient, scheme, cfg.RunDir, targetDir, cfg.TrivyJavaDBRepository, publisher, cfg.InstallationNamespace, logger),
			handlers.ScanNodeSBOMSubject + "." + cfg.NodeName:     handlers.NewNodeScanSBOMHandler(k8sClient, scheme, cfg.RunDir, cfg.TrivyDBRepository, cfg.TrivyJavaDBRepository, logger),
		}
		durableName = "worker-node-" + cfg.NodeName
	default:
		return fmt.Errorf("invalid scanning mode: %s", cfg.Mode)
	}

	var failureHandler messaging.FailureHandler
	switch cfg.Mode {
	case nodeMode:
		failureHandler = handlers.NewNodeScanJobFailureHandler(k8sClient, logger)
	default:
		failureHandler = handlers.NewScanJobFailureHandler(k8sClient, logger)
	}
	retryConfig := &messaging.RetryConfig{
		BaseDelay:   5 * time.Second,
		Jitter:      0.2,
		MaxAttempts: 5,
	}

	subscriber, err := messaging.NewNatsSubscriber(ctx, nc, durableName, scanMode, failureHandler, retryConfig, logger)
	if err != nil {
		return fmt.Errorf("creating NATS subscriber: %w", err)
	}

	healthServer := runHealthServer(logger)

	err = subscriber.Run(ctx)
	if err != nil {
		return fmt.Errorf("running worker subscriber: %w", err)
	}

	logger.Debug("Shutting down health server")
	if err := healthServer.Close(); err != nil {
		return fmt.Errorf("shutting down health check server: %w", err)
	}
	return nil
}

func runHealthServer(logger *slog.Logger) *http.Server {
	handler := &healthz.Handler{}

	mux := http.NewServeMux()
	mux.Handle("/livez/", http.StripPrefix("/livez", handler))
	mux.Handle("/readyz/", http.StripPrefix("/readyz", handler))

	server := &http.Server{
		Addr:        ":8081",
		Handler:     mux,
		ReadTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("Starting health check server", "addr", ":8081")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Health check server error", "error", err)
		}
	}()

	return server
}
