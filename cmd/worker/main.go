package main

import (
	"context"
	"flag"
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
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	"github.com/nats-io/nats.go"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

func main() {
	var natsURL string
	var natsCertFile string
	var natsKeyFile string
	var natsCAFile string
	var runDir string
	var trivyDBRepository string
	var trivyJavaDBRepository string
	var installationNamespace string
	var init bool
	var logLevel string

	flag.StringVar(&natsURL, "nats-url", "localhost:4222", "The URL of the NATS server.")
	flag.StringVar(&natsCertFile, "nats-cert-file", "/nats/tls/tls.crt", "The path to the NATS client certificate.")
	flag.StringVar(&natsKeyFile, "nats-key-file", "/nats/tls/tls.key", "The path to the NATS client key.")
	flag.StringVar(&natsCAFile, "nats-ca-file", "/nats/tls/ca.crt", "The path to the NATS CA certificate.")
	flag.StringVar(&runDir, "run-dir", "/var/run/worker", "Directory to store temporary files.")
	flag.StringVar(&trivyDBRepository, "trivy-db-repository", "public.ecr.aws/aquasecurity/trivy-db", "OCI repository to retrieve trivy-db.")
	flag.StringVar(&trivyJavaDBRepository, "trivy-java-db-repository", "public.ecr.aws/aquasecurity/trivy-java-db", "OCI repository to retrieve trivy-java-db.")
	flag.StringVar(&installationNamespace, "installation-namespace", "sbomscanner", "The namespace where sbomscanner is installed.")
	flag.BoolVar(&init, "init", false, "Run initialization tasks and exit.")
	flag.StringVar(&logLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.Parse()

	slogLevel, err := cmdutil.ParseLogLevel(logLevel)
	if err != nil {
		//nolint:sloglint // Use the global logger since the logger is not yet initialized
		slog.Error(
			"error initializing the logger",
			"error",
			err,
		)
		os.Exit(1)
	}
	opts := slog.HandlerOptions{
		Level: slogLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &opts)).With("component", "worker")
	logger.Info("Starting worker")

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		cancel()
	}()

	config := ctrl.GetConfigOrDie()
	natsOpts := []nats.Option{
		nats.RootCAs(natsCAFile),
		nats.ClientCert(natsCertFile, natsKeyFile),
	}

	if init {
		logger = logger.With("task", "init")

		if err := cmdutil.WaitForStorageTypes(ctx, config, logger); err != nil {
			logger.Error("Error waiting for storage types", "error", err)
			os.Exit(1)
		}

		if err := cmdutil.WaitForJetStream(ctx, natsURL, natsOpts, logger); err != nil {
			logger.Error("Error waiting for JetStream", "error", err)
			os.Exit(1)
		}

		logger.Info("Initialization tasks completed successfully.")
		os.Exit(0)
	}

	nc, err := nats.Connect(natsURL,
		natsOpts...,
	)
	if err != nil {
		logger.Error("Unable to connect to NATS server", "error", err, "natsURL", natsURL)
		os.Exit(1)
	}

	publisher, err := messaging.NewNatsPublisher(ctx, nc, logger)
	if err != nil {
		logger.Error("Error creating NATS publisher", "error", err)
		os.Exit(1)
	}

	scheme := scheme.Scheme
	if err = v1alpha1.AddToScheme(scheme); err != nil {
		logger.Error("Error adding v1alpha1 to scheme", "error", err)
		os.Exit(1)
	}
	if err = storagev1alpha1.AddToScheme(scheme); err != nil {
		logger.Error("Error adding storagev1alpha1 to scheme", "error", err)
		os.Exit(1)
	}
	if err = k8sscheme.AddToScheme(scheme); err != nil {
		logger.Error("Error adding kubernetes to scheme", "error", err)
		os.Exit(1)
	}
	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error("Error creating k8s client", "error", err)
		os.Exit(1)
	}
	registryClientFactory := func(transport http.RoundTripper) *registry.Client {
		return registry.NewClient(transport, logger)
	}

	registry := messaging.HandlerRegistry{
		handlers.CreateCatalogSubject: handlers.NewCreateCatalogHandler(registryClientFactory, k8sClient, scheme, publisher, installationNamespace, logger),
		handlers.GenerateSBOMSubject:  handlers.NewGenerateSBOMHandler(k8sClient, scheme, runDir, trivyJavaDBRepository, publisher, installationNamespace, logger),
		handlers.ScanSBOMSubject:      handlers.NewScanSBOMHandler(k8sClient, scheme, runDir, trivyDBRepository, trivyJavaDBRepository, logger),
	}
	failureHandler := handlers.NewScanJobFailureHandler(k8sClient, logger)
	retryConfig := &messaging.RetryConfig{
		BaseDelay:   5 * time.Second,
		Jitter:      0.2,
		MaxAttempts: 5,
	}

	subscriber, err := messaging.NewNatsSubscriber(ctx, nc, "worker", registry, failureHandler, retryConfig, logger)
	if err != nil {
		logger.Error("Error creating NATS subscriber", "error", err)
		os.Exit(1)
	}

	healthServer := runHealthServer(logger)

	err = subscriber.Run(ctx)
	if err != nil {
		logger.Error("Error running worker subscriber", "error", err)
		os.Exit(1)
	}

	logger.Debug("Shutting down health server")
	if err := healthServer.Close(); err != nil {
		logger.Error("Error shutting down health check server", "error", err)
		os.Exit(1)
	}
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
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Health check server error", "error", err)
		}
	}()

	return server
}
