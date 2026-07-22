package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	mcpserver "github.com/kubewarden/sbomscanner/internal/mcp"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
	"github.com/kubewarden/sbomscanner/internal/version"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

type config struct {
	Addr           string
	CredentialsDir string
	CertFile       string
	KeyFile        string
	ReadOnly       bool
	LogLevel       string
	DisableTLS     bool
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.Addr, "addr", ":8222", "HTTP listen address.")
	flag.StringVar(&cfg.CredentialsDir, "credentials-dir", "/etc/mcp/credentials", "Directory containing username and password files.")
	flag.StringVar(&cfg.CertFile, "cert-file", "/tls/tls.crt", "Path to TLS certificate file.")
	flag.StringVar(&cfg.KeyFile, "key-file", "/tls/tls.key", "Path to TLS private key file.")
	flag.BoolVar(&cfg.ReadOnly, "read-only", false, "Run in read-only mode (no create/update/delete tools).")
	flag.StringVar(&cfg.LogLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.BoolVar(&cfg.DisableTLS, "disable-tls", false, "Disable TLS and serve plain HTTP.")
	flag.Parse()
	return cfg
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		//nolint:sloglint // No structured logger is available at this scope: run() owns the logger lifecycle.
		slog.Error("mcp exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	slogLevel, err := cmdutil.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		//nolint:sloglint // Use the global logger since the logger is not yet initialized
		slog.Error(
			"Error parsing log level, using default",
			"error", err, "default", slog.LevelInfo.String())
		slogLevel = slog.LevelInfo
	}

	slogHandler := telemetry.NewTraceContextHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	}))
	logger := slog.New(slogHandler).With("component", "mcp")

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		cancel()
	}()

	// Initialize OpenTelemetry. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	shutdownTelemetry, err := telemetry.Setup(ctx, "sbomscanner-mcp", version.Version)
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

	s := scheme.Scheme
	if err := v1alpha1.AddToScheme(s); err != nil {
		return fmt.Errorf("adding v1alpha1 to scheme: %w", err)
	}
	if err := storagev1alpha1.AddToScheme(s); err != nil {
		return fmt.Errorf("adding storagev1alpha1 to scheme: %w", err)
	}
	if err := k8sscheme.AddToScheme(s); err != nil {
		return fmt.Errorf("adding kubernetes to scheme: %w", err)
	}

	config := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(config, client.Options{Scheme: s})
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}

	server := mcpserver.NewServer(k8sClient, logger, cfg.ReadOnly)
	if err := server.Run(ctx, cfg.Addr, cfg.CredentialsDir, cfg.CertFile, cfg.KeyFile, cfg.DisableTLS); err != nil {
		return fmt.Errorf("running MCP server: %w", err)
	}
	return nil
}
