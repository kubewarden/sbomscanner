package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	mcpserver "github.com/kubewarden/sbomscanner/internal/mcp"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

func main() {
	var addr string
	var credentialsDir string
	var certFile string
	var keyFile string
	var readOnly bool
	var logLevel string
	var disableTLS bool

	flag.StringVar(&addr, "addr", ":8222", "HTTP listen address.")
	flag.StringVar(&credentialsDir, "credentials-dir", "/etc/mcp/credentials", "Directory containing username and password files.")
	flag.StringVar(&certFile, "cert-file", "/tls/tls.crt", "Path to TLS certificate file.")
	flag.StringVar(&keyFile, "key-file", "/tls/tls.key", "Path to TLS private key file.")
	flag.BoolVar(&readOnly, "read-only", false, "Run in read-only mode (no create/update/delete tools).")
	flag.StringVar(&logLevel, "log-level", slog.LevelInfo.String(), "Log level.")
	flag.BoolVar(&disableTLS, "disable-tls", false, "Disable TLS and serve plain HTTP.")
	flag.Parse()

	slogLevel, err := cmdutil.ParseLogLevel(logLevel)
	if err != nil {
		//nolint:sloglint // Use the global logger since the logger is not yet initialized
		slog.Error(
			"Error parsing log level, using default",
			"error", err, "default", slog.LevelInfo.String())
		slogLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	})).With("component", "mcp")

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		cancel()
	}()

	s := scheme.Scheme
	if err := v1alpha1.AddToScheme(s); err != nil {
		logger.Error("Error adding v1alpha1 to scheme", "error", err)
		os.Exit(1)
	}
	if err := storagev1alpha1.AddToScheme(s); err != nil {
		logger.Error("Error adding storagev1alpha1 to scheme", "error", err)
		os.Exit(1)
	}
	if err := k8sscheme.AddToScheme(s); err != nil {
		logger.Error("Error adding kubernetes to scheme", "error", err)
		os.Exit(1)
	}

	config := ctrl.GetConfigOrDie()
	k8sClient, err := client.New(config, client.Options{Scheme: s})
	if err != nil {
		logger.Error("Error creating k8s client", "error", err)
		os.Exit(1)
	}

	server := mcpserver.NewServer(k8sClient, logger, readOnly)
	if err := server.Run(ctx, addr, credentialsDir, certFile, keyFile, disableTLS); err != nil {
		logger.Error("Error running MCP server", "error", err)
		os.Exit(1)
	}
}
