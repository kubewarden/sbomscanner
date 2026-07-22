package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/nats-io/nats.go"
	prombridge "go.opentelemetry.io/contrib/bridges/prometheus"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cmdutil"
	"github.com/kubewarden/sbomscanner/internal/controller"
	"github.com/kubewarden/sbomscanner/internal/messaging"
	"github.com/kubewarden/sbomscanner/internal/storage"
	"github.com/kubewarden/sbomscanner/internal/telemetry"
	"github.com/kubewarden/sbomscanner/internal/version"
	internalwebhook "github.com/kubewarden/sbomscanner/internal/webhook"
	webhookv1alpha1 "github.com/kubewarden/sbomscanner/internal/webhook/v1alpha1"
	// +kubebuilder:scaffold:imports
)

type Config struct {
	MetricsAddr             string
	ProbeAddr               string
	PprofAddr               string
	EnableLeaderElection    bool
	SecureMetrics           bool
	EnableHTTP2             bool
	NatsURL                 string
	NatsCertFile            string
	NatsKeyFile             string
	NatsCAFile              string
	ServiceAccountNamespace string
	ServiceAccountName      string
	Init                    bool
	LogLevel                string
	WorkloadScan            bool
	NodeScan                bool
}

func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.MetricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&cfg.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&cfg.PprofAddr, "pprof-bind-address", "0", "The address the pprof endpoint binds to. Leave as 0 to disable the pprof service.")
	flag.BoolVar(&cfg.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&cfg.SecureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&cfg.EnableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&cfg.NatsURL, "nats-url", "localhost:4222", "The URL of the NATS server")
	flag.StringVar(&cfg.NatsCertFile, "nats-cert-file", "/nats/tls/tls.crt", "The path to the NATS client certificate.")
	flag.StringVar(&cfg.NatsKeyFile, "nats-key-file", "/nats/tls/tls.key", "The path to the NATS client key.")
	flag.StringVar(&cfg.NatsCAFile, "nats-ca-file", "/nats/tls/ca.crt", "The path to the NATS CA certificate.")
	flag.StringVar(&cfg.ServiceAccountNamespace, "service-account-namespace", "sbomscanner", "The namespace of the service account used by the controller. This is used in validating webhooks.")
	flag.StringVar(&cfg.ServiceAccountName, "service-account-name", "sbomscanner-controller", "The name of the service account used by the controller. This is used in validating webhooks.")
	flag.BoolVar(&cfg.Init, "init", false, "Run initialization tasks and exit.")
	flag.StringVar(&cfg.LogLevel, "log-level", slog.LevelInfo.String(), "Log level")
	flag.BoolVar(&cfg.WorkloadScan, "workloadscan", true, "Enable workload scan controllers.")
	flag.BoolVar(&cfg.NodeScan, "nodescan", true, "Enable node scan controllers.")

	flag.Parse()
	return cfg
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		//nolint:sloglint // No structured logger is available at this scope: run() owns the logger lifecycle.
		slog.Error("controller exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg Config) error {
	var tlsOpts []func(*tls.Config)

	slogLevel, err := cmdutil.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}
	opts := slog.HandlerOptions{
		Level: slogLevel,
	}
	slogHandler := telemetry.NewTraceContextHandler(slog.NewJSONHandler(os.Stdout, &opts))
	slogger := slog.New(slogHandler)
	logger := logr.FromSlogHandler(slogHandler).WithValues("component", "controller")
	ctrl.SetLogger(logger)
	setupLog := logger.WithName("setup")

	signalHandler := ctrl.SetupSignalHandler()

	// Initialize OpenTelemetry. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	// The Prometheus bridge exports the controller-runtime metrics
	// (controller_runtime_*, workqueue_*, rest_client_*, ...) over OTLP alongside our own;
	// the controller-runtime metrics server keeps serving them for users on legacy Prometheus pull.
	shutdownTelemetry, err := telemetry.Setup(signalHandler, "sbomscanner-controller", version.Version,
		telemetry.WithMetricProducer(prombridge.NewMetricProducer(prombridge.WithGatherer(ctrlmetrics.Registry))),
	)
	if err != nil {
		return fmt.Errorf("initializing telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(shutdownCtx); err != nil {
			setupLog.Error(err, "telemetry shutdown error")
		}
	}()

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !cfg.EnableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookInstrumentation, err := internalwebhook.NewInstrumentation(
		telemetry.Tracer("internal/webhook"),
		telemetry.Meter("internal/webhook"),
	)
	if err != nil {
		return fmt.Errorf("creating webhook instrumentation: %w", err)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   cfg.MetricsAddr,
		SecureServing: cfg.SecureMetrics,
		// TODO(user): TLSOpts is used to allow configuring the TLS config used for the server. If certificates are
		// not provided, self-signed certificates will be generated by default. This option is not recommended for
		// production environments as self-signed certificates do not offer the same level of trust and security
		// as certificates issued by a trusted Certificate Authority (CA). The primary risk is potentially allowing
		// unauthorized access to sensitive metrics data. Consider replacing with CertDir, CertName, and KeyName
		// to provide certificates, ensuring the server communicates using trusted and secure certificates.
		TLSOpts: tlsOpts,
	}

	if cfg.SecureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(storagev1alpha1.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme

	natsOpts := []nats.Option{
		nats.RootCAs(cfg.NatsCAFile),
		nats.ClientCert(cfg.NatsCertFile, cfg.NatsKeyFile),
	}

	// If the init flag is set, run initialization tasks and exit.
	if cfg.Init {
		slogger = slogger.With("task", "init")

		if err := cmdutil.WaitForStorageTypes(signalHandler, ctrl.GetConfigOrDie(), slogger); err != nil {
			return fmt.Errorf("waiting for storage types: %w", err)
		}

		if err := cmdutil.WaitForJetStream(signalHandler, cfg.NatsURL, natsOpts, slogger); err != nil {
			return fmt.Errorf("waiting for JetStream: %w", err)
		}

		slogger.Info("Initialization tasks completed successfully.")
		return nil
	}

	nc, err := nats.Connect(cfg.NatsURL, natsOpts...)
	if err != nil {
		return fmt.Errorf("connecting to NATS server %q: %w", cfg.NatsURL, err)
	}

	publisher, err := messaging.NewNatsPublisher(signalHandler, nc, slogger)
	if err != nil {
		return fmt.Errorf("creating NATS publisher: %w", err)
	}

	controllerInstrumentation, err := controller.NewInstrumentation(
		telemetry.Tracer("internal/controller"),
		telemetry.Meter("internal/controller"),
	)
	if err != nil {
		return fmt.Errorf("creating controller instrumentation: %w", err)
	}

	cacheByObject := buildCacheByObject(cfg)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		PprofBindAddress:       cfg.PprofAddr,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       "0cc30ed1.sbomscanner.kubewarden.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
		Cache: cache.Options{
			DefaultTransform: cache.TransformStripManagedFields(),
			ByObject:         cacheByObject,
		},
		Controller: config.Controller{
			ReconciliationTimeout: 90 * time.Second,
		},
	})
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	if err := controller.SetupIndexer(signalHandler, mgr); err != nil {
		return fmt.Errorf("setting up indexer: %w", err)
	}

	if err := (&controller.ScanJobReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Publisher:       publisher,
		Instrumentation: controllerInstrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating ScanJob controller: %w", err)
	}

	if err := (&controller.VulnerabilityReportReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Instrumentation: controllerInstrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating VulnerabilityReport controller: %w", err)
	}

	if err := (&controller.RegistryScanRunner{
		Client:          mgr.GetClient(),
		Instrumentation: controllerInstrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating RegistryScanRunner: %w", err)
	}

	if cfg.WorkloadScan {
		if err := setupWorkloadScanControllers(mgr, controllerInstrumentation); err != nil {
			return err
		}
	}

	if cfg.NodeScan {
		if err := setupNodeScanControllers(mgr, publisher, controllerInstrumentation); err != nil {
			return err
		}
	}

	// Node scan webhooks are registered even when node scan is disabled, so that
	// requests to node scan resources are still validated.
	if err = webhookv1alpha1.SetupNodeScanConfigurationWebhookWithManager(mgr, webhookInstrumentation); err != nil {
		return fmt.Errorf("creating NodeScanConfiguration webhook: %w", err)
	}

	if err = webhookv1alpha1.SetupNodeScanJobWebhookWithManager(mgr, webhookInstrumentation); err != nil {
		return fmt.Errorf("creating NodeScanJob webhook: %w", err)
	}

	if err = webhookv1alpha1.SetupRegistryWebhookWithManager(mgr, cfg.ServiceAccountNamespace, cfg.ServiceAccountName, webhookInstrumentation); err != nil {
		return fmt.Errorf("creating Registry webhook: %w", err)
	}

	if err = webhookv1alpha1.SetupScanJobWebhookWithManager(mgr, webhookInstrumentation); err != nil {
		return fmt.Errorf("creating ScanJob webhook: %w", err)
	}

	if err = webhookv1alpha1.SetupWorkloadScanConfigurationWebhookWithManager(mgr, webhookInstrumentation); err != nil {
		return fmt.Errorf("creating WorkloadScanConfiguration webhook: %w", err)
	}

	// +kubebuilder:scaffold:builder

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("adding healthz check: %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("adding readyz check: %w", err)
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(signalHandler); err != nil {
		return fmt.Errorf("running manager: %w", err)
	}
	return nil
}

func setupWorkloadScanControllers(mgr ctrl.Manager, instrumentation *controller.Instrumentation) error {
	if err := (&controller.WorkloadScanReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating WorkloadScan controller: %w", err)
	}

	if err := (&controller.ImageWorkloadScanReconciler{
		Client:          mgr.GetClient(),
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating ImageWorkloadScan controller: %w", err)
	}
	return nil
}

func setupNodeScanControllers(mgr ctrl.Manager, publisher *messaging.NatsPublisher, instrumentation *controller.Instrumentation) error {
	if err := (&controller.NodeScanRunner{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating NodeScanRunner: %w", err)
	}

	if err := (&controller.NodeScanReconciler{
		Client:          mgr.GetClient(),
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating NodeScan controller: %w", err)
	}

	if err := (&controller.NodeScanConfigurationReconciler{
		Client:          mgr.GetClient(),
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating NodeScanConfiguration controller: %w", err)
	}

	if err := (&controller.NodeScanJobReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Publisher:       publisher,
		Instrumentation: instrumentation,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("creating NodeScanJob controller: %w", err)
	}
	return nil
}

func buildCacheByObject(cfg Config) map[client.Object]cache.ByObject {
	cacheByObject := map[client.Object]cache.ByObject{
		&metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: storagev1alpha1.SchemeGroupVersion.String(),
				Kind:       "VulnerabilityReport",
			},
		}: {
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		},
		&metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       "Namespace",
			},
		}: {
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		},
	}

	if cfg.WorkloadScan {
		cacheByObject[&storagev1alpha1.Image{}] = cache.ByObject{
			Label:     labels.SelectorFromSet(labels.Set{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue}),
			Transform: storage.TransformStripImage,
		}
		cacheByObject[&storagev1alpha1.WorkloadScanReport{}] = cache.ByObject{
			Transform: storage.TransformStripWorkloadScanReport,
		}
		cacheByObject[&corev1.Pod{}] = cache.ByObject{
			Transform: controller.TransformStripPod,
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		}
		cacheByObject[&metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "ReplicaSet",
			},
		}] = cache.ByObject{
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		}
		cacheByObject[&metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: batchv1.SchemeGroupVersion.String(),
				Kind:       "Job",
			},
		}] = cache.ByObject{
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		}
	}

	if cfg.NodeScan {
		cacheByObject[&corev1.Node{}] = cache.ByObject{
			Transform: controller.TransformStripNode,
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		}
		cacheByObject[&storagev1alpha1.NodeSBOM{}] = cache.ByObject{
			Transform: storage.TransformStripNodeSBOM,
			// Read-only
			UnsafeDisableDeepCopy: new(true),
		}
	}

	return cacheByObject
}
