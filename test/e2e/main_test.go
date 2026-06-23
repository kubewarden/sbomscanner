package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testenv              env.Environment
	kindClusterName      string
	namespace            = "sbomscanner"
	workerImage          = "ghcr.io/kubewarden/sbomscanner/worker:latest"
	controllerImage      = "ghcr.io/kubewarden/sbomscanner/controller:latest"
	storageImage         = "ghcr.io/kubewarden/sbomscanner/storage:latest"
	certManagerNamespace = "cert-manager"
	certManagerVersion   = "v1.18.2"
	cnpgNamespace        = "cnpg-system"
	releaseName          = "sbomscanner"
	chartPath            = "../../charts/sbomscanner"
)

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testenv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("sbomscanner-e2e-cluster", 32)

	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace),
		envfuncs.LoadImageToCluster(kindClusterName, workerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, controllerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, storageImage, "--verbose", "--mode", "direct"),
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			manager := helm.New(cfg.KubeconfigFile())

			// Add the Jetstack Helm repository for cert-manager
			err := manager.RunRepo(helm.WithArgs(
				"add",
				"jetstack",
				"https://charts.jetstack.io",
				"--force-update"),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to add cert-manager helm repo: %w", err)
			}

			// Install cert-manager
			err = manager.RunInstall(
				helm.WithName("cert-manager"),
				helm.WithChart("jetstack/cert-manager"),
				helm.WithWait(),
				helm.WithArgs("--version", certManagerVersion),
				helm.WithArgs("--set", "installCRDs=true"),
				helm.WithNamespace(certManagerNamespace),
				helm.WithArgs("--create-namespace"),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install cert-manager: %w", err)
			}

			// Add the CNPG repository
			err = manager.RunRepo(helm.WithArgs(
				"add",
				"cnpg",
				"https://cloudnative-pg.github.io/charts",
				"--force-update"),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to add cnpg helm repo: %w", err)
			}

			// Install the CNPG operator
			err = manager.RunInstall(
				helm.WithName("cnpg"),
				helm.WithChart("cnpg/cloudnative-pg"),
				helm.WithWait(),
				helm.WithNamespace(cnpgNamespace),
				helm.WithArgs("--create-namespace"),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install cnpg operator: %w", err)
			}

			// Install SBOMscanner
			err = manager.RunInstall(helm.WithName(releaseName),
				helm.WithNamespace(namespace),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithArgs("--set", "controller.image.tag=latest",
					"--set", "storage.image.tag=latest",
					"--set", "worker.image.tag=latest",
					"--set", "controller.logLevel=debug",
					"--set", "storage.logLevel=debug",
					"--set", "worker.logLevel=debug",
				),
				helm.WithTimeout("3m"))
			if err != nil {
				return ctx, fmt.Errorf("failed to install sbomscanner: %w", err)
			}

			// Register schemes
			err = storagev1alpha1.AddToScheme(cfg.Client().Resources(namespace).GetScheme())
			if err != nil {
				return ctx, fmt.Errorf("failed to add storage scheme: %w", err)
			}

			err = v1alpha1.AddToScheme(cfg.Client().Resources(namespace).GetScheme())
			if err != nil {
				return ctx, fmt.Errorf("failed to add v1alpha1 scheme: %w", err)
			}

			return ctx, nil
		},
	)

	testenv.Finish(
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunUninstall(
				helm.WithName(releaseName),
				helm.WithNamespace(namespace),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to uninstall sbomscanner: %w", err)
			}

			return ctx, nil
		},
		envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		envfuncs.DestroyCluster(kindClusterName),
	)

	os.Exit(testenv.Run(m))
}
