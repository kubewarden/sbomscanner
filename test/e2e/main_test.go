package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
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

// Trivy in the worker pods downloads the VEX repositories from GitHub.
// Without a token, GitHub allows only 60 requests per hour from one IP address,
// and the scans time out.
// When GITHUB_TOKEN is set, the e2e setup stores it in a Secret,
// and gives it to the worker pods through the extraEnv chart values.
const (
	githubTokenEnv        = "GITHUB_TOKEN"
	githubTokenSecretName = "e2e-github-token"
	githubTokenSecretKey  = "token"
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

			installArgs := []string{
				"--set", "controller.image.tag=latest",
				"--set", "storage.image.tag=latest",
				"--set", "worker.image.tag=latest",
				"--set", "controller.logLevel=debug",
				"--set", "storage.logLevel=debug",
				"--set", "worker.logLevel=debug",
				// Skip the default VEXHubs, so that the scans do not download them from GitHub.
				// The aquasecurity org has an IP allow list that rejects requests with a token.
				// TestRegistryScan creates its own VEXHub.
				"--set", "controller.defaultVEXHubResources=false",
			}

			// Give the GitHub token to the worker pods through a Secret.
			// This keeps the token value out of the Helm arguments.
			if token := os.Getenv(githubTokenEnv); token != "" {
				if err = createGitHubTokenSecret(ctx, cfg, token); err != nil {
					return ctx, err
				}
				installArgs = append(installArgs, githubTokenHelmArgs()...)
			}

			// Install SBOMscanner
			err = manager.RunInstall(helm.WithName(releaseName),
				helm.WithNamespace(namespace),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithArgs(installArgs...),
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

	// Export the cluster logs first.
	// The uninstall deletes the worker pods, and their logs must be in the exported logs.
	// Each step is a separate Finish registration.
	// The framework stops one registration at its first error,
	// but it logs the error and runs the next registration.
	// So a failed export or uninstall does not skip the cluster deletion.
	testenv.Finish(envfuncs.ExportClusterLogs(kindClusterName, "./logs"))
	testenv.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		manager := helm.New(cfg.KubeconfigFile())
		err := manager.RunUninstall(
			helm.WithName(releaseName),
			helm.WithNamespace(namespace),
		)
		if err != nil {
			return ctx, fmt.Errorf("failed to uninstall sbomscanner: %w", err)
		}

		return ctx, nil
	})
	testenv.Finish(envfuncs.DestroyCluster(kindClusterName))

	os.Exit(testenv.Run(m))
}

// githubTokenHelmArgs returns the Helm arguments that give the GITHUB_TOKEN env var
// from the token Secret to the worker and worker-node pods.
// The arguments contain only the Secret reference, never the token value.
func githubTokenHelmArgs() []string {
	var args []string
	for _, workload := range []string{"worker", "workerNode"} {
		args = append(args,
			"--set", workload+".extraEnv[0].name="+githubTokenEnv,
			"--set", workload+".extraEnv[0].valueFrom.secretKeyRef.name="+githubTokenSecretName,
			"--set", workload+".extraEnv[0].valueFrom.secretKeyRef.key="+githubTokenSecretKey,
		)
	}

	return args
}

// createGitHubTokenSecret stores the token in a Secret in the sbomscanner namespace.
// The returned error never contains the token value.
func createGitHubTokenSecret(ctx context.Context, cfg *envconf.Config, token string) error {
	secret := &corev1.Secret{
		Name:      githubTokenSecretName,
		Namespace: namespace,
		Type:      corev1.SecretTypeOpaque,
		Data:      map[string][]byte{githubTokenSecretKey: []byte(token)},
	}
	if err := cfg.Client().Resources(namespace).Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create the %s/%s Secret: %w", namespace, githubTokenSecretName, err)
	}

	return nil
}
