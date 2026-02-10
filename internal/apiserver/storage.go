package apiserver

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	basecompatibility "k8s.io/component-base/compatibility"
	baseversion "k8s.io/component-base/version"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/kubewarden/sbomscanner/api/storage/install"
	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/apiserver/admission"
	"github.com/kubewarden/sbomscanner/internal/storage"
	storageopenapi "github.com/kubewarden/sbomscanner/pkg/generated/openapi"
)

var (
	Scheme = runtime.NewScheme()
	Codecs = serializer.NewCodecFactory(Scheme)
)

func init() {
	install.Install(Scheme)
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
		&metav1.WatchEvent{},
	)
}

// StorageAPIServerConfig holds configuration options for the storage API server.
type StorageAPIServerConfig struct {
	// CertFile is the path to the TLS certificate file for serving HTTPS.
	CertFile string
	// KeyFile is the path to the TLS private key file for serving HTTPS.
	KeyFile string
	// MaxRequestBodyBytes is the limit on the request size that would be accepted and decoded in a write request.
	// 0 means no limit.
	MaxRequestBodyBytes int64
	// ServiceAccountNamespace is the namespace of the service account used by the admission plugins.
	ServiceAccountNamespace string
	// ServiceAccountName is the name of the service account used by the admission plugins.
	ServiceAccountName string
}

type StorageAPIServer struct {
	db                        *pgxpool.Pool
	watchers                  []manager.Runnable
	logger                    *slog.Logger
	server                    *genericapiserver.GenericAPIServer
	dynamicCertKeyPairContent *dynamiccertificates.DynamicCertKeyPairContent
}

func NewStorageAPIServer(db *pgxpool.Pool, nc *nats.Conn, logger *slog.Logger, cfg StorageAPIServerConfig) (*StorageAPIServer, error) { //nolint:funlen
	// Setup dynamic certs
	dynamicCertKeyPairContent, err := dynamiccertificates.NewDynamicServingContentFromFiles(
		"storage-serving-certs",
		cfg.CertFile,
		cfg.KeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating dynamic certificate content provider: %w", err)
	}

	// Setup recommended options with defaults
	recommendedOptions := genericoptions.NewRecommendedOptions(
		"/registry/sbomscanner.kubewarden.io",
		Codecs.LegacyCodec(v1alpha1.SchemeGroupVersion),
	)
	recommendedOptions.Etcd = nil
	recommendedOptions.Features.EnablePriorityAndFairness = false
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertKeyPairContent

	// Register admission plugins
	workloadScanReportValidationPlugin := admission.NewWorkloadScanReportValidation(
		cfg.ServiceAccountNamespace,
		cfg.ServiceAccountName,
	)
	workloadScanReportValidationPlugin.Register(recommendedOptions.Admission.Plugins)
	recommendedOptions.Admission.RecommendedPluginOrder = append(recommendedOptions.Admission.RecommendedPluginOrder,
		workloadScanReportValidationPlugin.GetName())
	recommendedOptions.Admission.EnablePlugins = append(
		recommendedOptions.Admission.EnablePlugins,
		workloadScanReportValidationPlugin.GetName(),
	)

	// Create server config
	serverConfig := genericapiserver.NewRecommendedConfig(Codecs)
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(
		storageopenapi.GetOpenAPIDefinitions,
		openapi.NewDefinitionNamer(Scheme),
	)
	serverConfig.OpenAPIConfig.Info.Title = "SBOM Scanner Storage"
	serverConfig.OpenAPIConfig.Info.Version = "v1alpha1"

	serverConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(
		storageopenapi.GetOpenAPIDefinitions,
		openapi.NewDefinitionNamer(Scheme),
	)
	serverConfig.OpenAPIV3Config.Info.Title = "SBOM Scanner Storage"
	serverConfig.OpenAPIV3Config.Info.Version = "v1alpha1"

	serverConfig.FeatureGate = utilfeature.DefaultFeatureGate
	serverConfig.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString(
		baseversion.DefaultKubeBinaryVersion,
		"",
		"",
	)

	serverConfig.RESTOptionsGetter = &RestOptionsGetter{}

	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, fmt.Errorf("error applying options to server config: %w", err)
	}

	serverConfig.MaxRequestBodyBytes = cfg.MaxRequestBodyBytes
	databaseChecker := newDatabaseChecker(db, logger)
	serverConfig.AddReadyzChecks(databaseChecker)

	// Create generic server
	genericServer, err := serverConfig.Complete().New("sbom-storage-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, fmt.Errorf("error creating generic server: %w", err)
	}

	// Create API group and storage
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(v1alpha1.GroupName, Scheme, metav1.ParameterCodec, Codecs)

	imageStore, imageWatchers, err := storage.NewImageStore(Scheme, serverConfig.RESTOptionsGetter, db, nc, logger)
	if err != nil {
		return nil, fmt.Errorf("error creating Image store: %w", err)
	}

	sbomStore, sbomWatchers, err := storage.NewSBOMStore(Scheme, serverConfig.RESTOptionsGetter, db, nc, logger)
	if err != nil {
		return nil, fmt.Errorf("error creating SBOM store: %w", err)
	}

	vulnerabilityReportStore, vulnerabilityReportWatchers, err := storage.NewVulnerabilityReportStore(
		Scheme,
		serverConfig.RESTOptionsGetter,
		db,
		nc,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating VulnerabilityReport store: %w", err)
	}

	workloadScanReportStore, workloadScanReportWatchers, err := storage.NewWorkloadScanReportStore(
		Scheme,
		serverConfig.RESTOptionsGetter,
		db,
		nc,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating WorkloadScanReport store: %w", err)
	}

	v1alpha1storage := map[string]rest.Storage{
		"images":               imageStore,
		"sboms":                sbomStore,
		"vulnerabilityreports": vulnerabilityReportStore,
		"workloadscanreports":  workloadScanReportStore,
	}
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	if err := genericServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("error installing API group: %w", err)
	}

	return &StorageAPIServer{
		db:                        db,
		watchers:                  slices.Concat(imageWatchers, sbomWatchers, vulnerabilityReportWatchers, workloadScanReportWatchers),
		logger:                    logger,
		server:                    genericServer,
		dynamicCertKeyPairContent: dynamicCertKeyPairContent,
	}, nil
}

func (s *StorageAPIServer) Start(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Starting storage server")

	s.logger.DebugContext(ctx, "Starting dynamic certificate controller")
	go s.dynamicCertKeyPairContent.Run(ctx, 1)

	g, ctx := errgroup.WithContext(ctx)
	for _, watcher := range s.watchers {
		g.Go(func() error {
			return watcher.Start(ctx)
		})
	}
	g.Go(func() error {
		if err := s.server.PrepareRun().RunWithContext(ctx); err != nil {
			return fmt.Errorf("error running server: %w", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		return fmt.Errorf("storage API server exited with error: %w", err)
	}

	return nil
}
