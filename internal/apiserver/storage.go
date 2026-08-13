package apiserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	mutatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/mutating"
	validatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	basecompatibility "k8s.io/component-base/compatibility"
	baseversion "k8s.io/component-base/version"

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
	watchers                  []storage.Watcher
	logger                    *slog.Logger
	server                    *genericapiserver.GenericAPIServer
	dynamicCertKeyPairContent *dynamiccertificates.DynamicCertKeyPairContent
}

func NewStorageAPIServer(
	db *pgxpool.Pool,
	nc *nats.Conn,
	instrumentation *Instrumentation,
	storeInstrumentation *storage.Instrumentation,
	logger *slog.Logger,
	cfg StorageAPIServerConfig,
) (*StorageAPIServer, error) {
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
	// The API extension server doesn't use admission policies; disable the plugins.
	recommendedOptions.Admission.DisablePlugins = append(
		recommendedOptions.Admission.DisablePlugins,
		mutatingadmissionpolicy.PluginName,
		validatingadmissionpolicy.PluginName,
	)

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

	// The stores are built before the handler chain: the duration filter needs
	// the served resource names to bound the resource metric label.
	v1alpha1storage, watchers, err := buildStores(serverConfig.RESTOptionsGetter, db, nc, storeInstrumentation, logger)
	if err != nil {
		return nil, err
	}

	serverConfig.BuildHandlerChainFunc = buildHandlerChain(instrumentation, sets.KeySet(v1alpha1storage))

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
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	if err := genericServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("error installing API group: %w", err)
	}

	return &StorageAPIServer{
		db:                        db,
		watchers:                  watchers,
		logger:                    logger,
		server:                    genericServer,
		dynamicCertKeyPairContent: dynamicCertKeyPairContent,
	}, nil
}

// buildHandlerChain wraps the default handler chain with otelhttp as the outermost handler,
// so the server span covers the whole request and the trace context is extracted first.
// Machinery requests (probes, discovery, OpenAPI aggregation) produce no spans.
func buildHandlerChain(instrumentation *Instrumentation, servedResources sets.Set[string]) func(http.Handler, *genericapiserver.Config) http.Handler {
	return func(apiHandler http.Handler, config *genericapiserver.Config) http.Handler {
		// The duration filter sits inside the default chain, where the request
		// info filter has already resolved the Kubernetes verb and resource.
		handler := instrumentation.requestDurationFilter(apiHandler, config.LongRunningFunc, servedResources)
		return otelhttp.NewHandler(
			genericapiserver.DefaultBuildHandlerChain(handler, config),
			"APIServer",
			otelhttp.WithFilter(func(req *http.Request) bool {
				return !isMachineryRequest(req)
			}),
		)
	}
}

// buildStores creates the REST store and the watchers of every served resource.
func buildStores(
	optsGetter generic.RESTOptionsGetter,
	db *pgxpool.Pool,
	nc *nats.Conn,
	instrumentation *storage.Instrumentation,
	logger *slog.Logger,
) (map[string]rest.Storage, []storage.Watcher, error) {
	imageStore, imageWatchers, err := storage.NewImageStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Image store: %w", err)
	}

	sbomStore, sbomWatchers, err := storage.NewSBOMStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating SBOM store: %w", err)
	}

	vulnerabilityReportStore, vulnerabilityReportWatchers, err := storage.NewVulnerabilityReportStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating VulnerabilityReport store: %w", err)
	}

	workloadScanReportStore, workloadScanReportWatchers, err := storage.NewWorkloadScanReportStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating WorkloadScanReport store: %w", err)
	}

	nodeSBOMStore, nodeSBOMWatchers, err := storage.NewNodeSBOMStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating NodeSBOM store: %w", err)
	}

	nodeVulnerabilityReportStore, nodeVulnerabilityReportWatchers, err := storage.NewNodeVulnerabilityReportStore(Scheme, optsGetter, db, nc, instrumentation, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating NodeVulnerabilityReport store: %w", err)
	}

	stores := map[string]rest.Storage{
		"images":                   imageStore,
		"sboms":                    sbomStore,
		"vulnerabilityreports":     vulnerabilityReportStore,
		"workloadscanreports":      workloadScanReportStore,
		"nodesboms":                nodeSBOMStore,
		"nodevulnerabilityreports": nodeVulnerabilityReportStore,
	}
	watchers := slices.Concat(imageWatchers, sbomWatchers, vulnerabilityReportWatchers, workloadScanReportWatchers, nodeSBOMWatchers, nodeVulnerabilityReportWatchers)

	return stores, watchers, nil
}

func (s *StorageAPIServer) Start(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Starting storage server")

	s.logger.DebugContext(ctx, "Starting dynamic certificate controller")
	go s.dynamicCertKeyPairContent.Run(ctx, 1)

	for _, watcher := range s.watchers {
		if err := watcher.Setup(ctx); err != nil {
			return fmt.Errorf("error setting up watcher: %w", err)
		}
	}

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
