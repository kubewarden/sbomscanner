package apiserver

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
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

	"github.com/kubewarden/sbomscanner/api/storage/install"
	"github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
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

type StorageAPIServer struct {
	db                        *pgxpool.Pool
	logger                    *slog.Logger
	server                    *genericapiserver.GenericAPIServer
	dynamicCertKeyPairContent *dynamiccertificates.DynamicCertKeyPairContent
}

func NewStorageAPIServer(db *pgxpool.Pool, certFile, keyFile string, logger *slog.Logger) (*StorageAPIServer, error) {
	// Setup dynamic certs
	dynamicCertKeyPairContent, err := dynamiccertificates.NewDynamicServingContentFromFiles(
		"storage-serving-certs",
		certFile,
		keyFile,
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
	recommendedOptions.Admission = nil
	recommendedOptions.Features.EnablePriorityAndFairness = false
	recommendedOptions.SecureServing.ServerCert.GeneratedCert = dynamicCertKeyPairContent

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

	// Disable WatchList for now
	// TODO: remove this once we implement WatchList in the storage.
	mutableFeatureGate := utilfeature.DefaultMutableFeatureGate
	if err = mutableFeatureGate.Set("WatchList=false"); err != nil {
		return nil, fmt.Errorf("failed to set feature gate: %w", err)
	}
	serverConfig.FeatureGate = mutableFeatureGate
	serverConfig.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString(
		baseversion.DefaultKubeBinaryVersion,
		"",
		"",
	)

	serverConfig.RESTOptionsGetter = &RestOptionsGetter{}

	if err := recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, fmt.Errorf("error applying options to server config: %w", err)
	}

	// Create generic server
	genericServer, err := serverConfig.Complete().New("sbom-storage-apiserver", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, fmt.Errorf("error creating generic server: %w", err)
	}

	// Create API group and storage
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(v1alpha1.GroupName, Scheme, metav1.ParameterCodec, Codecs)

	imageStore, err := storage.NewImageStore(Scheme, serverConfig.RESTOptionsGetter, db, logger)
	if err != nil {
		return nil, fmt.Errorf("error creating Image store: %w", err)
	}

	sbomStore, err := storage.NewSBOMStore(Scheme, serverConfig.RESTOptionsGetter, db, logger)
	if err != nil {
		return nil, fmt.Errorf("error creating SBOM store: %w", err)
	}

	vulnerabilityReportStore, err := storage.NewVulnerabilityReport(
		Scheme,
		serverConfig.RESTOptionsGetter,
		db,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating VulnerabilityReport store: %w", err)
	}

	v1alpha1storage := map[string]rest.Storage{
		"images":               imageStore,
		"sboms":                sbomStore,
		"vulnerabilityreports": vulnerabilityReportStore,
	}
	apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

	if err := genericServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("error installing API group: %w", err)
	}

	return &StorageAPIServer{
		db:                        db,
		logger:                    logger,
		server:                    genericServer,
		dynamicCertKeyPairContent: dynamicCertKeyPairContent,
	}, nil
}

func (s *StorageAPIServer) Start(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Starting storage server")

	s.logger.DebugContext(ctx, "Starting dynamic certificate controller")
	go s.dynamicCertKeyPairContent.Run(ctx, 1)

	if err := s.server.PrepareRun().RunWithContext(ctx); err != nil {
		return fmt.Errorf("error running server: %w", err)
	}

	return nil
}
