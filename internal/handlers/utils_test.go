package handlers

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testTrivyDBRepository     = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-db:2"
	testTrivyJavaDBRepository = "ghcr.io/kubewarden/sbomscanner/test-assets/trivy-java-db:1"
)

const (
	authUser = "user"
	authPass = "password"
	htpasswd = "user:$2y$10$nTQigvLRGGHCBQwZB4MPPe2SA6GYG218uTe1ntHusNcEjLaAfBive" // user:password
)

const (
	imageRefSingleArch    = "ghcr.io/kubewarden/sbomscanner/test-assets/nginx:1.27.1"
	imageDigestSingleArch = "sha256:f41b7d70c5779beba4a570ca861f788d480156321de2876ce479e072fb0246f1"

	imageRefMultiArch                = "ghcr.io/kubewarden/sbomscanner/test-assets/golang:1.12-alpine"
	imageDigestLinuxAmd64MultiArch   = "sha256:1782cafde43390b032f960c0fad3def745fac18994ced169003cb56e9a93c028"
	imageDigestLinuxArmV6MultiArch   = "sha256:ea95bb81dab31807beac6c62824c048b1ee96b408f6097ea9dd0204e380f00b2"
	imageDigestLinuxArmV7MultiArch   = "sha256:ab389e320938f3bd42f45437d381fab28742dadcb892816236801e24a0bef804"
	imageDigestLinuxArm64V8MultiArch = "sha256:1c96d48d06d96929d41e76e8145eb182ce22983f5e3539a655ec2918604835d0"
	imageDigestLinux386MultiArch     = "sha256:d8801b3783dd4e4aee273c1a312cc265c832c7f264056d68e7ea73b8e1dd94b0"
	imageDigestLinuxPpc64leMultiArch = "sha256:216cb428a7a53a75ef7806ed1120c409253e3e65bddc6ae0c21f5cd2faf92324"
	imageDigestLinuxS390xMultiArch   = "sha256:f2475c61ab276da0882a9637b83b2a5710b289d6d80f3daedb71d4a8eaeb1686"

	imageRefMultiArchWithUnknownPlatform              = "ghcr.io/kubewarden/sbombscanner/test-assets/udash-front:v0.11.0"
	imageDigestLinuxAmd64MultiArchWithUnknownPlatform = "sha256:d2fabf8aca7ade7f2bcb63d0ef7966b697bed9482197d9906cf2578202d7f789"
	imageDigestLinuxArm64MultiArchWithUnknownPlatform = "sha256:6c8913ca09035b8730212b9a5b2f2ce451fe37a36b4e591e3d5af77b2eb60971"
)

// testMessage is a simple implementation of a message used for testing purposes.
type testMessage struct {
	data []byte
}

func (m *testMessage) Data() []byte {
	return m.data
}

func (m *testMessage) InProgress() error {
	return nil
}

// Custom keychain for the test registry
type staticKeychain struct {
	registry string
	auth     authn.Authenticator
}

func (k *staticKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if target.RegistryStr() == k.registry {
		return k.auth, nil
	}
	return authn.Anonymous, nil
}

// runTestRegistry starts a test container registry, optionally with authentication, and pushes the provided test images to it.
func runTestRegistry(ctx context.Context, testImages []name.Reference, private bool) (*registry.RegistryContainer, error) {
	opts := []testcontainers.ContainerCustomizer{}
	if private {
		opts = append(opts, registry.WithHtpasswd(htpasswd))
	}

	registryTestcontainer, err := registry.Run(
		ctx,
		registry.DefaultImage,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to start registry testcontainer: %w", err)
	}

	registryHostAddress, err := registryTestcontainer.HostAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get registry host address: %w", err)
	}

	keychains := []authn.Keychain{authn.DefaultKeychain}
	if private {
		_, err := registry.SetDockerAuthConfig(registryHostAddress, authUser, authPass)
		if err != nil {
			return nil, fmt.Errorf("unable to set docker auth config: %w", err)
		}

		// Add custom keychain for the test registry authentication
		keychains = append(keychains, &staticKeychain{
			registry: registryHostAddress,
			auth: &authn.Basic{
				Username: authUser,
				Password: authPass,
			},
		})
	}

	for _, image := range testImages {
		localImageRef := fmt.Sprintf("%s/%s:%s", registryHostAddress, image.Context().RepositoryStr(), image.Identifier())

		// Use crane.Copy to preserve multi-arch manifests
		if err := crane.Copy(image.String(), localImageRef, crane.WithAuthFromKeychain(authn.NewMultiKeychain(keychains...))); err != nil {
			return nil, fmt.Errorf("unable to copy image: %w", err)
		}
	}

	return registryTestcontainer, nil
}

// imageFactory creates a storagev1alpha1.Image object for testing purposes.
func imageFactory(registryURI, repository, tag, platform, digest string) *storagev1alpha1.Image {
	return &storagev1alpha1.Image{
		ObjectMeta: metav1.ObjectMeta{
			Name:      computeImageUID(fmt.Sprintf("%s/%s", registryURI, repository), tag, digest),
			Namespace: "default",
		},
		ImageMetadata: storagev1alpha1.ImageMetadata{
			Registry:    "test-registry",
			RegistryURI: registryURI,
			Repository:  repository,
			Tag:         tag,
			Platform:    platform,
			Digest:      digest,
		},
	}
}
