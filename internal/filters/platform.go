package filters

import (
	"slices"

	cranev1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// IsPlatformAllowed reports if the platform of an image is allowed by the registry filter.
//
// A nil platform is not allowed. Image index entries must have a platform. OCI artifacts
// that reuse the image index format (for example, cosign referrers) have entries without
// a platform.
func IsPlatformAllowed(platform *cranev1.Platform, allowedPlatforms []v1alpha1.Platform) bool {
	if platform == nil {
		return false
	}

	// Images can contain "unknown/unknown" layers, which usually contain attestations.
	// See https://docs.docker.com/build/metadata/attestations/attestation-storage/
	// We need to skip these images, as they cannot be scanned.
	if platform.OS == "unknown" && platform.Architecture == "unknown" {
		return false
	}

	// If no platform is specified in the Registry CR,
	// we assume the user wants to scan all the platforms.
	if len(allowedPlatforms) == 0 {
		return true
	}

	return slices.ContainsFunc(allowedPlatforms, func(allowedPlatform v1alpha1.Platform) bool {
		if allowedPlatform.Variant == "" {
			return platform.OS == allowedPlatform.OS && platform.Architecture == allowedPlatform.Architecture
		}
		return platform.OS == allowedPlatform.OS && platform.Architecture == allowedPlatform.Architecture && platform.Variant == allowedPlatform.Variant
	})
}
