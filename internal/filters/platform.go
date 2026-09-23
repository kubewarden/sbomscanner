package filters

import (
	"slices"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

// IsPlatformAllowed verify if the platform of the image is allowed by the registry filter.
func IsPlatformAllowed(os, architecture, variant string, allowedPlatforms []v1alpha1.Platform) bool {
	// Images can contain "unknown/unknown" layers, which usually contain attestations.
	// See https://docs.docker.com/build/metadata/attestations/attestation-storage/
	// We need to skip these images, as they cannot be scanned.
	if os == "unknown" && architecture == "unknown" {
		return false
	}

	// If no platform is specified in the Registry CR,
	// we assume the user wants to scan all the platforms.
	if len(allowedPlatforms) == 0 {
		return true
	}

	return slices.ContainsFunc(allowedPlatforms, func(allowedPlatform v1alpha1.Platform) bool {
		if allowedPlatform.Variant == "" {
			return os == allowedPlatform.OS && architecture == allowedPlatform.Architecture
		}
		return os == allowedPlatform.OS && architecture == allowedPlatform.Architecture && variant == allowedPlatform.Variant
	})
}
