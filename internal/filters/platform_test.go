package filters

import (
	"testing"

	cranev1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func Test_isPlatformAllowed(t *testing.T) {
	tests := []struct {
		name             string // description of this test case
		platform         *cranev1.Platform
		allowedPlatforms []v1alpha1.Platform
		want             bool
	}{
		{
			name:             "no platforms provided",
			platform:         &cranev1.Platform{OS: "linux", Architecture: "amd64"},
			allowedPlatforms: []v1alpha1.Platform{},
			want:             true,
		},
		{
			name:     "platform matches",
			platform: &cranev1.Platform{OS: "linux", Architecture: "amd64"},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			want: true,
		},
		{
			name:     "platform doesn't match",
			platform: &cranev1.Platform{OS: "linux", Architecture: "amd64"},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "arm",
					OS:           "linux",
					Variant:      "v7",
				},
			},
			want: false,
		},
		{
			name:     "platform is unknown",
			platform: &cranev1.Platform{OS: "unknown", Architecture: "unknown"},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "arm",
					OS:           "linux",
					Variant:      "v7",
				},
			},
			want: false,
		},
		{
			name:             "platform is unknown and no platforms provided",
			platform:         &cranev1.Platform{OS: "unknown", Architecture: "unknown"},
			allowedPlatforms: []v1alpha1.Platform{},
			want:             false,
		},
		{
			name:             "platform is nil and no platforms provided",
			platform:         nil,
			allowedPlatforms: []v1alpha1.Platform{},
			want:             false,
		},
		{
			name:     "platform is nil",
			platform: nil,
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			want: false,
		},
		{
			name:     "platform is linux/arm/v7",
			platform: &cranev1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "arm",
					OS:           "linux",
				},
			},
			want: true,
		},
		{
			name:     "platform is linux/arm",
			platform: &cranev1.Platform{OS: "linux", Architecture: "arm"},
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "arm",
					OS:           "linux",
					Variant:      "v7",
				},
				{
					Architecture: "arm",
					OS:           "linux",
					Variant:      "v8",
				},
			},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsPlatformAllowed(test.platform, test.allowedPlatforms)
			if got != test.want {
				t.Errorf("isPlatformAllowed() = %v, want %v", got, test.want)
			}
		})
	}
}
