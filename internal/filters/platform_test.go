package filters

import (
	"testing"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func Test_isPlatformAllowed(t *testing.T) {
	tests := []struct {
		name                 string // description of this test case
		platformOs           string
		platformArchitecture string
		platformVariant      string
		allowedPlatforms     []v1alpha1.Platform
		want                 bool
	}{
		{
			name:                 "no platforms provided",
			platformArchitecture: "amd64",
			platformOs:           "linux",
			platformVariant:      "",
			allowedPlatforms:     []v1alpha1.Platform{},
			want:                 true,
		},
		{
			name:                 "platform matches",
			platformArchitecture: "amd64",
			platformOs:           "linux",
			platformVariant:      "",
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			want: true,
		},
		{
			name:                 "platform doesn't match",
			platformArchitecture: "amd64",
			platformOs:           "linux",
			platformVariant:      "",
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
			name:                 "platform is unknown",
			platformArchitecture: "unknown",
			platformOs:           "unknown",
			platformVariant:      "",
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
			name:                 "platform is linux/arm/v7",
			platformArchitecture: "arm",
			platformOs:           "linux",
			platformVariant:      "v7",
			allowedPlatforms: []v1alpha1.Platform{
				{
					Architecture: "arm",
					OS:           "linux",
				},
			},
			want: true,
		},
		{
			name:                 "platform is linux/arm",
			platformArchitecture: "arm",
			platformOs:           "linux",
			platformVariant:      "",
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
			got := IsPlatformAllowed(test.platformOs, test.platformArchitecture, test.platformVariant, test.allowedPlatforms)
			if got != test.want {
				t.Errorf("isPlatformAllowed() = %v, want %v", got, test.want)
			}
		})
	}
}
