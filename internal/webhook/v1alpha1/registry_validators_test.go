package v1alpha1

import (
	"testing"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func Test_validatePlatform(t *testing.T) {
	tests := []struct {
		name    string
		p       v1alpha1.Platform
		wantErr bool
	}{
		{
			name: "valid",
			p: v1alpha1.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			wantErr: false,
		},
		{
			name: "wrong arch",
			p: v1alpha1.Platform{
				Architecture: "armz",
				OS:           "linux",
			},
			wantErr: true,
		},
		{
			name: "wrong variant",
			p: v1alpha1.Platform{
				Architecture: "arm",
				OS:           "linux",
				Variant:      "v1",
			},
			wantErr: true,
		},
		{
			name: "arch doesn not have variant",
			p: v1alpha1.Platform{
				Architecture: "amd64",
				OS:           "linux",
				Variant:      "v2",
			},
			wantErr: true,
		},
		{
			// this test case highlight that if we provide
			// linux/arm we consider it valid and let
			// the catalog search for all the variants:
			// linux/arm/{v6,v7,v8}
			name: "no variant provided but still valid",
			p: v1alpha1.Platform{
				Architecture: "arm",
				OS:           "linux",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := validatePlatform(tt.p)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("validatePlatform() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("validatePlatform() succeeded unexpectedly")
			}
		})
	}
}
