package v1alpha1

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/sbomscanner/api"
)

func TestRegistry_IsManagedByWorkloadScan(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		expected bool
	}{
		{
			name:     "no labels",
			labels:   nil,
			expected: false,
		},
		{
			name:     "only workloadscan label",
			labels:   map[string]string{api.LabelWorkloadScanKey: api.LabelWorkloadScanValue},
			expected: false,
		},
		{
			name:     "only managed-by label",
			labels:   map[string]string{api.LabelManagedByKey: api.LabelManagedByValue},
			expected: false,
		},
		{
			name: "both labels",
			labels: map[string]string{
				api.LabelManagedByKey:    api.LabelManagedByValue,
				api.LabelWorkloadScanKey: api.LabelWorkloadScanValue,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &Registry{Labels: tt.labels}
			assert.Equal(t, tt.expected, registry.IsManagedByWorkloadScan())
		})
	}
}

func TestGetRepository(t *testing.T) {
	expectedConditions := []MatchCondition{
		{Name: "tag-latest", Expression: `tag == "latest"`},
	}

	tests := []struct {
		name        string
		registryURI string
		repoName    string
		lookupRepo  string
		expectMatch bool
	}{
		{
			name:        "exact match",
			registryURI: "ghcr.io",
			repoName:    "test/app",
			lookupRepo:  "test/app",
			expectMatch: true,
		},
		{
			name:        "no match",
			registryURI: "ghcr.io",
			repoName:    "test/app",
			lookupRepo:  "other/app",
			expectMatch: false,
		},
		{
			name:        "Docker Hub official image with short repo name",
			registryURI: name.DefaultRegistry,
			repoName:    "busybox",
			lookupRepo:  "library/busybox",
			expectMatch: true,
		},
		{
			name:        "Docker Hub official image with full library/ repo name",
			registryURI: name.DefaultRegistry,
			repoName:    "library/busybox",
			lookupRepo:  "library/busybox",
			expectMatch: true,
		},
		{
			name:        "Docker Hub namespaced image",
			registryURI: name.DefaultRegistry,
			repoName:    "myuser/myapp",
			lookupRepo:  "myuser/myapp",
			expectMatch: true,
		},
		{
			name:        "non-Docker Hub registry does not strip library/",
			registryURI: "ghcr.io",
			repoName:    "myapp",
			lookupRepo:  "library/myapp",
			expectMatch: false,
		},
		{
			name:        "non-Docker Hub registry with library/ in path",
			registryURI: "ghcr.io",
			repoName:    "library/myapp",
			lookupRepo:  "library/myapp",
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &Registry{
				Spec: RegistrySpec{
					URI: tt.registryURI,
					Repositories: []Repository{
						{Name: tt.repoName, MatchConditions: expectedConditions},
					},
				},
			}

			got := registry.GetRepository(tt.lookupRepo)
			if tt.expectMatch {
				require.NotNil(t, got)
				assert.Equal(t, expectedConditions, got.MatchConditions)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
