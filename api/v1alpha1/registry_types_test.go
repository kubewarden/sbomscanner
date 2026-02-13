package v1alpha1

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
)

func TestGetMatchConditionsByRepository(t *testing.T) {
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

			got := registry.GetMatchConditionsByRepository(tt.lookupRepo)
			if tt.expectMatch {
				assert.Equal(t, expectedConditions, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}
