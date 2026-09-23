package handlers

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	registryserver "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubewarden/sbomscanner/api"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	registryclient "github.com/kubewarden/sbomscanner/internal/handlers/registry"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestWorkloadRepositoryReferences(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	condition := func(identifier string) v1alpha1.MatchCondition {
		return v1alpha1.MatchCondition{Name: "tag-" + identifier, Expression: fmt.Sprintf("tag == %q", identifier)}
	}
	tests := []struct {
		name       string
		conditions []v1alpha1.MatchCondition
		managed    bool
		operator   v1alpha1.MatchOperator
		want       []string
		handled    bool
		invalid    bool
	}{
		{"digest without a tag", []v1alpha1.MatchCondition{condition(digest)}, true, v1alpha1.MatchOperatorOr, []string{"example.com/team/image@" + digest}, true, false},
		{"tag-only uses existing discovery", []v1alpha1.MatchCondition{condition("v1")}, true, v1alpha1.MatchOperatorOr, nil, false, false},
		{"mixed and duplicate", []v1alpha1.MatchCondition{condition("v1"), condition(digest), condition(digest)}, true, v1alpha1.MatchOperatorOr, []string{"example.com/team/image:v1", "example.com/team/image@" + digest}, true, false},
		{"manual registry", []v1alpha1.MatchCondition{condition(digest)}, false, v1alpha1.MatchOperatorOr, nil, false, false},
		{"custom CEL", []v1alpha1.MatchCondition{{Name: "custom", Expression: "tag.startsWith('v')"}}, true, v1alpha1.MatchOperatorOr, nil, false, false},
		{"changed expression", []v1alpha1.MatchCondition{{Name: "tag-" + digest, Expression: "true"}}, true, v1alpha1.MatchOperatorOr, nil, false, false},
		{"and operator", []v1alpha1.MatchCondition{condition(digest)}, true, v1alpha1.MatchOperatorAnd, nil, false, false},
		{"empty conditions", nil, true, v1alpha1.MatchOperatorOr, nil, false, false},
		{"invalid digest fails", []v1alpha1.MatchCondition{condition("sha256:short")}, true, v1alpha1.MatchOperatorOr, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &v1alpha1.Registry{Spec: v1alpha1.RegistrySpec{URI: "example.com", Repositories: []v1alpha1.Repository{{Name: "team/image", MatchOperator: tt.operator, MatchConditions: tt.conditions}}}}
			if tt.managed {
				registry.Labels = map[string]string{api.LabelManagedByKey: api.LabelManagedByValue, api.LabelWorkloadScanKey: api.LabelWorkloadScanValue}
			}
			repo, err := name.NewRepository("example.com/team/image")
			require.NoError(t, err)
			got, handled, err := workloadRepositoryReferences(registry, repo)
			if tt.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.handled, handled)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWorkloadDigestPrivateMultiArchitecture(t *testing.T) {
	registryHandler := registryserver.New(registryserver.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelInfo)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, _ := r.BasicAuth()
		if user != "scanner" || password != "fixture" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			http.Error(w, "tag listing forbidden", http.StatusForbidden)
			return
		}
		registryHandler.ServeHTTP(w, r)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	repo, err := name.NewRepository(host+"/private/image", name.Insecure)
	require.NoError(t, err)
	amd64, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{Architecture: "amd64", OS: "linux"})
	require.NoError(t, err)
	arm64, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{Architecture: "arm64", OS: "linux"})
	require.NoError(t, err)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd64, Platform: &v1.Platform{Architecture: "amd64", OS: "linux"}},
		mutate.IndexAddendum{Add: arm64, Platform: &v1.Platform{Architecture: "arm64", OS: "linux"}},
	)
	indexDigest, err := index.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(repo.Digest(indexDigest.String()), index, remote.WithAuth(&authn.Basic{Username: "scanner", Password: "fixture"})))
	config := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("scanner:fixture"))
	require.NoError(t, os.WriteFile(filepath.Join(config, "config.json"), []byte(fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, auth)), 0600))
	t.Setenv("DOCKER_CONFIG", config)
	registry := &v1alpha1.Registry{
		Name: "workloadscan-test", Namespace: "test",
		Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue, api.LabelWorkloadScanKey: api.LabelWorkloadScanValue},
		Spec: v1alpha1.RegistrySpec{URI: host, Insecure: true,
			Platforms:    []v1alpha1.Platform{{Architecture: "amd64", OS: "linux"}},
			Repositories: []v1alpha1.Repository{{Name: "private/image", MatchOperator: v1alpha1.MatchOperatorOr, MatchConditions: []v1alpha1.MatchCondition{{Name: "tag-" + indexDigest.String(), Expression: fmt.Sprintf("tag == %q", indexDigest.String())}}}},
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	handler := &CreateCatalogHandler{scheme: scheme, logger: slog.Default()}
	client := registryclient.NewClient(server.Client().Transport, slog.Default())
	refs, err := handler.discoverImages(t.Context(), client, registry, repo.Name())
	require.NoError(t, err)
	require.Len(t, refs, 1)
	ref, err := name.ParseReference(refs[0], name.Insecure)
	require.NoError(t, err)
	images, err := handler.refToImages(t.Context(), &testMessage{}, client, ref, registry)
	require.NoError(t, err)
	require.Len(t, images, 1)
	amd64Digest, err := amd64.Digest()
	require.NoError(t, err)
	require.Equal(t, amd64Digest.String(), images[0].Digest)
	require.Equal(t, indexDigest.String(), images[0].IndexDigest)
	require.Equal(t, "linux/amd64", images[0].Platform)
}

func TestDiscoverWorkloadImagesWithoutTagListing(t *testing.T) {
	for _, forbidListing := range []bool{false, true} {
		t.Run(fmt.Sprintf("forbidListing=%t", forbidListing), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path == "/v2/" {
					w.WriteHeader(http.StatusOK)
					return
				}
				if forbidListing {
					http.Error(w, "tag listing forbidden", http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"name":"private/image","tags":[]}`)
			}))
			defer server.Close()
			digest := "sha256:" + strings.Repeat("a", 64)
			host := strings.TrimPrefix(server.URL, "http://")
			registry := &v1alpha1.Registry{
				Labels: map[string]string{api.LabelManagedByKey: api.LabelManagedByValue, api.LabelWorkloadScanKey: api.LabelWorkloadScanValue},
				Spec: v1alpha1.RegistrySpec{URI: host, Insecure: true, Repositories: []v1alpha1.Repository{{
					Name: "private/image", MatchOperator: v1alpha1.MatchOperatorOr,
					MatchConditions: []v1alpha1.MatchCondition{{Name: "tag-" + digest, Expression: fmt.Sprintf("tag == %q", digest)}},
				}}},
			}
			handler := &CreateCatalogHandler{logger: slog.Default()}
			client := registryclient.NewClient(server.Client().Transport, slog.Default())
			refs, err := handler.discoverImages(t.Context(), client, registry, host+"/private/image")
			require.NoError(t, err)
			require.Equal(t, []string{host + "/private/image@" + digest}, refs)
			require.Zero(t, requests)
		})
	}
}
