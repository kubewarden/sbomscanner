package filters

import (
	"testing"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cel"
	"github.com/stretchr/testify/require"
)

func Test_filterByTag(t *testing.T) {
	tagEvaluator, err := cel.NewTagEvaluator()
	imageTag := "1.27.1"
	require.NoError(t, err)

	tests := []struct {
		name    string
		repo    *v1alpha1.Repository
		tag     string
		want    bool
		wantErr bool
	}{
		{
			name: "matches single condition",
			repo: &v1alpha1.Repository{
				Name: "test-repo",
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
				},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "matches multiple condition with AND operator",
			repo: &v1alpha1.Repository{
				Name:          "test-repo",
				MatchOperator: v1alpha1.MatchOperatorAnd,
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
					{
						Name:       "images >= 1.27.0",
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.0'))",
					},
				},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "matches only one condition and then fails with AND operator",
			repo: &v1alpha1.Repository{
				Name:          "test-repo",
				MatchOperator: v1alpha1.MatchOperatorAnd,
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
					{
						Name:       "images >= 1.27.2",
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.2'))",
					},
				},
			},
			tag:     imageTag,
			want:    false,
			wantErr: false,
		},
		{
			name: "matches one condition with OR operator",
			repo: &v1alpha1.Repository{
				Name:          "test-repo",
				MatchOperator: v1alpha1.MatchOperatorOr,
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
					{
						Name:       "images >= 1.27.2",
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.2'))",
					},
				},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "matches no conditions with OR operator",
			repo: &v1alpha1.Repository{
				Name:          "test-repo",
				MatchOperator: v1alpha1.MatchOperatorOr,
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "images with -dev tags only",
						Expression: "tag.matches('-dev$')",
					},
					{
						Name:       "images >= 1.27.2",
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.2'))",
					},
				},
			},
			tag:     imageTag,
			want:    false,
			wantErr: false,
		},
		{
			name: "no conditions are provided",
			repo: &v1alpha1.Repository{
				Name:            "test-repo",
				MatchConditions: []v1alpha1.MatchCondition{},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name:    "nil repository",
			repo:    nil,
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "defaults to AND operator when not specified",
			repo: &v1alpha1.Repository{
				Name: "test-repo",
				// Operator not set, should default to AND
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
					{
						Name:       "images >= 1.27.2",
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.2'))",
					},
				},
			},
			tag:     imageTag,
			want:    false,
			wantErr: false,
		},
		{
			name: "wrong expression provided",
			repo: &v1alpha1.Repository{
				Name: "test-repo",
				MatchConditions: []v1alpha1.MatchCondition{
					{
						Name:       "no images with -dev tags",
						Expression: "!tag.matches('$-dev')",
					},
					{
						Name: "images >= 1.27.2",
						// the expression below has a syntax error to force its failure,
						// it misses the final ')' at the end of the string.
						Expression: "semver(tag, true).isGreaterThan(semver('1.27.2')",
					},
				},
			},
			tag:     imageTag,
			want:    false,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := FilterByTag(tagEvaluator, test.repo, test.tag)
			if test.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
			require.Equal(t, test.want, got)
		})
	}
}
