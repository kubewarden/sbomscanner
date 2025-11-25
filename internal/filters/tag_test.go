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
		name            string
		matchConditions []v1alpha1.MatchCondition
		tag             string
		want            bool
		wantErr         bool
	}{
		{
			name: "matches single condition",
			matchConditions: []v1alpha1.MatchCondition{
				{
					Name:       "no images with -dev tags",
					Expression: "!tag.matches('$-dev')",
				},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "matches multiple condition",
			matchConditions: []v1alpha1.MatchCondition{
				{
					Name:       "no images with -dev tags",
					Expression: "!tag.matches('$-dev')",
				},
				{
					Name:       "images >= 1.27.0",
					Expression: "semver(tag, true).isGreaterThan(semver('1.27.0'))",
				},
			},
			tag:     imageTag,
			want:    true,
			wantErr: false,
		},
		{
			name: "matches only one condition and then fails",
			matchConditions: []v1alpha1.MatchCondition{
				{
					Name:       "no images with -dev tags",
					Expression: "!tag.matches('$-dev')",
				},
				{
					Name:       "images >= 1.27.2",
					Expression: "semver(tag, true).isGreaterThan(semver('1.27.2'))",
				},
			},
			tag:     imageTag,
			want:    false,
			wantErr: false,
		},
		{
			name:            "no conditions are provided",
			matchConditions: []v1alpha1.MatchCondition{},
			tag:             imageTag,
			want:            true,
			wantErr:         false,
		},
		{
			name: "wrong expression provided",
			matchConditions: []v1alpha1.MatchCondition{
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
			tag:     imageTag,
			want:    false,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := FilterByTag(tagEvaluator, test.matchConditions, test.tag)
			if gotErr != nil {
				if !test.wantErr {
					t.Errorf("filterByTag() failed: %v", gotErr)
				}
				return
			}
			if test.wantErr {
				t.Fatal("filterByTag() succeeded unexpectedly")
			}
			if test.want != got {
				t.Errorf("filterByTag() = %v, want %v", got, test.want)
			}
		})
	}
}
