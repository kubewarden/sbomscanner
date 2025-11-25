package cel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagEvaluator_Evaluate(t *testing.T) {
	evaluator, err := NewTagEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name           string
		expression     string
		tag            string
		expectedResult bool
		expectedErr    bool
	}{
		{
			name:           "expression with semver",
			expression:     "semver(tag, true).isLessThan(semver('v1.0.0-dev', true))",
			tag:            "v0.9.0",
			expectedResult: true,
		},
		{
			name:           "expression wiht regex",
			expression:     "tag.matches('alpine$')",
			tag:            "v1.12.1-alpine",
			expectedResult: true,
		},
		{
			name:           "expression with string comparison",
			expression:     "tag == 'v.1.0.0'",
			tag:            "latest",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(test.expression, test.tag)

			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedResult, result)
			}
		})
	}
}

func TestTagEvaluator_Validate(t *testing.T) {
	tagEvaluator, err := NewTagEvaluator()
	require.NoError(t, err)

	tests := []struct {
		name        string
		expression  string
		expectedErr string
	}{
		{
			name:       "valid expression",
			expression: "semver(tag, true).isLessThan(semver('v1.0.0-dev', true))",
		},
		{
			name:        "unknown variable",
			expression:  "unknown_var == 'value'",
			expectedErr: "undeclared reference to 'unknown_var'",
		},
		{
			name:        "return type is not boolean",
			expression:  "tag + 'suffix'",
			expectedErr: "must evaluate to bool",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := tagEvaluator.Validate(test.expression)
			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
