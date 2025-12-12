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
		expectedErr    string
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
		{
			name:       "exceeds cost limit",
			expression: "semver(tag, true).isLessThan(semver('v1.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v2.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v3.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v4.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v5.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v6.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v7.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v8.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v9.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v10.0.0-dev', true))",
			// Cost breakdown for 10 semver comparisons:
			//   semver(tag, true):         128 * 0.1 = 13 (tag bounded to 128 chars)
			//   semver('vX.0.0-dev', true): 11 * 0.1 =  1 (literal, actual size)
			//   isLessThan():               fixed    =  1
			//   Per comparison:                      = 15
			//
			//   10 comparisons: 150
			//   9 || operators:   9
			//   Overhead:         2
			//   Total:          161
			expectedErr: "expression cost 161 exceeds limit 100",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(test.expression, test.tag)

			if test.expectedErr != "" {
				require.ErrorContains(t, err, test.expectedErr)
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

		{
			name:       "exceeds cost limit",
			expression: "semver(tag, true).isLessThan(semver('v1.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v2.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v3.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v4.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v5.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v6.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v7.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v8.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v9.0.0-dev', true)) || semver(tag, true).isLessThan(semver('v10.0.0-dev', true))",
			// Cost breakdown for 10 semver comparisons:
			//   semver(tag, true):         128 * 0.1 = 13 (tag bounded to 128 chars)
			//   semver('vX.0.0-dev', true): 11 * 0.1 =  1 (literal, actual size)
			//   isLessThan():               fixed    =  1
			//   Per comparison:                      = 15
			//
			//   10 comparisons: 150
			//   9 || operators:   9
			//   Overhead:         2
			//   Total:          161
			expectedErr: "expression cost 161 exceeds limit 100",
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
