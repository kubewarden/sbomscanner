package filters

import (
	"fmt"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cel"
)

// FilterByTag filters the image evaluating the tag CEL expressions.
// Returns true, if the tag is a valid tag or if no MatchConditions
// are provided in the Registry configuration.
// Returns false if the tag is not allowed, followed by an error in case
// the expression evaluation fails.
func FilterByTag(tagEvaluator *cel.TagEvaluator, matchConditions []v1alpha1.MatchCondition, tag string) (bool, error) {
	if len(matchConditions) == 0 {
		return true, nil
	}

	// All match conditions must pass (AND logic)
	for _, mc := range matchConditions {
		allowed, err := tagEvaluator.Evaluate(mc.Expression, tag)
		if err != nil {
			return false, fmt.Errorf("cannot evaluate expression: %w", err)
		}
		// here we are evaluating the list of MatchConditions
		// with an AND statement, so if at least one of the
		// expressions fails, then the entire MatchCondition fails.
		if !allowed {
			return false, nil
		}
	}

	// if no MatchConditions are found,
	// we assume the user doesn't want to apply
	// any filter to the image.
	return true, nil
}
