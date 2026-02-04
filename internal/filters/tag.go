package filters

import (
	"fmt"

	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/internal/cel"
)

// FilterByTag filters the image evaluating the tag CEL expressions.
// Returns true, if the tag is a valid tag or if no MatchConditions are provided in the Repository configuration.
// Returns false if the tag is not allowed, followed by an error in case the expression evaluation fails.
func FilterByTag(tagEvaluator *cel.TagEvaluator, repository *v1alpha1.Repository, tag string) (bool, error) {
	if repository == nil || len(repository.MatchConditions) == 0 {
		return true, nil
	}

	op := repository.MatchOperator
	if op == "" {
		op = v1alpha1.MatchOperatorAnd
	}

	for _, mc := range repository.MatchConditions {
		allowed, err := tagEvaluator.Evaluate(mc.Expression, tag)
		if err != nil {
			return false, fmt.Errorf("cannot evaluate expression %q: %w", mc.Name, err)
		}

		switch op {
		case v1alpha1.MatchOperatorAnd:
			// All conditions must pass, so if one fails, return false immediately.
			if !allowed {
				return false, nil
			}
		case v1alpha1.MatchOperatorOr:
			// At least one condition must pass, so if one passes, return true immediately.
			if allowed {
				return true, nil
			}
		}
	}

	// For AND: all conditions passed.
	// For OR: no condition passed.
	return op == v1alpha1.MatchOperatorAnd, nil
}
