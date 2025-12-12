package cel

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/ext"
	"k8s.io/apiserver/pkg/cel/library"
)

// tagEvaluatorCostLimit is the maximum cost limit for evaluating tag expressions.
// This is to prevent excessively complex expressions from consuming too many resources.
const tagEvaluatorCostLimit = 100

// tagSizeEstimator provides size estimates for the tag variable.
type tagSizeEstimator struct{}

func (t *tagSizeEstimator) EstimateSize(_ checker.AstNode) *checker.SizeEstimate {
	// OCI distribution spec allows tags up to 128 characters.
	return &checker.SizeEstimate{Min: 0, Max: 128}
}

func (t *tagSizeEstimator) EstimateCallCost(_, _ string, _ *checker.AstNode, _ []checker.AstNode) *checker.CallEstimate {
	return nil
}

// TagEvaluator is the evaluator for tag filter expressions.
type TagEvaluator struct {
	env *cel.Env
}

func NewTagEvaluator() (*TagEvaluator, error) {
	env, err := cel.NewEnv(
		// Clear all default macros (has, all, exists, exists_one, map, filter)
		// as they are not needed for tag evaluation.
		cel.ClearMacros(),
		cel.ASTValidators(
			cel.ValidateTimestampLiterals(),
			cel.ValidateRegexLiterals(),
		),
		ext.Strings(),
		library.SemverLib(library.SemverVersion(1)),
		cel.Variable("tag", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &TagEvaluator{
		env: env,
	}, nil
}

// Evaluate evaluates the given CEL expression against the provided tag.
// Returns true if the expression evaluates to true, false otherwise.
func (e *TagEvaluator) Evaluate(expression string, tag string) (bool, error) {
	ast, err := e.compile(expression)
	if err != nil {
		return false, err
	}
	prg, err := e.env.Program(ast, cel.CostLimit(tagEvaluatorCostLimit))
	if err != nil {
		return false, fmt.Errorf("failed to create CEL program: %w", err)
	}

	val, _, err := prg.Eval(map[string]interface{}{
		"tag": tag,
	})
	if err != nil {
		return false, fmt.Errorf("failed to evaluate expression: %w", err)
	}

	result, ok := val.Value().(bool)
	if !ok {
		return false, errors.New("expression did not evaluate to a boolean")
	}

	return result, nil
}

// Validate validates the given CEL expression against the tag evaluator's environment.
// Returns an error if the expression is invalid or does not evaluate to a boolean.
func (e *TagEvaluator) Validate(expression string) error {
	ast, err := e.compile(expression)
	if err != nil {
		return err
	}

	if ast.OutputType() != cel.BoolType {
		return errors.New("must evaluate to bool")
	}

	return nil
}

func (e *TagEvaluator) compile(expression string) (*cel.Ast, error) {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile expression: %w", issues.Err())
	}

	costEst, err := e.env.EstimateCost(ast, &library.CostEstimator{
		SizeEstimator: &tagSizeEstimator{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to estimate expression cost: %w", err)
	}
	if costEst.Max > tagEvaluatorCostLimit {
		return nil, fmt.Errorf("expression cost %d exceeds limit %d", costEst.Max, tagEvaluatorCostLimit)
	}

	return ast, nil
}
