package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dialect"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apiserver/pkg/storage"
)

// list executes a list query with standard filtering and pagination.
// The caller provides the base query builder and a function to scan rows.
//
//nolint:gocognit,funlen // Complexity is acceptable for this function.
func list(
	ctx context.Context,
	db Querier,
	qb bob.BaseQuery[*dialect.SelectQuery],
	namespace string,
	opts storage.ListOptions,
	newFunc func() runtime.Object,
) ([]runtime.Object, string, error) {
	if namespace != "" {
		qb.Apply(sm.Where(psql.Quote("namespace").EQ(psql.Arg(namespace))))
	}

	if opts.Predicate.Continue != "" {
		continueID, err := strconv.ParseInt(opts.Predicate.Continue, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("invalid continue token: %w", err)
		}
		qb.Apply(sm.Where(psql.Quote("id").GT(psql.Arg(continueID))))
	}

	// Apply resource version filtering when a specific RV is requested.
	// Skip this during WatchList since initial events will naturally have RVs
	// lower than the list RV.
	//
	// NOTE: ResourceVersionMatch is ignored. This storage always uses
	// NotOlderThan semantics, even if Exact is specified.
	// This matches legacy apiserver behavior from before ResourceVersionMatch
	// was introduced in Kubernetes 1.19.
	// True Exact semantics would require MVCC snapshots which PostgreSQL
	// sequences don't provide.
	if opts.ResourceVersion != "" && opts.ResourceVersion != "0" {
		rv, err := strconv.ParseUint(opts.ResourceVersion, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("invalid resource version: %w", err)
		}
		if opts.SendInitialEvents == nil || !*opts.SendInitialEvents {
			qb.Apply(sm.Where(psql.Raw("(object->'metadata'->>'resourceVersion')::bigint >= ?", rv)))
		}
	}

	if opts.Predicate.Label != nil {
		labelSelectorExpressions, err := buildLabelSelectorExpressions(opts.Predicate.Label)
		if err != nil {
			return nil, "", err
		}
		for _, expression := range labelSelectorExpressions {
			qb.Apply(sm.Where(expression))
		}
	}

	if opts.Predicate.Field != nil {
		fieldSelectorExpressions, err := buildFieldSelectorExpressions(opts.Predicate.Field)
		if err != nil {
			return nil, "", err
		}
		for _, expression := range fieldSelectorExpressions {
			qb.Apply(sm.Where(expression))
		}
	}

	// Fetch one extra row to determine if there are more results.
	// This is necessary when using label or field selectors because the SQL
	// filtering happens at query time, so we can't predict how many rows match.
	// Without the extra row, we'd return a continue token whenever count equals
	// limit, which could lead to an empty final page.
	if opts.Predicate.Limit > 0 {
		qb.Apply(sm.Limit(opts.Predicate.Limit + 1))
	}

	query, args, err := qb.Build(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build list query: %w", err)
	}

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to execute list query: %w", err)
	}
	defer rows.Close()

	var items []runtime.Object
	var lastID int64
	var count int64
	var hasMore bool

	for rows.Next() {
		if opts.Predicate.Limit > 0 && count == opts.Predicate.Limit {
			// We fetched one extra row, so there are more pages
			hasMore = true
			break
		}

		var id int64
		var objectBytes []byte
		if err := rows.Scan(&id, &objectBytes); err != nil {
			return nil, "", fmt.Errorf("failed to scan row: %w", err)
		}

		obj := newFunc()
		if err := json.Unmarshal(objectBytes, obj); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal object: %w", err)
		}

		items = append(items, obj)
		lastID = id
		count++
	}

	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("failed to iterate rows: %w", err)
	}

	// Generate continue token only if we actually have more rows
	var continueToken string
	if hasMore {
		continueToken = strconv.FormatInt(lastID, 10)
	}

	return items, continueToken, nil
}

// buildLabelSelectorExpressions builds SQL expressions from the provided k8s label selector
// using PostgreSQL JSONB operators.
func buildLabelSelectorExpressions(labelSelector labels.Selector) ([]psql.Expression, error) {
	var expressions []psql.Expression
	requirements, selectable := labelSelector.Requirements()
	if !selectable {
		return expressions, nil
	}

	for _, req := range requirements {
		var expression psql.Expression

		switch req.Operator() {
		case selection.Equals, selection.DoubleEquals:
			expression = psql.Raw("object->'metadata'->'labels'->>?", req.Key()).EQ(psql.Arg(req.Values().List()[0]))
		case selection.NotEquals:
			expression = psql.Raw("object->'metadata'->'labels'->>?", req.Key()).NE(psql.Arg(req.Values().List()[0]))
		case selection.In:
			expression = psql.Raw("object->'metadata'->'labels'->>? = ANY(?)", req.Key(), req.Values().List())
		case selection.NotIn:
			expression = psql.Raw("object->'metadata'->'labels'->>? != ALL(?)", req.Key(), req.Values().List())
		case selection.Exists:
			expression = psql.Raw("jsonb_exists(object->'metadata'->'labels', ?)", req.Key())
		case selection.DoesNotExist:
			expression = psql.Not(psql.Raw("jsonb_exists(object->'metadata'->'labels', ?)", req.Key()))
		case selection.GreaterThan, selection.LessThan:
			return nil, fmt.Errorf("unsupported label selector operator: %s", req.Operator())
		}

		expressions = append(expressions, expression)
	}

	return expressions, nil
}

// buildFieldSelectorExpressions builds SQL expressions from the provided k8s field selector
// using PostgreSQL JSONB operators.
func buildFieldSelectorExpressions(fieldSelector fields.Selector) ([]psql.Expression, error) {
	var expressions []psql.Expression
	requirements := fieldSelector.Requirements()

	for _, req := range requirements {
		// Convert dot notation to JSON path
		// "metadata.name" -> {metadata,name}
		pathParts := strings.Split(req.Field, ".")
		jsonPath := "{" + strings.Join(pathParts, ",") + "}"

		var expression psql.Expression

		switch req.Operator {
		case selection.Equals, selection.DoubleEquals:
			expression = psql.Raw("object #>> ?", jsonPath).EQ(psql.Arg(req.Value))
		case selection.NotEquals:
			expression = psql.Raw("object #>> ?", jsonPath).NE(psql.Arg(req.Value))
		case selection.In, selection.NotIn, selection.Exists, selection.DoesNotExist, selection.GreaterThan, selection.LessThan:
			return nil, fmt.Errorf("unsupported field selector operator: %v", req.Operator)
		}

		expressions = append(expressions, expression)
	}
	return expressions, nil
}
