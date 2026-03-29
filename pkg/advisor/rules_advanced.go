// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package advisor

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ---------------------------------------------------------------------------
// OPT-009: Correlated Subquery in SELECT List (N+1 pattern)
// ---------------------------------------------------------------------------

// CorrelatedSubqueryInSelectRule detects subqueries in the SELECT column list.
// Each row in the outer query triggers one inner query — the classic N+1 problem.
type CorrelatedSubqueryInSelectRule struct{}

func (r *CorrelatedSubqueryInSelectRule) ID() string   { return "OPT-009" }
func (r *CorrelatedSubqueryInSelectRule) Name() string { return "Correlated Subquery in SELECT" }
func (r *CorrelatedSubqueryInSelectRule) Description() string {
	return "Detects correlated subqueries in the SELECT column list which cause N+1 query execution."
}

func (r *CorrelatedSubqueryInSelectRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	var suggestions []Suggestion
	for _, col := range sel.Columns {
		// Handle aliased expressions wrapping a subquery
		inner := col
		if aliased, ok := col.(*ast.AliasedExpression); ok {
			inner = aliased.Expr
		}
		if _, ok := inner.(*ast.SubqueryExpression); ok {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityWarning,
				Message:      "Correlated subquery in SELECT list causes N+1 query execution",
				Detail:       "Each row in the outer query executes this subquery independently. Replace with a LEFT JOIN for a single-pass query that is typically orders of magnitude faster.",
				SuggestedSQL: "Replace the subquery with LEFT JOIN ... ON ...",
			})
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-010: HAVING Without GROUP BY
// ---------------------------------------------------------------------------

// HavingWithoutGroupByRule detects HAVING clauses without a corresponding GROUP BY.
// Most databases treat this as a full-table aggregate — rarely the intent.
type HavingWithoutGroupByRule struct{}

func (r *HavingWithoutGroupByRule) ID() string   { return "OPT-010" }
func (r *HavingWithoutGroupByRule) Name() string { return "HAVING Without GROUP BY" }
func (r *HavingWithoutGroupByRule) Description() string {
	return "HAVING without GROUP BY treats the entire table as one group — usually a logic error."
}

func (r *HavingWithoutGroupByRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	if sel.Having != nil && len(sel.GroupBy) == 0 {
		return []Suggestion{{
			RuleID:   r.ID(),
			Severity: SeverityWarning,
			Message:  "HAVING clause without GROUP BY groups the entire table as one aggregate",
			Detail:   "HAVING without GROUP BY is valid SQL but treats all rows as a single group. If you intend to filter individual rows, use WHERE instead.",
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OPT-011: Redundant ORDER BY in CTE
// ---------------------------------------------------------------------------

// RedundantOrderByInCTERule detects ORDER BY inside a CTE definition without LIMIT.
// In most databases (PostgreSQL, MySQL, SQL Server, ClickHouse), ORDER BY inside a
// CTE is ignored unless paired with LIMIT/TOP/FETCH.
type RedundantOrderByInCTERule struct{}

func (r *RedundantOrderByInCTERule) ID() string   { return "OPT-011" }
func (r *RedundantOrderByInCTERule) Name() string { return "Redundant ORDER BY in CTE" }
func (r *RedundantOrderByInCTERule) Description() string {
	return "ORDER BY inside a CTE definition is ignored by most databases unless combined with LIMIT/TOP."
}

func (r *RedundantOrderByInCTERule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.With == nil {
		return nil
	}
	var suggestions []Suggestion
	for _, cte := range sel.With.CTEs {
		cteQuery, ok := cte.Statement.(*ast.SelectStatement)
		if !ok {
			continue
		}
		// ORDER BY without LIMIT/FETCH/TOP is redundant in a CTE
		hasLimit := cteQuery.Limit != nil || cteQuery.Fetch != nil || cteQuery.Top != nil
		if len(cteQuery.OrderBy) > 0 && !hasLimit {
			suggestions = append(suggestions, Suggestion{
				RuleID:   r.ID(),
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("ORDER BY in CTE %q is likely ignored by the database", cte.Name),
				Detail:   "CTE inner ORDER BY is ignored by PostgreSQL, MySQL, SQL Server, and ClickHouse unless combined with LIMIT/TOP/FETCH. Move the ORDER BY to the outer query.",
			})
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-012: Implicit Type Conversion (CAST on column in WHERE)
// ---------------------------------------------------------------------------

// ImplicitTypeConversionRule detects CAST expressions wrapping a column in WHERE conditions.
// Wrapping a column in CAST/CONVERT prevents the database from using an index on that column.
type ImplicitTypeConversionRule struct{}

func (r *ImplicitTypeConversionRule) ID() string   { return "OPT-012" }
func (r *ImplicitTypeConversionRule) Name() string { return "Implicit Type Conversion in WHERE" }
func (r *ImplicitTypeConversionRule) Description() string {
	return "CAST/CONVERT wrapping a column in a WHERE clause prevents index use and causes full table scans."
}

func (r *ImplicitTypeConversionRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	if containsCastExprInWhere(sel.Where) {
		return []Suggestion{{
			RuleID:   r.ID(),
			Severity: SeverityWarning,
			Message:  "CAST/CONVERT wrapping a column in WHERE prevents index usage",
			Detail:   "Casting a column in a WHERE comparison forces a full table scan. Cast the literal value to match the column type instead: column = CAST(value AS column_type).",
		}}
	}
	return nil
}

// containsCastExprInWhere recursively checks if a WHERE expression contains a
// CastExpression wrapping an Identifier (i.e., CAST(col AS type)).
func containsCastExprInWhere(expr ast.Expression) bool {
	if expr == nil {
		return false
	}
	switch v := expr.(type) {
	case *ast.CastExpression:
		// CAST wrapping a column identifier
		if _, ok := v.Expr.(*ast.Identifier); ok {
			return true
		}
	case *ast.BinaryExpression:
		return containsCastExprInWhere(v.Left) || containsCastExprInWhere(v.Right)
	case *ast.UnaryExpression:
		return containsCastExprInWhere(v.Expr)
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-013: OR-to-IN Conversion
// ---------------------------------------------------------------------------

// OrToInConversionRule detects three or more OR equality conditions on the same column.
// col = A OR col = B OR col = C is more readable and sometimes faster as col IN (A, B, C).
type OrToInConversionRule struct{}

func (r *OrToInConversionRule) ID() string   { return "OPT-013" }
func (r *OrToInConversionRule) Name() string { return "OR Conditions on Same Column" }
func (r *OrToInConversionRule) Description() string {
	return "Three or more OR equality conditions on the same column should be rewritten as IN (...)."
}

func (r *OrToInConversionRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	col, count := collectOrEqualityColumn(sel.Where)
	if count >= 3 && col != "" {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      fmt.Sprintf("Column %q has %d OR equality conditions — consider using IN (...)", col, count),
			Detail:       "Multiple OR conditions on the same column are equivalent to IN (...) but harder to read and may be less efficient.",
			SuggestedSQL: fmt.Sprintf("WHERE %s IN (...)", col),
		}}
	}
	return nil
}

// collectOrEqualityColumn traverses an OR chain and returns the column name and count
// if all equality conditions in the OR chain reference the same column.
// Returns ("", 0) if conditions are on different columns or the pattern is not matched.
func collectOrEqualityColumn(expr ast.Expression) (string, int) {
	bin, ok := expr.(*ast.BinaryExpression)
	if !ok {
		return "", 0
	}

	if strings.ToUpper(bin.Operator) == "OR" {
		leftCol, leftCount := collectOrEqualityColumn(bin.Left)
		rightCol, rightCount := collectOrEqualityColumn(bin.Right)

		// Both sides must be on the same column
		if leftCol == "" || rightCol == "" {
			return "", 0
		}
		if leftCol != rightCol {
			return "", 0
		}
		return leftCol, leftCount + rightCount
	}

	if bin.Operator == "=" {
		if id, ok := bin.Left.(*ast.Identifier); ok {
			return id.Name, 1
		}
	}

	return "", 0
}

// ---------------------------------------------------------------------------
// OPT-014: NOT IN Subquery NULL Risk
// ---------------------------------------------------------------------------

// NotInSubqueryNullRule flags NOT IN (subquery) patterns.
// If the subquery returns any NULL, the entire NOT IN evaluates to an empty result set.
type NotInSubqueryNullRule struct{}

func (r *NotInSubqueryNullRule) ID() string   { return "OPT-014" }
func (r *NotInSubqueryNullRule) Name() string { return "NOT IN With Subquery NULL Risk" }
func (r *NotInSubqueryNullRule) Description() string {
	return "NOT IN (subquery) returns empty set if the subquery produces any NULL. Use NOT EXISTS or LEFT JOIN ... IS NULL instead."
}

func (r *NotInSubqueryNullRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil
	}
	if containsNotInSubquery(sel.Where) {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      "NOT IN (subquery) returns empty result if the subquery has any NULL values",
			Detail:       "If the subquery column is nullable, NOT IN returns no rows whenever any NULL appears. Use NOT EXISTS (SELECT 1 FROM ... WHERE ...) or a LEFT JOIN ... WHERE right.id IS NULL for correct behavior.",
			SuggestedSQL: "WHERE NOT EXISTS (SELECT 1 FROM ... WHERE col = outer.col)",
		}}
	}
	return nil
}

// containsNotInSubquery checks if an expression is or contains NOT IN (subquery).
func containsNotInSubquery(expr ast.Expression) bool {
	if expr == nil {
		return false
	}
	switch v := expr.(type) {
	case *ast.InExpression:
		if v.Not && v.Subquery != nil {
			return true
		}
	case *ast.BinaryExpression:
		return containsNotInSubquery(v.Left) || containsNotInSubquery(v.Right)
	case *ast.UnaryExpression:
		return containsNotInSubquery(v.Expr)
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-015: Missing LIMIT on Ordered Query
// ---------------------------------------------------------------------------

// MissingLimitRule flags SELECT queries with ORDER BY but no LIMIT/FETCH/TOP.
// Without a LIMIT, the database must sort the entire result set.
type MissingLimitRule struct{}

func (r *MissingLimitRule) ID() string   { return "OPT-015" }
func (r *MissingLimitRule) Name() string { return "Missing LIMIT on Ordered Query" }
func (r *MissingLimitRule) Description() string {
	return "SELECT with ORDER BY but no LIMIT/FETCH/TOP sorts the full result set, which can be slow on large tables."
}

func (r *MissingLimitRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	hasLimit := sel.Limit != nil || sel.Fetch != nil || sel.Top != nil
	if len(sel.OrderBy) > 0 && !hasLimit {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "SELECT with ORDER BY but no LIMIT sorts the full result set",
			Detail:       "Without a LIMIT clause, the database must sort every matching row before returning results. Add LIMIT N to cap the result set at a known maximum.",
			SuggestedSQL: "SELECT ... ORDER BY ... LIMIT 100",
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OPT-016: Unused Column Alias
// ---------------------------------------------------------------------------

// UnusedAliasRule detects column aliases defined in the SELECT list that are never
// referenced in ORDER BY or HAVING clauses.
type UnusedAliasRule struct{}

func (r *UnusedAliasRule) ID() string   { return "OPT-016" }
func (r *UnusedAliasRule) Name() string { return "Unused Column Alias" }
func (r *UnusedAliasRule) Description() string {
	return "Column aliases defined in SELECT but never referenced in ORDER BY or HAVING add noise and may indicate a bug."
}

func (r *UnusedAliasRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}

	// Collect all aliases defined in the SELECT list
	aliases := make(map[string]bool)
	for _, col := range sel.Columns {
		if aliased, ok := col.(*ast.AliasedExpression); ok && aliased.Alias != "" {
			aliases[strings.ToLower(aliased.Alias)] = false // false = not yet used
		}
	}

	if len(aliases) == 0 {
		return nil
	}

	// Mark aliases referenced in ORDER BY
	for _, ob := range sel.OrderBy {
		markAliasUsed(ob.Expression, aliases)
	}
	// Mark aliases referenced in HAVING
	markAliasUsed(sel.Having, aliases)

	// Report aliases that are never referenced
	var suggestions []Suggestion
	for alias, used := range aliases {
		if !used {
			suggestions = append(suggestions, Suggestion{
				RuleID:   r.ID(),
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("Column alias %q is defined but never referenced in ORDER BY or HAVING", alias),
				Detail:   "Unused aliases add noise. If the alias is intentional for the caller, this warning can be ignored. Otherwise, check whether ORDER BY references should use the alias.",
			})
		}
	}
	return suggestions
}

// markAliasUsed walks an expression tree and marks any identifier that matches
// a known alias as used.
func markAliasUsed(expr ast.Expression, aliases map[string]bool) {
	if expr == nil {
		return
	}
	switch v := expr.(type) {
	case *ast.Identifier:
		key := strings.ToLower(v.Name)
		if _, exists := aliases[key]; exists {
			aliases[key] = true
		}
	case *ast.BinaryExpression:
		markAliasUsed(v.Left, aliases)
		markAliasUsed(v.Right, aliases)
	case *ast.UnaryExpression:
		markAliasUsed(v.Expr, aliases)
	case *ast.FunctionCall:
		for _, arg := range v.Arguments {
			markAliasUsed(arg, aliases)
		}
	case *ast.AliasedExpression:
		markAliasUsed(v.Expr, aliases)
	}
}

// ---------------------------------------------------------------------------
// OPT-017: UNION Instead of UNION ALL
// ---------------------------------------------------------------------------

// UnionDeduplicationRule warns when UNION (without ALL) is used.
// UNION deduplicates results by performing an internal sort or hash; UNION ALL avoids this.
type UnionDeduplicationRule struct{}

func (r *UnionDeduplicationRule) ID() string   { return "OPT-017" }
func (r *UnionDeduplicationRule) Name() string { return "UNION Instead of UNION ALL" }
func (r *UnionDeduplicationRule) Description() string {
	return "UNION deduplicates results requiring a full sort or hash; use UNION ALL if duplicates are acceptable."
}

func (r *UnionDeduplicationRule) Analyze(stmt ast.Statement) []Suggestion {
	op, ok := stmt.(*ast.SetOperation)
	if !ok {
		return nil
	}
	if strings.ToUpper(op.Operator) == "UNION" && !op.All {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "UNION deduplicates results — use UNION ALL if duplicates are acceptable",
			Detail:       "UNION requires sorting or hashing the combined result set to remove duplicates, adding significant overhead. If the queries cannot produce duplicates, or duplicates are acceptable, use UNION ALL for better performance.",
			SuggestedSQL: "Replace UNION with UNION ALL",
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OPT-018: COUNT(DISTINCT col) Where COUNT(*) May Suffice
// ---------------------------------------------------------------------------

// CountStarRule flags COUNT(DISTINCT col) in SELECT lists.
// COUNT(DISTINCT col) is significantly more expensive than COUNT(*) or COUNT(col)
// because it requires sorting or hashing the distinct values.
type CountStarRule struct{}

func (r *CountStarRule) ID() string   { return "OPT-018" }
func (r *CountStarRule) Name() string { return "COUNT(DISTINCT col) Overhead" }
func (r *CountStarRule) Description() string {
	return "COUNT(DISTINCT col) requires sorting/hashing all distinct values — verify DISTINCT is necessary."
}

func (r *CountStarRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	var suggestions []Suggestion
	for _, col := range sel.Columns {
		inner := col
		if aliased, ok := col.(*ast.AliasedExpression); ok {
			inner = aliased.Expr
		}
		if fn, ok := inner.(*ast.FunctionCall); ok {
			if strings.ToUpper(fn.Name) == "COUNT" && fn.Distinct {
				suggestions = append(suggestions, Suggestion{
					RuleID:       r.ID(),
					Severity:     SeverityInfo,
					Message:      "COUNT(DISTINCT col) requires hashing all distinct values — ensure DISTINCT is necessary",
					Detail:       "COUNT(DISTINCT col) is significantly more expensive than COUNT(*) or COUNT(col) because it must enumerate unique values. Verify that deduplication is actually required for correctness.",
					SuggestedSQL: "Consider COUNT(*) or COUNT(col) if rows are already unique in this context",
				})
			}
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-019: Deep Subquery Nesting
// ---------------------------------------------------------------------------

// DeepSubqueryNestingRule flags queries with more than 3 levels of subquery nesting.
// Deeply nested subqueries are difficult to optimize and should be rewritten with CTEs.
type DeepSubqueryNestingRule struct{}

func (r *DeepSubqueryNestingRule) ID() string   { return "OPT-019" }
func (r *DeepSubqueryNestingRule) Name() string { return "Deep Subquery Nesting" }
func (r *DeepSubqueryNestingRule) Description() string {
	return "More than 3 levels of subquery nesting is hard for the optimizer — consider CTEs or JOINs."
}

func (r *DeepSubqueryNestingRule) Analyze(stmt ast.Statement) []Suggestion {
	depth := maxSubqueryDepth(stmt, 0)
	if depth > 3 {
		return []Suggestion{{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      fmt.Sprintf("Query has %d levels of subquery nesting — consider rewriting with CTEs", depth),
			Detail:       "Deeply nested subqueries are hard for both developers to read and query optimizers to plan efficiently. Rewrite as a sequence of CTEs (WITH clauses) to improve readability and enable better optimization.",
			SuggestedSQL: "WITH cte1 AS (...), cte2 AS (...) SELECT ... FROM cte2",
		}}
	}
	return nil
}

// maxSubqueryDepth returns the maximum subquery nesting depth starting from a statement.
func maxSubqueryDepth(node interface{}, depth int) int {
	if depth > 15 {
		return depth // guard against pathological inputs
	}

	switch v := node.(type) {
	case *ast.SelectStatement:
		max := depth
		for _, col := range v.Columns {
			if d := maxSubqueryDepthExpr(col, depth); d > max {
				max = d
			}
		}
		if d := maxSubqueryDepthExpr(v.Where, depth); d > max {
			max = d
		}
		if d := maxSubqueryDepthExpr(v.Having, depth); d > max {
			max = d
		}
		return max

	case *ast.SetOperation:
		left := maxSubqueryDepth(v.Left, depth)
		right := maxSubqueryDepth(v.Right, depth)
		if left > right {
			return left
		}
		return right
	}
	return depth
}

// maxSubqueryDepthExpr computes the maximum subquery depth starting from an expression.
func maxSubqueryDepthExpr(expr ast.Expression, depth int) int {
	if expr == nil || depth > 15 {
		return depth
	}

	switch v := expr.(type) {
	case *ast.SubqueryExpression:
		return maxSubqueryDepth(v.Subquery, depth+1)

	case *ast.InExpression:
		if v.Subquery != nil {
			return maxSubqueryDepth(v.Subquery, depth+1)
		}

	case *ast.ExistsExpression:
		return maxSubqueryDepth(v.Subquery, depth+1)

	case *ast.BinaryExpression:
		left := maxSubqueryDepthExpr(v.Left, depth)
		right := maxSubqueryDepthExpr(v.Right, depth)
		if left > right {
			return left
		}
		return right

	case *ast.AliasedExpression:
		return maxSubqueryDepthExpr(v.Expr, depth)

	case *ast.FunctionCall:
		max := depth
		for _, arg := range v.Arguments {
			if d := maxSubqueryDepthExpr(arg, depth); d > max {
				max = d
			}
		}
		return max
	}

	return depth
}

// ---------------------------------------------------------------------------
// OPT-020: Explicit Cross Join / Cartesian Product
// ---------------------------------------------------------------------------

// ExplicitCrossJoinRule detects explicit CROSS JOIN clauses (without a join condition).
// CROSS JOIN produces a cartesian product which is usually unintentional.
type ExplicitCrossJoinRule struct{}

func (r *ExplicitCrossJoinRule) ID() string   { return "OPT-020" }
func (r *ExplicitCrossJoinRule) Name() string { return "Explicit Cross Join" }
func (r *ExplicitCrossJoinRule) Description() string {
	return "An explicit CROSS JOIN without a filter condition produces a cartesian product of all rows from both tables."
}

func (r *ExplicitCrossJoinRule) Analyze(stmt ast.Statement) []Suggestion {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	var suggestions []Suggestion
	for _, j := range sel.Joins {
		if strings.ToUpper(j.Type) == "CROSS" && j.Condition == nil {
			suggestions = append(suggestions, Suggestion{
				RuleID:   r.ID(),
				Severity: SeverityWarning,
				Message:  "CROSS JOIN produces a cartesian product — ensure this is intentional",
				Detail:   "A CROSS JOIN combines every row from the left table with every row from the right table, producing rows_left × rows_right output rows. This is rarely intended. Add an ON condition to make it a standard JOIN, or use the explicit CROSS JOIN only when a cartesian product is genuinely needed.",
			})
		}
	}
	return suggestions
}
