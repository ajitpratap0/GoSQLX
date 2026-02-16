package advisor

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// DefaultRules returns the default set of all built-in optimization rules.
func DefaultRules() []Rule {
	return []Rule{
		&SelectStarRule{},
		&MissingWhereRule{},
		&CartesianProductRule{},
		&DistinctOveruseRule{},
		&SubqueryInWhereRule{},
		&OrInWhereRule{},
		&LeadingWildcardLikeRule{},
		&FunctionOnColumnRule{},
	}
}

// ---------------------------------------------------------------------------
// OPT-001: SELECT * Detection
// ---------------------------------------------------------------------------

// SelectStarRule detects SELECT * and recommends listing columns explicitly.
type SelectStarRule struct{}

func (r *SelectStarRule) ID() string   { return "OPT-001" }
func (r *SelectStarRule) Name() string { return "SELECT * Detection" }
func (r *SelectStarRule) Description() string {
	return "Detects SELECT * usage and suggests listing columns explicitly for better performance and maintainability."
}

func (r *SelectStarRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	for _, col := range sel.Columns {
		if isStarIdentifier(col) {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityWarning,
				Message:      "Avoid using SELECT * in production queries",
				Detail:       "SELECT * retrieves all columns which can hurt performance by transferring unnecessary data over the network, preventing index-only scans, and making the query fragile to schema changes.",
				Line:         1,
				Column:       1,
				SuggestedSQL: "List specific columns: SELECT col1, col2, ... FROM ...",
			})
			break // One suggestion per SELECT is enough
		}
	}

	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-002: Missing WHERE Clause
// ---------------------------------------------------------------------------

// MissingWhereRule detects UPDATE/DELETE statements without a WHERE clause.
type MissingWhereRule struct{}

func (r *MissingWhereRule) ID() string   { return "OPT-002" }
func (r *MissingWhereRule) Name() string { return "Missing WHERE Clause" }
func (r *MissingWhereRule) Description() string {
	return "Detects UPDATE and DELETE statements without WHERE clauses which affect all rows in the table."
}

func (r *MissingWhereRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	switch s := stmt.(type) {
	case *ast.UpdateStatement:
		if s.Where == nil {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityError,
				Message:      fmt.Sprintf("UPDATE on table %q without WHERE clause will modify all rows", s.TableName),
				Detail:       "An UPDATE without a WHERE clause applies changes to every row in the table. This is almost always unintentional and can cause catastrophic data corruption.",
				Line:         1,
				Column:       1,
				SuggestedSQL: fmt.Sprintf("UPDATE %s SET ... WHERE <condition>", s.TableName),
			})
		}
	case *ast.DeleteStatement:
		if s.Where == nil {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityError,
				Message:      fmt.Sprintf("DELETE from table %q without WHERE clause will remove all rows", s.TableName),
				Detail:       "A DELETE without a WHERE clause removes every row from the table. Use TRUNCATE if that is the intent, or add a WHERE clause to limit the scope.",
				Line:         1,
				Column:       1,
				SuggestedSQL: fmt.Sprintf("DELETE FROM %s WHERE <condition>", s.TableName),
			})
		}
	}

	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-003: Cartesian Product Detection
// ---------------------------------------------------------------------------

// CartesianProductRule detects implicit cross joins (multiple tables in FROM without JOIN conditions).
type CartesianProductRule struct{}

func (r *CartesianProductRule) ID() string   { return "OPT-003" }
func (r *CartesianProductRule) Name() string { return "Cartesian Product Detection" }
func (r *CartesianProductRule) Description() string {
	return "Detects implicit cross joins from multiple tables in FROM without corresponding join conditions in WHERE."
}

func (r *CartesianProductRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	// Only flag when there are 2+ real table references (not subqueries) and no JOINs
	tableCount := 0
	var tableNames []string
	for _, from := range sel.From {
		if from.Name != "" {
			tableCount++
			tableNames = append(tableNames, from.Name)
		}
	}

	if tableCount < 2 {
		return suggestions
	}

	// If there are explicit JOINs, the developer is using proper join syntax
	if len(sel.Joins) > 0 {
		return suggestions
	}

	// Check if the WHERE clause contains conditions linking the tables
	if sel.Where != nil && hasJoinCondition(sel.Where, tableNames) {
		return suggestions
	}

	suggestions = append(suggestions, Suggestion{
		RuleID:   r.ID(),
		Severity: SeverityWarning,
		Message:  fmt.Sprintf("Possible Cartesian product: tables %s listed without join condition", strings.Join(tableNames, ", ")),
		Detail:   "Multiple tables in the FROM clause without corresponding join conditions produce a Cartesian product (cross join), which can generate an extremely large result set. Use explicit JOIN syntax with ON conditions instead.",
		Line:     1,
		Column:   1,
		SuggestedSQL: fmt.Sprintf("SELECT ... FROM %s JOIN %s ON %s.id = %s.%s_id",
			tableNames[0], tableNames[1], tableNames[0], tableNames[1], tableNames[0]),
	})

	return suggestions
}

// hasJoinCondition checks if a WHERE expression contains a condition linking two different tables.
func hasJoinCondition(expr ast.Expression, tableNames []string) bool {
	if expr == nil {
		return false
	}

	if e, ok := expr.(*ast.BinaryExpression); ok {
		if e.Operator == "AND" || e.Operator == "OR" {
			return hasJoinCondition(e.Left, tableNames) || hasJoinCondition(e.Right, tableNames)
		}
		// Check if this is a table1.col = table2.col condition
		if e.Operator == "=" {
			leftTable := extractTableQualifier(e.Left)
			rightTable := extractTableQualifier(e.Right)
			if leftTable != "" && rightTable != "" && leftTable != rightTable {
				return true
			}
		}
	}

	return false
}

// extractTableQualifier returns the table qualifier from an identifier expression.
func extractTableQualifier(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		return id.Table
	}
	return ""
}

// ---------------------------------------------------------------------------
// OPT-004: SELECT DISTINCT Overuse
// ---------------------------------------------------------------------------

// DistinctOveruseRule warns when DISTINCT might indicate a JOIN issue.
type DistinctOveruseRule struct{}

func (r *DistinctOveruseRule) ID() string   { return "OPT-004" }
func (r *DistinctOveruseRule) Name() string { return "SELECT DISTINCT Overuse" }
func (r *DistinctOveruseRule) Description() string {
	return "Warns when DISTINCT is used, which may indicate a JOIN producing duplicates rather than the correct join conditions."
}

func (r *DistinctOveruseRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	if !sel.Distinct {
		return suggestions
	}

	// DISTINCT with JOINs is a stronger signal
	if len(sel.Joins) > 0 {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      "SELECT DISTINCT with JOINs may indicate incorrect join conditions",
			Detail:       "Using DISTINCT to remove duplicate rows often masks an underlying join problem. Review the join conditions to ensure they produce the correct result set without duplicates. DISTINCT also adds sorting overhead.",
			Line:         1,
			Column:       1,
			SuggestedSQL: "Review JOIN conditions or use GROUP BY for intentional aggregation",
		})
	} else {
		suggestions = append(suggestions, Suggestion{
			RuleID:   r.ID(),
			Severity: SeverityInfo,
			Message:  "SELECT DISTINCT adds sorting overhead - ensure it is necessary",
			Detail:   "DISTINCT forces the database to sort or hash the result set to eliminate duplicates. If the data is already unique (e.g., selecting a primary key), DISTINCT is unnecessary overhead.",
			Line:     1,
			Column:   1,
		})
	}

	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-005: Subquery in WHERE
// ---------------------------------------------------------------------------

// SubqueryInWhereRule suggests converting subqueries in WHERE to JOINs.
type SubqueryInWhereRule struct{}

func (r *SubqueryInWhereRule) ID() string   { return "OPT-005" }
func (r *SubqueryInWhereRule) Name() string { return "Subquery in WHERE Clause" }
func (r *SubqueryInWhereRule) Description() string {
	return "Detects subqueries in WHERE clauses and suggests converting to JOINs for better performance."
}

func (r *SubqueryInWhereRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	if sel.Where == nil {
		return suggestions
	}

	suggestions = append(suggestions, findWhereSubqueries(sel.Where, r.ID())...)

	return suggestions
}

// findWhereSubqueries recursively searches for subquery expressions in a WHERE clause.
func findWhereSubqueries(expr ast.Expression, ruleID string) []Suggestion {
	if expr == nil {
		return nil
	}

	var suggestions []Suggestion

	switch e := expr.(type) {
	case *ast.InExpression:
		if e.Subquery != nil {
			msg := "Subquery in IN clause - consider rewriting as a JOIN"
			detail := "Subqueries in IN clauses can cause the database to execute the subquery for each row in the outer query (correlated subquery behavior). Rewriting as a JOIN often allows the optimizer to use more efficient execution plans."
			suggestions = append(suggestions, Suggestion{
				RuleID:       ruleID,
				Severity:     SeverityWarning,
				Message:      msg,
				Detail:       detail,
				Line:         1,
				Column:       1,
				SuggestedSQL: "Rewrite as: SELECT ... FROM table1 JOIN table2 ON table1.col = table2.col",
			})
		}
	case *ast.ExistsExpression:
		suggestions = append(suggestions, Suggestion{
			RuleID:       ruleID,
			Severity:     SeverityInfo,
			Message:      "EXISTS subquery detected - verify it cannot be replaced with a JOIN",
			Detail:       "EXISTS subqueries are sometimes appropriate (especially for semi-joins), but consider whether a JOIN or IN clause would be clearer and equally performant.",
			Line:         1,
			Column:       1,
			SuggestedSQL: "Consider: SELECT ... FROM table1 JOIN table2 ON ...",
		})
	case *ast.SubqueryExpression:
		suggestions = append(suggestions, Suggestion{
			RuleID:   ruleID,
			Severity: SeverityWarning,
			Message:  "Scalar subquery in WHERE clause may impact performance",
			Detail:   "Scalar subqueries in WHERE clauses may be executed once per row. Consider materializing the result or rewriting as a JOIN if the subquery references outer query columns.",
			Line:     1,
			Column:   1,
		})
	case *ast.BinaryExpression:
		suggestions = append(suggestions, findWhereSubqueries(e.Left, ruleID)...)
		suggestions = append(suggestions, findWhereSubqueries(e.Right, ruleID)...)
	case *ast.UnaryExpression:
		suggestions = append(suggestions, findWhereSubqueries(e.Expr, ruleID)...)
	}

	return suggestions
}

// ---------------------------------------------------------------------------
// OPT-006: OR in WHERE
// ---------------------------------------------------------------------------

// OrInWhereRule warns about OR conditions that may prevent index usage.
type OrInWhereRule struct{}

func (r *OrInWhereRule) ID() string   { return "OPT-006" }
func (r *OrInWhereRule) Name() string { return "OR in WHERE Clause" }
func (r *OrInWhereRule) Description() string {
	return "Warns about OR conditions in WHERE clauses that may prevent index usage and suggests UNION alternatives."
}

func (r *OrInWhereRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	if sel.Where == nil {
		return suggestions
	}

	if containsOrCondition(sel.Where) {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "OR condition in WHERE clause may prevent index usage",
			Detail:       "When using OR between conditions on different columns, the database may not be able to use indexes efficiently and might resort to a full table scan. Consider rewriting as a UNION of separate queries, each targeting a specific index.",
			Line:         1,
			Column:       1,
			SuggestedSQL: "Rewrite as: SELECT ... WHERE cond1 UNION ALL SELECT ... WHERE cond2",
		})
	}

	return suggestions
}

// containsOrCondition checks if an expression tree contains a top-level OR condition
// on different columns.
func containsOrCondition(expr ast.Expression) bool {
	if expr == nil {
		return false
	}

	if e, ok := expr.(*ast.BinaryExpression); ok {
		if strings.EqualFold(e.Operator, "OR") {
			// Check if the OR operates on different columns
			leftCols := collectColumnNames(e.Left)
			rightCols := collectColumnNames(e.Right)

			// If the OR is on different columns, it likely prevents index usage
			if !columnsOverlap(leftCols, rightCols) && len(leftCols) > 0 && len(rightCols) > 0 {
				return true
			}
		}
		return containsOrCondition(e.Left) || containsOrCondition(e.Right)
	}

	return false
}

// collectColumnNames extracts all column identifiers from an expression.
func collectColumnNames(expr ast.Expression) []string {
	if expr == nil {
		return nil
	}

	var names []string

	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name != "*" {
			names = append(names, e.Name)
		}
	case *ast.BinaryExpression:
		names = append(names, collectColumnNames(e.Left)...)
		names = append(names, collectColumnNames(e.Right)...)
	case *ast.UnaryExpression:
		names = append(names, collectColumnNames(e.Expr)...)
	}

	return names
}

// columnsOverlap checks if two column name slices share any elements.
func columnsOverlap(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, name := range a {
		set[strings.ToLower(name)] = true
	}
	for _, name := range b {
		if set[strings.ToLower(name)] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// OPT-007: Leading Wildcard in LIKE
// ---------------------------------------------------------------------------

// LeadingWildcardLikeRule detects LIKE patterns starting with % which prevent index usage.
type LeadingWildcardLikeRule struct{}

func (r *LeadingWildcardLikeRule) ID() string   { return "OPT-007" }
func (r *LeadingWildcardLikeRule) Name() string { return "Leading Wildcard in LIKE" }
func (r *LeadingWildcardLikeRule) Description() string {
	return "Detects LIKE patterns with a leading wildcard (%) that prevent index usage."
}

func (r *LeadingWildcardLikeRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	if sel.Where == nil {
		return suggestions
	}

	suggestions = append(suggestions, findLeadingWildcardLike(sel.Where, r.ID())...)

	return suggestions
}

// findLeadingWildcardLike recursively searches for LIKE expressions with leading wildcards.
func findLeadingWildcardLike(expr ast.Expression, ruleID string) []Suggestion {
	if expr == nil {
		return nil
	}

	var suggestions []Suggestion

	switch e := expr.(type) {
	case *ast.BinaryExpression:
		if strings.EqualFold(e.Operator, "LIKE") || strings.EqualFold(e.Operator, "ILIKE") {
			if isLeadingWildcard(e.Right) {
				colName := identifierName(e.Left)
				suggestions = append(suggestions, Suggestion{
					RuleID:       ruleID,
					Severity:     SeverityWarning,
					Message:      fmt.Sprintf("Leading wildcard in LIKE pattern on column %q prevents index usage", colName),
					Detail:       "A LIKE pattern starting with %% (e.g., '%%search') forces a full table scan because the database cannot use a B-tree index to find matching rows. Consider using a full-text search index, a trigram index (pg_trgm), or restructuring the query.",
					Line:         1,
					Column:       1,
					SuggestedSQL: fmt.Sprintf("Use a full-text index: WHERE %s @@ to_tsquery('search_term')", colName),
				})
			}
		}
		// Recurse into AND/OR branches
		suggestions = append(suggestions, findLeadingWildcardLike(e.Left, ruleID)...)
		suggestions = append(suggestions, findLeadingWildcardLike(e.Right, ruleID)...)
	case *ast.UnaryExpression:
		suggestions = append(suggestions, findLeadingWildcardLike(e.Expr, ruleID)...)
	}

	return suggestions
}

// isLeadingWildcard checks if a literal value starts with %.
func isLeadingWildcard(expr ast.Expression) bool {
	if lit, ok := expr.(*ast.LiteralValue); ok {
		if s, ok := lit.Value.(string); ok {
			return strings.HasPrefix(s, "%")
		}
	}
	return false
}

// identifierName returns the name of an identifier expression, or a placeholder string.
func identifierName(expr ast.Expression) string {
	if id, ok := expr.(*ast.Identifier); ok {
		if id.Table != "" {
			return id.Table + "." + id.Name
		}
		return id.Name
	}
	return "<column>"
}

// ---------------------------------------------------------------------------
// OPT-008: Function on Indexed Column
// ---------------------------------------------------------------------------

// FunctionOnColumnRule detects function calls wrapping columns in WHERE clauses.
type FunctionOnColumnRule struct{}

func (r *FunctionOnColumnRule) ID() string   { return "OPT-008" }
func (r *FunctionOnColumnRule) Name() string { return "Function on Indexed Column" }
func (r *FunctionOnColumnRule) Description() string {
	return "Detects function calls wrapping columns in WHERE clauses which prevent index usage."
}

func (r *FunctionOnColumnRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	if sel.Where == nil {
		return suggestions
	}

	suggestions = append(suggestions, findFunctionOnColumn(sel.Where, r.ID())...)

	return suggestions
}

// findFunctionOnColumn recursively searches for function calls wrapping columns in comparisons.
func findFunctionOnColumn(expr ast.Expression, ruleID string) []Suggestion {
	if expr == nil {
		return nil
	}

	var suggestions []Suggestion

	switch e := expr.(type) {
	case *ast.BinaryExpression:
		// Check if the left side of a comparison is a function call on a column
		if isComparisonOperator(e.Operator) {
			if fn := extractFunctionOnColumn(e.Left); fn != nil {
				colName := extractColumnFromFunction(fn)
				suggestions = append(suggestions, Suggestion{
					RuleID:       ruleID,
					Severity:     SeverityWarning,
					Message:      fmt.Sprintf("Function %s() wrapping column %q in WHERE prevents index usage", fn.Name, colName),
					Detail:       "Applying a function to a column in a WHERE clause prevents the database from using an index on that column. Consider creating a functional index, using a computed/generated column, or restructuring the condition.",
					Line:         1,
					Column:       1,
					SuggestedSQL: fmt.Sprintf("Create a functional index: CREATE INDEX idx ON table (%s(%s))", strings.ToLower(fn.Name), colName),
				})
			}
			// Also check right side for symmetry
			if fn := extractFunctionOnColumn(e.Right); fn != nil {
				colName := extractColumnFromFunction(fn)
				suggestions = append(suggestions, Suggestion{
					RuleID:       ruleID,
					Severity:     SeverityWarning,
					Message:      fmt.Sprintf("Function %s() wrapping column %q in WHERE prevents index usage", fn.Name, colName),
					Detail:       "Applying a function to a column in a WHERE clause prevents the database from using an index on that column. Consider creating a functional index, using a computed/generated column, or restructuring the condition.",
					Line:         1,
					Column:       1,
					SuggestedSQL: fmt.Sprintf("Create a functional index: CREATE INDEX idx ON table (%s(%s))", strings.ToLower(fn.Name), colName),
				})
			}
		}

		// Recurse into AND/OR branches
		if strings.EqualFold(e.Operator, "AND") || strings.EqualFold(e.Operator, "OR") {
			suggestions = append(suggestions, findFunctionOnColumn(e.Left, ruleID)...)
			suggestions = append(suggestions, findFunctionOnColumn(e.Right, ruleID)...)
		}
	case *ast.UnaryExpression:
		suggestions = append(suggestions, findFunctionOnColumn(e.Expr, ruleID)...)
	}

	return suggestions
}

// extractFunctionOnColumn returns a FunctionCall if the expression is a function wrapping a column.
func extractFunctionOnColumn(expr ast.Expression) *ast.FunctionCall {
	fn, ok := expr.(*ast.FunctionCall)
	if !ok {
		return nil
	}

	// Check if the function has arguments that include a column reference
	for _, arg := range fn.Arguments {
		if _, ok := arg.(*ast.Identifier); ok {
			return fn
		}
	}

	return nil
}

// extractColumnFromFunction extracts the column name from a function call's arguments.
func extractColumnFromFunction(fn *ast.FunctionCall) string {
	for _, arg := range fn.Arguments {
		if id, ok := arg.(*ast.Identifier); ok {
			if id.Table != "" {
				return id.Table + "." + id.Name
			}
			return id.Name
		}
	}
	return "<column>"
}

// isComparisonOperator returns true if the operator is a comparison operator.
func isComparisonOperator(op string) bool {
	switch strings.ToUpper(op) {
	case "=", "<>", "!=", "<", ">", "<=", ">=", "LIKE", "ILIKE":
		return true
	}
	return false
}

// isStarIdentifier checks if an expression represents a star (*) column reference.
func isStarIdentifier(expr ast.Expression) bool {
	// Check through AliasedExpression wrappers
	if aliased, ok := expr.(*ast.AliasedExpression); ok {
		return isStarIdentifier(aliased.Expr)
	}

	if id, ok := expr.(*ast.Identifier); ok {
		return id.Name == "*"
	}

	return false
}
