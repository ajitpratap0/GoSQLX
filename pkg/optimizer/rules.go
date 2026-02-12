package optimizer

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
		&NPlusOneRule{},
		&IndexRecommendationRule{},
		&JoinOrderRule{},
		&QueryCostRule{},
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

	switch e := expr.(type) {
	case *ast.BinaryExpression:
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

	switch e := expr.(type) {
	case *ast.BinaryExpression:
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

// ---------------------------------------------------------------------------
// OPT-009: N+1 Query Detection
// ---------------------------------------------------------------------------

type NPlusOneRule struct{}

func (r *NPlusOneRule) ID() string   { return "OPT-009" }
func (r *NPlusOneRule) Name() string { return "N+1 Query Detection" }
func (r *NPlusOneRule) Description() string {
	return "Detects correlated subquery patterns that may indicate N+1 query problems."
}

func (r *NPlusOneRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}
	outerTables := collectOuterTables(sel)
	for _, col := range sel.Columns {
		if detectCorrelatedSubquery(col, outerTables) {
			suggestions = append(suggestions, Suggestion{
				RuleID:       r.ID(),
				Severity:     SeverityWarning,
				Message:      "Correlated subquery in SELECT list may cause N+1 query pattern",
				Detail:       "A correlated subquery in the SELECT list executes once per row. Rewrite as a JOIN or CTE.",
				Line:         1,
				Column:       1,
				SuggestedSQL: "Rewrite as: SELECT ... FROM outer JOIN inner ON ...",
			})
			break
		}
	}
	if sel.Where != nil && detectCorrelatedSubqueryInWhere(sel.Where, outerTables) {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      "Correlated subquery in WHERE clause may cause N+1 execution pattern",
			Detail:       "A correlated subquery in WHERE executes once per outer row. Consider rewriting as a JOIN.",
			Line:         1,
			Column:       1,
			SuggestedSQL: "Rewrite as a JOIN or use a well-indexed EXISTS clause",
		})
	}
	return suggestions
}

func collectOuterTables(sel *ast.SelectStatement) map[string]bool {
	tables := make(map[string]bool)
	for _, from := range sel.From {
		if from.Name != "" {
			tables[strings.ToLower(from.Name)] = true
		}
		if from.Alias != "" {
			tables[strings.ToLower(from.Alias)] = true
		}
	}
	return tables
}

func detectCorrelatedSubquery(expr ast.Expression, outerTables map[string]bool) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case *ast.AliasedExpression:
		return detectCorrelatedSubquery(e.Expr, outerTables)
	case *ast.SubqueryExpression:
		return stmtRefsOuterTables(e.Subquery, outerTables)
	case *ast.BinaryExpression:
		return detectCorrelatedSubquery(e.Left, outerTables) || detectCorrelatedSubquery(e.Right, outerTables)
	}
	return false
}

func detectCorrelatedSubqueryInWhere(expr ast.Expression, outerTables map[string]bool) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case *ast.SubqueryExpression:
		return stmtRefsOuterTables(e.Subquery, outerTables)
	case *ast.ExistsExpression:
		return stmtRefsOuterTables(e.Subquery, outerTables)
	case *ast.BinaryExpression:
		return detectCorrelatedSubqueryInWhere(e.Left, outerTables) || detectCorrelatedSubqueryInWhere(e.Right, outerTables)
	case *ast.UnaryExpression:
		return detectCorrelatedSubqueryInWhere(e.Expr, outerTables)
	}
	return false
}

func stmtRefsOuterTables(stmt ast.Statement, outerTables map[string]bool) bool {
	if stmt == nil {
		return false
	}
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return false
	}
	if sel.Where != nil {
		refs := gatherTableQualifiers(sel.Where)
		for _, ref := range refs {
			if outerTables[strings.ToLower(ref)] {
				return true
			}
		}
	}
	return false
}

func gatherTableQualifiers(expr ast.Expression) []string {
	if expr == nil {
		return nil
	}
	var refs []string
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Table != "" {
			refs = append(refs, e.Table)
		}
	case *ast.BinaryExpression:
		refs = append(refs, gatherTableQualifiers(e.Left)...)
		refs = append(refs, gatherTableQualifiers(e.Right)...)
	case *ast.UnaryExpression:
		refs = append(refs, gatherTableQualifiers(e.Expr)...)
	}
	return refs
}

// ---------------------------------------------------------------------------
// OPT-010: Index Recommendation
// ---------------------------------------------------------------------------

type IndexRecommendationRule struct{}

func (r *IndexRecommendationRule) ID() string   { return "OPT-010" }
func (r *IndexRecommendationRule) Name() string { return "Index Recommendation" }
func (r *IndexRecommendationRule) Description() string {
	return "Suggests indexes for columns used in WHERE, JOIN ON, and ORDER BY clauses."
}

func (r *IndexRecommendationRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}
	var whereCols []string
	if sel.Where != nil {
		whereCols = gatherFilterColumns(sel.Where)
	}
	var joinCols []string
	for _, join := range sel.Joins {
		if join.Condition != nil {
			joinCols = append(joinCols, gatherFilterColumns(join.Condition)...)
		}
	}
	var orderCols []string
	for _, ob := range sel.OrderBy {
		if id, ok := ob.Expression.(*ast.Identifier); ok {
			name := id.Name
			if id.Table != "" {
				name = id.Table + "." + name
			}
			orderCols = append(orderCols, name)
		}
	}
	if len(whereCols) > 0 && len(orderCols) > 0 {
		allCols := append(dedup(whereCols), dedup(orderCols)...)
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "Consider a composite index covering WHERE and ORDER BY columns",
			Detail:       "A composite index on filter + sort columns can avoid a separate sort step.",
			Line:         1,
			Column:       1,
			SuggestedSQL: fmt.Sprintf("CREATE INDEX idx_covering ON <table> (%s)", strings.Join(allCols, ", ")),
		})
	} else if len(whereCols) > 1 {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      "Consider a composite index on WHERE columns",
			Detail:       "Multiple WHERE columns may benefit from a composite index.",
			Line:         1,
			Column:       1,
			SuggestedSQL: fmt.Sprintf("CREATE INDEX idx_filter ON <table> (%s)", strings.Join(dedup(whereCols), ", ")),
		})
	}
	for _, col := range dedup(joinCols) {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      fmt.Sprintf("Ensure column %q used in JOIN has an index", col),
			Detail:       "Columns in JOIN conditions should be indexed.",
			Line:         1,
			Column:       1,
			SuggestedSQL: fmt.Sprintf("CREATE INDEX idx_%s ON <table> (%s)", strings.ReplaceAll(col, ".", "_"), col),
		})
	}
	return suggestions
}

func gatherFilterColumns(expr ast.Expression) []string {
	if expr == nil {
		return nil
	}
	var cols []string
	switch e := expr.(type) {
	case *ast.BinaryExpression:
		if isComparisonOperator(e.Operator) {
			if id, ok := e.Left.(*ast.Identifier); ok {
				name := id.Name
				if id.Table != "" {
					name = id.Table + "." + name
				}
				cols = append(cols, name)
			}
		} else if strings.EqualFold(e.Operator, "AND") || strings.EqualFold(e.Operator, "OR") {
			cols = append(cols, gatherFilterColumns(e.Left)...)
			cols = append(cols, gatherFilterColumns(e.Right)...)
		}
	}
	return cols
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// OPT-011: Join Order Optimization
// ---------------------------------------------------------------------------

type JoinOrderRule struct{}

func (r *JoinOrderRule) ID() string   { return "OPT-011" }
func (r *JoinOrderRule) Name() string { return "Join Order Optimization" }
func (r *JoinOrderRule) Description() string {
	return "Analyzes JOIN order and provides hints for optimal join sequencing."
}

func (r *JoinOrderRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}
	if len(sel.Joins) < 2 {
		return suggestions
	}
	joinsNoCond := 0
	for _, join := range sel.Joins {
		if join.Condition == nil {
			joinsNoCond++
		}
	}
	if joinsNoCond > 0 {
		suggestions = append(suggestions, Suggestion{
			RuleID:   r.ID(),
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("%d JOIN(s) without ON conditions in a multi-join query", joinsNoCond),
			Detail:   "JOINs without conditions produce Cartesian products.",
			Line:     1,
			Column:   1,
		})
	}
	if sel.Where != nil && len(sel.From) > 0 {
		filteredTbls := gatherFilteredTables(sel.Where)
		drivingTable := sel.From[0].Name
		for _, ft := range filteredTbls {
			if !strings.EqualFold(ft, drivingTable) && ft != "" {
				suggestions = append(suggestions, Suggestion{
					RuleID:       r.ID(),
					Severity:     SeverityInfo,
					Message:      fmt.Sprintf("Table %q has WHERE filters but is not the driving table", ft),
					Detail:       "Place the most filtered table first in FROM.",
					Line:         1,
					Column:       1,
					SuggestedSQL: fmt.Sprintf("FROM %s JOIN %s ON ...", ft, drivingTable),
				})
				break
			}
		}
	}
	if len(sel.Joins) >= 4 {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityInfo,
			Message:      fmt.Sprintf("Query joins %d tables — consider CTEs for readability", len(sel.Joins)+1),
			Detail:       "Queries with many joins can be hard to optimize.",
			Line:         1,
			Column:       1,
			SuggestedSQL: "WITH filtered AS (SELECT ... WHERE ...) SELECT ... FROM filtered JOIN ...",
		})
	}
	return suggestions
}

func gatherFilteredTables(expr ast.Expression) []string {
	if expr == nil {
		return nil
	}
	var tables []string
	switch e := expr.(type) {
	case *ast.BinaryExpression:
		if isComparisonOperator(e.Operator) {
			if id, ok := e.Left.(*ast.Identifier); ok && id.Table != "" {
				tables = append(tables, id.Table)
			}
		} else {
			tables = append(tables, gatherFilteredTables(e.Left)...)
			tables = append(tables, gatherFilteredTables(e.Right)...)
		}
	}
	return tables
}

// ---------------------------------------------------------------------------
// OPT-012: Query Cost Estimation
// ---------------------------------------------------------------------------

type QueryCostRule struct{}

func (r *QueryCostRule) ID() string   { return "OPT-012" }
func (r *QueryCostRule) Name() string { return "Query Cost Estimation" }
func (r *QueryCostRule) Description() string {
	return "Estimates query complexity by scoring structural elements and flags high-cost queries."
}

func (r *QueryCostRule) Analyze(stmt ast.Statement) []Suggestion {
	var suggestions []Suggestion
	cost := estimateStmtCost(stmt)
	if cost >= 20 {
		suggestions = append(suggestions, Suggestion{
			RuleID:       r.ID(),
			Severity:     SeverityWarning,
			Message:      fmt.Sprintf("High query complexity score: %d — consider simplifying", cost),
			Detail:       fmt.Sprintf("Structural complexity score of %d (scale: 1-50+). Scores above 20 indicate expensive queries.", cost),
			Line:         1,
			Column:       1,
			SuggestedSQL: "Break into CTEs: WITH step1 AS (...), step2 AS (...) SELECT ...",
		})
	} else if cost >= 10 {
		suggestions = append(suggestions, Suggestion{
			RuleID:   r.ID(),
			Severity: SeverityInfo,
			Message:  fmt.Sprintf("Moderate query complexity score: %d", cost),
			Detail:   fmt.Sprintf("Structural complexity score of %d. Ensure appropriate indexes exist.", cost),
			Line:     1,
			Column:   1,
		})
	}
	return suggestions
}

func estimateStmtCost(stmt ast.Statement) int {
	if stmt == nil {
		return 0
	}
	cost := 0
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		cost += 1
		for _, j := range s.Joins {
			switch strings.ToUpper(j.Type) {
			case "FULL", "CROSS":
				cost += 4
			case "LEFT", "RIGHT":
				cost += 3
			default:
				cost += 2
			}
		}
		for _, from := range s.From {
			if from.Subquery != nil {
				cost += 5
			}
		}
		cost += len(s.GroupBy) * 2
		if s.Having != nil {
			cost += 3
		}
		cost += len(s.Windows) * 3
		cost += len(s.OrderBy)
		if s.Distinct {
			cost += 2
		}
		if s.With != nil {
			for _, cte := range s.With.CTEs {
				cost += 3
				if cte.Statement != nil {
					cost += estimateStmtCost(cte.Statement)
				}
			}
		}
		if s.Where != nil {
			cost += countSubqCost(s.Where)
		}
	case *ast.SetOperation:
		cost += estimateStmtCost(s.Left) + estimateStmtCost(s.Right) + 3
	case *ast.UpdateStatement:
		cost += 2
		if s.Where == nil {
			cost += 5
		}
	case *ast.DeleteStatement:
		cost += 2
		if s.Where == nil {
			cost += 5
		}
	default:
		cost += 1
	}
	return cost
}

func countSubqCost(expr ast.Expression) int {
	if expr == nil {
		return 0
	}
	cost := 0
	switch e := expr.(type) {
	case *ast.SubqueryExpression:
		cost += 5
		if e.Subquery != nil {
			cost += estimateStmtCost(e.Subquery)
		}
	case *ast.InExpression:
		if e.Subquery != nil {
			cost += 4
		}
	case *ast.ExistsExpression:
		cost += 4
	case *ast.BinaryExpression:
		cost += countSubqCost(e.Left)
		cost += countSubqCost(e.Right)
	case *ast.UnaryExpression:
		cost += countSubqCost(e.Expr)
	}
	return cost
}
