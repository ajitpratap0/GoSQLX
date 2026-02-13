package schema

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// tableMapPool reuses map[string]string allocations for table alias resolution.
// This avoids allocating a new map for every validated statement.
var tableMapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]string, 8)
	},
}

// getTableMap retrieves a map from the pool.
func getTableMap() map[string]string {
	return tableMapPool.Get().(map[string]string)
}

// putTableMap clears and returns a map to the pool.
func putTableMap(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
	tableMapPool.Put(m)
}

// ValidationError represents a single validation issue found in a SQL query.
// Note: Line and Column are populated when position information is available
// from AST nodes. Currently, most AST nodes do not carry position data, so
// these fields will be 0 for most errors. Future AST enhancements will enable
// precise source location tracking.
type ValidationError struct {
	Message    string // Human-readable description of the issue
	Line       int    // Line number (1-based, 0 if unknown)
	Column     int    // Column number (1-based, 0 if unknown)
	Severity   string // "error" or "warning"
	Suggestion string // Optional suggestion for how to fix the issue
}

// Error returns a human-readable string for the validation error.
func (e ValidationError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s: %s (suggestion: %s)", e.Severity, e.Message, e.Suggestion)
	}
	return fmt.Sprintf("%s: %s", e.Severity, e.Message)
}

// Validator validates SQL queries against a schema.
type Validator struct {
	Schema *Schema
}

// NewValidator creates a new Validator for the given schema.
func NewValidator(schema *Schema) *Validator {
	return &Validator{Schema: schema}
}

// Validate parses a SQL query and validates it against the schema.
// Returns a slice of validation errors (which may be empty if valid)
// and an error if parsing fails.
func (v *Validator) Validate(sql string) ([]ValidationError, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}
	return v.ValidateAST(tree), nil
}

// ValidateAST checks a parsed AST against the schema and returns
// any validation errors found.
func (v *Validator) ValidateAST(tree *ast.AST) []ValidationError {
	var errors []ValidationError
	for _, stmt := range tree.Statements {
		errors = append(errors, v.validateStatement(stmt)...)
	}
	return errors
}

// validateStatement dispatches validation based on statement type.
// Performs both basic validation (table/column existence) and
// constraint validation (NOT NULL, type checking).
func (v *Validator) validateStatement(stmt ast.Statement) []ValidationError {
	var errors []ValidationError

	switch s := stmt.(type) {
	case *ast.SelectStatement:
		errors = append(errors, v.validateSelect(s)...)
	case *ast.InsertStatement:
		errors = append(errors, v.validateInsert(s)...)
	case *ast.UpdateStatement:
		errors = append(errors, v.validateUpdate(s)...)
	case *ast.DeleteStatement:
		errors = append(errors, v.validateDelete(s)...)
	}

	// Constraint-level validation (NOT NULL, type checking)
	errors = append(errors, v.validateConstraints(stmt)...)

	return errors
}

// validateSelect validates a SELECT statement against the schema.
func (v *Validator) validateSelect(s *ast.SelectStatement) []ValidationError {
	var errors []ValidationError

	// Build a map of available tables: alias -> tableName (pooled for reuse)
	tableMap := getTableMap()
	defer putTableMap(tableMap)

	// Validate FROM tables
	for _, ref := range s.From {
		if ref.Name == "" {
			continue // subquery, skip
		}
		tableName := ref.Name
		if _, ok := v.Schema.GetTable(tableName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("table %q does not exist in schema", tableName),
				Severity:   "error",
				Suggestion: v.suggestTable(tableName),
			})
		}
		if ref.Alias != "" {
			tableMap[ref.Alias] = tableName
		} else {
			tableMap[tableName] = tableName
		}
	}

	// Validate JOIN tables
	for _, join := range s.Joins {
		if join.Right.Name == "" {
			continue // subquery
		}
		tableName := join.Right.Name
		if _, ok := v.Schema.GetTable(tableName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("table %q does not exist in schema", tableName),
				Severity:   "error",
				Suggestion: v.suggestTable(tableName),
			})
		}
		if join.Right.Alias != "" {
			tableMap[join.Right.Alias] = tableName
		} else {
			tableMap[tableName] = tableName
		}
		// Also add the left side if it's a named table (for first join)
		if join.Left.Name != "" {
			leftName := join.Left.Name
			if join.Left.Alias != "" {
				tableMap[join.Left.Alias] = leftName
			} else {
				tableMap[leftName] = leftName
			}
		}
	}

	// Validate column references in SELECT columns
	errors = append(errors, v.validateColumnRefs(s.Columns, tableMap)...)

	// Validate column references in WHERE clause
	if s.Where != nil {
		errors = append(errors, v.validateExpressionColumns(s.Where, tableMap)...)
	}

	// Validate column references in JOIN conditions
	for _, join := range s.Joins {
		if join.Condition != nil {
			errors = append(errors, v.validateExpressionColumns(join.Condition, tableMap)...)
		}
	}

	// Validate column references in GROUP BY
	errors = append(errors, v.validateColumnRefs(s.GroupBy, tableMap)...)

	// Validate column references in HAVING
	if s.Having != nil {
		errors = append(errors, v.validateExpressionColumns(s.Having, tableMap)...)
	}

	return errors
}

// validateInsert validates an INSERT statement against the schema.
func (v *Validator) validateInsert(s *ast.InsertStatement) []ValidationError {
	var errors []ValidationError

	// Check target table exists
	tableName := s.TableName
	table, ok := v.Schema.GetTable(tableName)
	if !ok {
		errors = append(errors, ValidationError{
			Message:    fmt.Sprintf("table %q does not exist in schema", tableName),
			Severity:   "error",
			Suggestion: v.suggestTable(tableName),
		})
		return errors
	}

	// Validate column names if specified
	for _, colExpr := range s.Columns {
		colName := extractColumnName(colExpr)
		if colName == "" || colName == "*" {
			continue
		}
		if _, ok := table.GetColumn(colName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("column %q does not exist in table %q", colName, tableName),
				Severity:   "error",
				Suggestion: v.suggestColumn(table, colName),
			})
		}
	}

	// Validate INSERT column count matches VALUES count
	if len(s.Columns) > 0 && len(s.Values) > 0 {
		expectedCols := len(s.Columns)
		for i, row := range s.Values {
			if len(row) != expectedCols {
				errors = append(errors, ValidationError{
					Message: fmt.Sprintf(
						"INSERT column count (%d) does not match VALUES row %d count (%d)",
						expectedCols, i+1, len(row),
					),
					Severity: "error",
				})
			}
		}
	}

	return errors
}

// validateUpdate validates an UPDATE statement against the schema.
func (v *Validator) validateUpdate(s *ast.UpdateStatement) []ValidationError {
	var errors []ValidationError

	// Check target table exists
	tableName := s.TableName
	table, ok := v.Schema.GetTable(tableName)
	if !ok {
		errors = append(errors, ValidationError{
			Message:    fmt.Sprintf("table %q does not exist in schema", tableName),
			Severity:   "error",
			Suggestion: v.suggestTable(tableName),
		})
		return errors
	}

	// Build table map for column validation
	tableMap := getTableMap()
	defer putTableMap(tableMap)
	if s.Alias != "" {
		tableMap[s.Alias] = tableName
	} else {
		tableMap[tableName] = tableName
	}

	// Validate SET column names (using Updates field)
	for _, upd := range s.Updates {
		colName := extractColumnName(upd.Column)
		if colName == "" {
			continue
		}
		if _, ok := table.GetColumn(colName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("column %q does not exist in table %q", colName, tableName),
				Severity:   "error",
				Suggestion: v.suggestColumn(table, colName),
			})
		}
	}

	// Also check Assignments field for consistency
	for _, upd := range s.Assignments {
		colName := extractColumnName(upd.Column)
		if colName == "" {
			continue
		}
		if _, ok := table.GetColumn(colName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("column %q does not exist in table %q", colName, tableName),
				Severity:   "error",
				Suggestion: v.suggestColumn(table, colName),
			})
		}
	}

	// Validate WHERE clause column references
	if s.Where != nil {
		errors = append(errors, v.validateExpressionColumns(s.Where, tableMap)...)
	}

	return errors
}

// validateDelete validates a DELETE statement against the schema.
func (v *Validator) validateDelete(s *ast.DeleteStatement) []ValidationError {
	var errors []ValidationError

	// Check target table exists
	tableName := s.TableName
	if _, ok := v.Schema.GetTable(tableName); !ok {
		errors = append(errors, ValidationError{
			Message:    fmt.Sprintf("table %q does not exist in schema", tableName),
			Severity:   "error",
			Suggestion: v.suggestTable(tableName),
		})
		return errors
	}

	// Build table map for column validation
	tableMap := getTableMap()
	defer putTableMap(tableMap)
	if s.Alias != "" {
		tableMap[s.Alias] = tableName
	} else {
		tableMap[tableName] = tableName
	}

	// Validate WHERE clause column references
	if s.Where != nil {
		errors = append(errors, v.validateExpressionColumns(s.Where, tableMap)...)
	}

	return errors
}

// validateColumnRefs validates a list of expressions as column references.
func (v *Validator) validateColumnRefs(exprs []ast.Expression, tableMap map[string]string) []ValidationError {
	var errors []ValidationError
	for _, expr := range exprs {
		errors = append(errors, v.validateExpressionColumns(expr, tableMap)...)
	}
	return errors
}

// validateExpressionColumns recursively walks an expression tree and validates
// any column references found against the schema.
func (v *Validator) validateExpressionColumns(expr ast.Expression, tableMap map[string]string) []ValidationError {
	if expr == nil {
		return nil
	}

	var errors []ValidationError

	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name == "*" {
			return nil // wildcard, skip
		}
		if e.Table != "" {
			// Qualified reference: table.column
			errors = append(errors, v.validateQualifiedColumn(e.Table, e.Name, tableMap)...)
		} else {
			// Unqualified reference: just column name
			errors = append(errors, v.validateUnqualifiedColumn(e.Name, tableMap)...)
		}

	case *ast.AliasedExpression:
		// Validate the inner expression, not the alias
		errors = append(errors, v.validateExpressionColumns(e.Expr, tableMap)...)

	case *ast.BinaryExpression:
		errors = append(errors, v.validateExpressionColumns(e.Left, tableMap)...)
		errors = append(errors, v.validateExpressionColumns(e.Right, tableMap)...)

	case *ast.UnaryExpression:
		errors = append(errors, v.validateExpressionColumns(e.Expr, tableMap)...)

	case *ast.FunctionCall:
		for _, arg := range e.Arguments {
			errors = append(errors, v.validateExpressionColumns(arg, tableMap)...)
		}
		if e.Filter != nil {
			errors = append(errors, v.validateExpressionColumns(e.Filter, tableMap)...)
		}

	case *ast.BetweenExpression:
		errors = append(errors, v.validateExpressionColumns(e.Expr, tableMap)...)
		errors = append(errors, v.validateExpressionColumns(e.Lower, tableMap)...)
		errors = append(errors, v.validateExpressionColumns(e.Upper, tableMap)...)

	case *ast.InExpression:
		errors = append(errors, v.validateExpressionColumns(e.Expr, tableMap)...)
		for _, item := range e.List {
			errors = append(errors, v.validateExpressionColumns(item, tableMap)...)
		}

	case *ast.CaseExpression:
		if e.Value != nil {
			errors = append(errors, v.validateExpressionColumns(e.Value, tableMap)...)
		}
		for _, when := range e.WhenClauses {
			errors = append(errors, v.validateExpressionColumns(when.Condition, tableMap)...)
			errors = append(errors, v.validateExpressionColumns(when.Result, tableMap)...)
		}
		if e.ElseClause != nil {
			errors = append(errors, v.validateExpressionColumns(e.ElseClause, tableMap)...)
		}

	case *ast.CastExpression:
		errors = append(errors, v.validateExpressionColumns(e.Expr, tableMap)...)

	case *ast.LiteralValue:
		// Literals are always valid, nothing to check

	case *ast.ListExpression:
		for _, item := range e.Values {
			errors = append(errors, v.validateExpressionColumns(item, tableMap)...)
		}

	case *ast.TupleExpression:
		for _, item := range e.Expressions {
			errors = append(errors, v.validateExpressionColumns(item, tableMap)...)
		}

	case *ast.SubqueryExpression:
		// Don't validate subquery column refs against outer scope

	case *ast.ExistsExpression:
		// Don't validate subquery column refs against outer scope
	}

	return errors
}

// validateQualifiedColumn validates a table.column reference.
func (v *Validator) validateQualifiedColumn(tableRef, colName string, tableMap map[string]string) []ValidationError {
	var errors []ValidationError

	// Resolve the table alias to actual table name
	actualTableName, ok := tableMap[tableRef]
	if !ok {
		errors = append(errors, ValidationError{
			Message:    fmt.Sprintf("table or alias %q is not referenced in FROM clause", tableRef),
			Severity:   "error",
			Suggestion: v.suggestTable(tableRef),
		})
		return errors
	}

	// Look up the table in the schema
	table, ok := v.Schema.GetTable(actualTableName)
	if !ok {
		// Table doesn't exist in schema (already reported during FROM validation)
		return errors
	}

	// Check the column exists
	if colName != "*" {
		if _, ok := table.GetColumn(colName); !ok {
			errors = append(errors, ValidationError{
				Message:    fmt.Sprintf("column %q does not exist in table %q", colName, actualTableName),
				Severity:   "error",
				Suggestion: v.suggestColumn(table, colName),
			})
		}
	}

	return errors
}

// validateUnqualifiedColumn validates an unqualified column reference
// against all tables in scope. Produces warnings for ambiguous references.
func (v *Validator) validateUnqualifiedColumn(colName string, tableMap map[string]string) []ValidationError {
	var errors []ValidationError

	// Skip common expressions that look like column names but are not
	if colName == "*" {
		return nil
	}

	// Find which tables contain this column
	var matchingTables []string
	for _, actualTableName := range tableMap {
		table, ok := v.Schema.GetTable(actualTableName)
		if !ok {
			continue
		}
		if _, ok := table.GetColumn(colName); ok {
			matchingTables = append(matchingTables, actualTableName)
		}
	}

	// Deduplicate matching tables (same table may appear with different aliases)
	matchingTables = uniqueStrings(matchingTables)

	if len(matchingTables) == 0 {
		// Column not found in any table
		// Collect all available columns across all tables for suggestions
		errors = append(errors, ValidationError{
			Message:    fmt.Sprintf("column %q does not exist in any referenced table", colName),
			Severity:   "error",
			Suggestion: v.suggestColumnAcrossTables(colName, tableMap),
		})
	} else if len(matchingTables) > 1 {
		// Ambiguous column reference
		errors = append(errors, ValidationError{
			Message: fmt.Sprintf(
				"column %q is ambiguous, exists in multiple tables: %s",
				colName, strings.Join(matchingTables, ", "),
			),
			Severity:   "warning",
			Suggestion: fmt.Sprintf("qualify the column with a table name, e.g. %s.%s", matchingTables[0], colName),
		})
	}

	return errors
}

// suggestTable suggests a similar table name if one exists.
func (v *Validator) suggestTable(name string) string {
	names := v.Schema.TableNames()
	if suggestion := findClosest(name, names); suggestion != "" {
		return fmt.Sprintf("did you mean %q?", suggestion)
	}
	if len(names) > 0 {
		return fmt.Sprintf("available tables: %s", strings.Join(names, ", "))
	}
	return ""
}

// suggestColumn suggests a similar column name within a table.
func (v *Validator) suggestColumn(table *Table, name string) string {
	cols := table.ColumnNames()
	if suggestion := findClosest(name, cols); suggestion != "" {
		return fmt.Sprintf("did you mean %q?", suggestion)
	}
	if len(cols) > 0 {
		return fmt.Sprintf("available columns: %s", strings.Join(cols, ", "))
	}
	return ""
}

// suggestColumnAcrossTables suggests a similar column name from any table in scope.
func (v *Validator) suggestColumnAcrossTables(name string, tableMap map[string]string) string {
	var allCols []string
	seen := make(map[string]bool)
	for _, tableName := range tableMap {
		table, ok := v.Schema.GetTable(tableName)
		if !ok {
			continue
		}
		for _, col := range table.ColumnNames() {
			if !seen[col] {
				allCols = append(allCols, col)
				seen[col] = true
			}
		}
	}
	if suggestion := findClosest(name, allCols); suggestion != "" {
		return fmt.Sprintf("did you mean %q?", suggestion)
	}
	return ""
}

// extractColumnName extracts the column name from an expression.
func extractColumnName(expr ast.Expression) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *ast.Identifier:
		return e.Name
	case *ast.AliasedExpression:
		return extractColumnName(e.Expr)
	default:
		return ""
	}
}

// uniqueStrings returns a deduplicated, sorted copy of the input slice.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool, len(input))
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// findClosest finds the closest string in candidates to the target using
// a simple case-insensitive prefix/suffix match. Returns empty string
// if no close match is found.
func findClosest(target string, candidates []string) string {
	targetLower := strings.ToLower(target)

	// First try case-insensitive exact match
	for _, c := range candidates {
		if strings.ToLower(c) == targetLower {
			return c
		}
	}

	// Then try prefix match
	for _, c := range candidates {
		cLower := strings.ToLower(c)
		if strings.HasPrefix(cLower, targetLower) || strings.HasPrefix(targetLower, cLower) {
			return c
		}
	}

	// Then try Levenshtein distance <= 2
	var best string
	bestDist := 3 // threshold
	for _, c := range candidates {
		d := levenshtein(targetLower, strings.ToLower(c))
		if d < bestDist {
			bestDist = d
			best = c
		}
	}
	return best
}

// levenshtein computes the Levenshtein distance between two strings.
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use single-row DP for space efficiency
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// min3 returns the minimum of three integers.
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
