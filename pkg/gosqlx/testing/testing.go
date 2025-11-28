// Package testing provides helper functions for testing SQL parsing in Go tests.
//
// This package offers convenient assertion and requirement functions for validating
// SQL parsing, formatting, and metadata extraction in your test suites. It integrates
// seamlessly with Go's standard testing package and follows similar patterns to
// testify/assert.
//
// Example usage:
//
//	func TestMySQL(t *testing.T) {
//	    testing.AssertValidSQL(t, "SELECT * FROM users")
//	    testing.AssertInvalidSQL(t, "SELECT FROM")
//	    testing.AssertTables(t, "SELECT * FROM users u JOIN orders o", []string{"users", "orders"})
//	}
//
// Key features:
//   - Clear, descriptive error messages with SQL context
//   - Proper test failure reporting with t.Helper()
//   - Support for both assertion (test continues) and requirement (test stops) styles
//   - Metadata extraction helpers (tables, columns)
package testing

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestingT is an interface wrapper around *testing.T to allow for mocking in tests.
// It includes the methods used by the helper functions.
type TestingT interface {
	Helper()
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

// Ensure *testing.T implements TestingT
var _ TestingT = (*testing.T)(nil)

// AssertValidSQL asserts that the given SQL is syntactically valid.
// If the SQL is invalid, the test continues but is marked as failed.
//
// Example:
//
//	testing.AssertValidSQL(t, "SELECT * FROM users WHERE active = true")
func AssertValidSQL(t TestingT, sql string) bool {
	t.Helper()

	err := gosqlx.Validate(sql)
	if err != nil {
		t.Errorf("Expected valid SQL, but got error:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
		return false
	}
	return true
}

// AssertInvalidSQL asserts that the given SQL is syntactically invalid.
// If the SQL is valid, the test continues but is marked as failed.
//
// Example:
//
//	testing.AssertInvalidSQL(t, "SELECT FROM WHERE")
func AssertInvalidSQL(t TestingT, sql string) bool {
	t.Helper()

	err := gosqlx.Validate(sql)
	if err == nil {
		t.Errorf("Expected invalid SQL, but it parsed successfully:\n  SQL: %s",
			truncateSQL(sql))
		return false
	}
	return true
}

// RequireValidSQL requires that the given SQL is syntactically valid.
// If the SQL is invalid, the test stops immediately.
//
// Example:
//
//	testing.RequireValidSQL(t, "SELECT * FROM users")
//	// Test continues only if SQL is valid
func RequireValidSQL(t TestingT, sql string) {
	t.Helper()

	err := gosqlx.Validate(sql)
	if err != nil {
		t.Fatalf("Required valid SQL, but got error:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
	}
}

// RequireInvalidSQL requires that the given SQL is syntactically invalid.
// If the SQL is valid, the test stops immediately.
//
// Example:
//
//	testing.RequireInvalidSQL(t, "SELECT FROM WHERE")
func RequireInvalidSQL(t TestingT, sql string) {
	t.Helper()

	err := gosqlx.Validate(sql)
	if err == nil {
		t.Fatalf("Required invalid SQL, but it parsed successfully:\n  SQL: %s",
			truncateSQL(sql))
	}
}

// AssertFormattedSQL asserts that the SQL formats to match the expected output.
// This validates both that the SQL is valid and that it formats correctly.
//
// Example:
//
//	testing.AssertFormattedSQL(t,
//	    "select * from users",
//	    "SELECT * FROM users;")
func AssertFormattedSQL(t TestingT, sql, expected string) bool {
	t.Helper()

	opts := gosqlx.DefaultFormatOptions()
	formatted, err := gosqlx.Format(sql, opts)
	if err != nil {
		t.Errorf("Failed to format SQL:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
		return false
	}

	// Normalize whitespace for comparison
	formattedNorm := strings.TrimSpace(formatted)
	expectedNorm := strings.TrimSpace(expected)

	if formattedNorm != expectedNorm {
		t.Errorf("Formatted SQL does not match expected:\n  Input: %s\n  Expected: %s\n  Got: %s",
			truncateSQL(sql), expectedNorm, formattedNorm)
		return false
	}
	return true
}

// AssertTables asserts that the SQL contains references to the expected tables.
// This extracts table names from the AST and compares them (order-independent).
//
// Example:
//
//	testing.AssertTables(t,
//	    "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
//	    []string{"users", "orders"})
func AssertTables(t TestingT, sql string, expectedTables []string) bool {
	t.Helper()

	astNode, err := gosqlx.Parse(sql)
	if err != nil {
		t.Errorf("Failed to parse SQL for table extraction:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
		return false
	}

	tables := extractTables(astNode)

	// Sort both slices for comparison
	sort.Strings(tables)
	expectedSorted := make([]string, len(expectedTables))
	copy(expectedSorted, expectedTables)
	sort.Strings(expectedSorted)

	if !stringSlicesEqual(tables, expectedSorted) {
		t.Errorf("SQL table references do not match expected:\n  SQL: %s\n  Expected: %v\n  Got: %v",
			truncateSQL(sql), expectedSorted, tables)
		return false
	}
	return true
}

// AssertColumns asserts that the SQL selects the expected columns.
// This extracts column names from SELECT statements and compares them (order-independent).
//
// Example:
//
//	testing.AssertColumns(t,
//	    "SELECT id, name, email FROM users",
//	    []string{"id", "name", "email"})
func AssertColumns(t TestingT, sql string, expectedColumns []string) bool {
	t.Helper()

	astNode, err := gosqlx.Parse(sql)
	if err != nil {
		t.Errorf("Failed to parse SQL for column extraction:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
		return false
	}

	columns := extractColumns(astNode)

	// Sort both slices for comparison
	sort.Strings(columns)
	expectedSorted := make([]string, len(expectedColumns))
	copy(expectedSorted, expectedColumns)
	sort.Strings(expectedSorted)

	if !stringSlicesEqual(columns, expectedSorted) {
		t.Errorf("SQL column references do not match expected:\n  SQL: %s\n  Expected: %v\n  Got: %v",
			truncateSQL(sql), expectedColumns, columns)
		return false
	}
	return true
}

// AssertParsesTo asserts that SQL parses to a specific AST statement type.
// This is useful for verifying that SQL is interpreted as the expected statement type.
//
// Example:
//
//	testing.AssertParsesTo(t, "SELECT * FROM users", &ast.SelectStatement{})
func AssertParsesTo(t TestingT, sql string, expectedType interface{}) bool {
	t.Helper()

	astNode, err := gosqlx.Parse(sql)
	if err != nil {
		t.Errorf("Failed to parse SQL:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
		return false
	}

	if astNode == nil || len(astNode.Statements) == 0 {
		t.Errorf("Parsed AST contains no statements:\n  SQL: %s", truncateSQL(sql))
		return false
	}

	stmt := astNode.Statements[0]
	expectedTypeName := fmt.Sprintf("%T", expectedType)
	actualTypeName := fmt.Sprintf("%T", stmt)

	if expectedTypeName != actualTypeName {
		t.Errorf("SQL parsed to unexpected statement type:\n  SQL: %s\n  Expected: %s\n  Got: %s",
			truncateSQL(sql), expectedTypeName, actualTypeName)
		return false
	}
	return true
}

// AssertErrorContains asserts that parsing the SQL produces an error containing the expected substring.
// This is useful for testing specific error conditions.
//
// Example:
//
//	testing.AssertErrorContains(t, "SELECT FROM WHERE", "unexpected token")
func AssertErrorContains(t TestingT, sql, expectedSubstring string) bool {
	t.Helper()

	_, err := gosqlx.Parse(sql)
	if err == nil {
		t.Errorf("Expected parsing error containing '%s', but SQL parsed successfully:\n  SQL: %s",
			expectedSubstring, truncateSQL(sql))
		return false
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, expectedSubstring) {
		t.Errorf("Error message does not contain expected substring:\n  SQL: %s\n  Expected substring: %s\n  Error: %v",
			truncateSQL(sql), expectedSubstring, err)
		return false
	}
	return true
}

// RequireParse requires that the SQL parses successfully and returns the AST.
// If parsing fails, the test stops immediately.
//
// Example:
//
//	ast := testing.RequireParse(t, "SELECT * FROM users")
//	// Use ast for further assertions
func RequireParse(t TestingT, sql string) *ast.AST {
	t.Helper()

	astNode, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Required SQL to parse, but got error:\n  SQL: %s\n  Error: %v",
			truncateSQL(sql), err)
	}
	return astNode
}

// Helper functions

// truncateSQL truncates long SQL strings for readable error messages
func truncateSQL(sql string) string {
	const maxLen = 100
	sql = strings.TrimSpace(sql)
	if len(sql) <= maxLen {
		return sql
	}
	return sql[:maxLen] + "..."
}

// extractTables extracts all table names from an AST
func extractTables(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	tables := make(map[string]bool)

	for _, stmt := range astNode.Statements {
		extractTablesFromNode(stmt, tables)
	}

	// Convert map to sorted slice
	result := make([]string, 0, len(tables))
	for table := range tables {
		result = append(result, table)
	}

	return result
}

// extractTablesFromNode recursively extracts table names from AST nodes
func extractTablesFromNode(node ast.Node, tables map[string]bool) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.SelectStatement:
		for _, from := range n.From {
			if from.Name != "" && !isSyntheticTableName(from.Name) {
				tables[from.Name] = true
			}
		}
		for _, join := range n.Joins {
			if join.Left.Name != "" && !isSyntheticTableName(join.Left.Name) {
				tables[join.Left.Name] = true
			}
			if join.Right.Name != "" && !isSyntheticTableName(join.Right.Name) {
				tables[join.Right.Name] = true
			}
		}
		if n.With != nil {
			for _, child := range n.With.Children() {
				extractTablesFromNode(child, tables)
			}
		}
	case *ast.InsertStatement:
		if n.TableName != "" && !isSyntheticTableName(n.TableName) {
			tables[n.TableName] = true
		}
	case *ast.UpdateStatement:
		if n.TableName != "" && !isSyntheticTableName(n.TableName) {
			tables[n.TableName] = true
		}
	case *ast.DeleteStatement:
		if n.TableName != "" && !isSyntheticTableName(n.TableName) {
			tables[n.TableName] = true
		}
	case *ast.TableReference:
		if n.Name != "" && !isSyntheticTableName(n.Name) {
			tables[n.Name] = true
		}
	case *ast.SetOperation:
		extractTablesFromNode(n.Left, tables)
		extractTablesFromNode(n.Right, tables)
	}

	// Recursively check children
	for _, child := range node.Children() {
		extractTablesFromNode(child, tables)
	}
}

// isSyntheticTableName checks if a table name is synthetic (generated by the parser)
func isSyntheticTableName(name string) bool {
	// Filter out synthetic table names that the parser may generate internally
	// These typically have parentheses or "_with_" patterns
	return strings.Contains(name, "(") || strings.Contains(name, "_with_") ||
		strings.HasPrefix(name, "_") || name == ""
}

// extractColumns extracts column names from SELECT statements
func extractColumns(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	columns := make(map[string]bool)

	for _, stmt := range astNode.Statements {
		if selectStmt, ok := stmt.(*ast.SelectStatement); ok {
			for _, col := range selectStmt.Columns {
				extractColumnNames(col, columns)
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(columns))
	for col := range columns {
		// Skip wildcard
		if col == "*" {
			continue
		}
		result = append(result, col)
	}

	return result
}

// extractColumnNames extracts column names from expressions
func extractColumnNames(expr ast.Expression, columns map[string]bool) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name != "" {
			columns[e.Name] = true
		}
	case *ast.FunctionCall:
		// Extract column names from function arguments
		for _, arg := range e.Arguments {
			extractColumnNames(arg, columns)
		}
	case *ast.BinaryExpression:
		extractColumnNames(e.Left, columns)
		extractColumnNames(e.Right, columns)
	}
}

// stringSlicesEqual compares two string slices for equality
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
