// Package gosqlx - between_complex_test.go
// End-to-end tests for BETWEEN with complex expressions using high-level API (Issue #180)

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParse_BetweenWithArithmeticExpressions tests BETWEEN with arithmetic via high-level API
func TestParse_BetweenWithArithmeticExpressions(t *testing.T) {
	sql := "SELECT * FROM products WHERE price BETWEEN price * 0.9 AND price * 1.1"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(astObj.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
	}

	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is multiplication
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "*" {
		t.Errorf("expected operator '*', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is multiplication
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "*" {
		t.Errorf("expected operator '*', got '%s'", upperBinary.Operator)
	}
}

// TestParse_BetweenWithIntervalArithmetic tests BETWEEN with INTERVAL expressions via high-level API
func TestParse_BetweenWithIntervalArithmetic(t *testing.T) {
	sql := "SELECT * FROM orders WHERE created_at BETWEEN NOW() - INTERVAL '30 days' AND NOW()"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := astObj.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is subtraction (NOW() - INTERVAL)
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "-" {
		t.Errorf("expected operator '-', got '%s'", lowerBinary.Operator)
	}

	// Verify INTERVAL expression in lower bound
	intervalExpr, ok := lowerBinary.Right.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected IntervalExpression, got %T", lowerBinary.Right)
	}
	if intervalExpr.Value != "30 days" {
		t.Errorf("expected interval '30 days', got '%s'", intervalExpr.Value)
	}
}

// TestParse_BetweenWithSubqueries tests BETWEEN with subqueries via high-level API
func TestParse_BetweenWithSubqueries(t *testing.T) {
	sql := "SELECT * FROM data WHERE value BETWEEN (SELECT min_val FROM limits) AND (SELECT max_val FROM limits)"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := astObj.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	// Verify both bounds are subqueries
	_, ok = betweenExpr.Lower.(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be SubqueryExpression, got %T", betweenExpr.Lower)
	}

	_, ok = betweenExpr.Upper.(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be SubqueryExpression, got %T", betweenExpr.Upper)
	}
}

// TestParse_BetweenWithFunctionCalls tests BETWEEN with function calls via high-level API
func TestParse_BetweenWithFunctionCalls(t *testing.T) {
	sql := "SELECT * FROM orders WHERE amount BETWEEN MIN(price) AND MAX(price) * 2"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := astObj.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is MIN function
	lowerFunc, ok := betweenExpr.Lower.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected lower bound to be FunctionCall, got %T", betweenExpr.Lower)
	}
	if lowerFunc.Name != "MIN" {
		t.Errorf("expected function 'MIN', got '%s'", lowerFunc.Name)
	}

	// Verify upper bound is arithmetic with MAX function
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}

	upperFunc, ok := upperBinary.Left.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected upper bound left to be FunctionCall, got %T", upperBinary.Left)
	}
	if upperFunc.Name != "MAX" {
		t.Errorf("expected function 'MAX', got '%s'", upperFunc.Name)
	}
}

// TestParse_BetweenComplexScenarios tests various complex BETWEEN scenarios
func TestParse_BetweenComplexScenarios(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectError bool
	}{
		{
			name:        "Arithmetic with addition",
			sql:         "SELECT * FROM t WHERE x BETWEEN a + b AND c + d",
			expectError: false,
		},
		{
			name:        "Arithmetic with subtraction",
			sql:         "SELECT * FROM t WHERE x BETWEEN a - b AND c - d",
			expectError: false,
		},
		{
			name:        "Mixed arithmetic",
			sql:         "SELECT * FROM t WHERE x BETWEEN a * b + c AND d / e - f",
			expectError: false,
		},
		{
			name:        "Nested function calls",
			sql:         "SELECT * FROM t WHERE x BETWEEN ROUND(AVG(y)) AND CEIL(MAX(z))",
			expectError: false,
		},
		{
			name:        "CAST expressions",
			sql:         "SELECT * FROM t WHERE x BETWEEN CAST(a AS INT) AND CAST(b AS INT)",
			expectError: false,
		},
		{
			name:        "String concatenation",
			sql:         "SELECT * FROM t WHERE x BETWEEN a || 'low' AND b || 'high'",
			expectError: false,
		},
		{
			name:        "Parenthesized expressions",
			sql:         "SELECT * FROM t WHERE x BETWEEN (a * 0.8) + discount AND (b * 1.2) - fee",
			expectError: false,
		},
		{
			name:        "INTERVAL arithmetic multiple",
			sql:         "SELECT * FROM t WHERE ts BETWEEN NOW() - INTERVAL '7 days' AND NOW() - INTERVAL '1 day'",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astObj, err := Parse(tt.sql)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(astObj.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(astObj.Statements))
			}

			stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
			}

			if stmt.Where == nil {
				t.Fatal("expected WHERE clause, got nil")
			}

			_, ok = stmt.Where.(*ast.BetweenExpression)
			if !ok {
				t.Fatalf("expected BetweenExpression in WHERE, got %T", stmt.Where)
			}
		})
	}
}

// TestParse_BetweenWithNotOperator tests NOT BETWEEN with complex expressions
func TestParse_BetweenWithNotOperator(t *testing.T) {
	sql := "SELECT * FROM products WHERE price NOT BETWEEN price * 0.5 AND price * 2"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := astObj.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	if !betweenExpr.Not {
		t.Error("expected NOT BETWEEN, but Not flag is false")
	}

	// Verify both bounds are arithmetic expressions
	_, ok = betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}

	_, ok = betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
}

// TestValidate_BetweenWithComplexExpressions tests Validate function with complex BETWEEN
func TestValidate_BetweenWithComplexExpressions(t *testing.T) {
	sqls := []string{
		"SELECT * FROM products WHERE price BETWEEN price * 0.9 AND price * 1.1",
		"SELECT * FROM orders WHERE created_at BETWEEN NOW() - INTERVAL '30 days' AND NOW()",
		"SELECT * FROM data WHERE value BETWEEN (SELECT MIN(x) FROM limits) AND (SELECT MAX(x) FROM limits)",
	}

	for _, sql := range sqls {
		t.Run(sql, func(t *testing.T) {
			err := Validate(sql)
			if err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestExtractMetadata_BetweenWithComplexExpressions tests ExtractMetadata function with complex BETWEEN
func TestExtractMetadata_BetweenWithComplexExpressions(t *testing.T) {
	sql := "SELECT id, name, price FROM products WHERE price BETWEEN price * 0.9 AND price * 1.1 ORDER BY price"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	metadata := ExtractMetadata(astObj)
	if metadata == nil {
		t.Fatal("expected metadata, got nil")
	}

	// Verify tables
	if len(metadata.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(metadata.Tables))
	}
	if metadata.Tables[0] != "products" {
		t.Errorf("expected table 'products', got '%s'", metadata.Tables[0])
	}

	// Verify columns (should include id, name, price)
	// Price appears multiple times: in SELECT list, WHERE clause, and ORDER BY
	expectedColumns := []string{"id", "name", "price"}
	for _, col := range expectedColumns {
		found := false
		for _, metadataCol := range metadata.Columns {
			if strings.Contains(strings.ToLower(metadataCol), col) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected column '%s' not found in metadata.Columns: %v", col, metadata.Columns)
		}
	}

	// Verify the AST structure
	stmt := astObj.Statements[0].(*ast.SelectStatement)
	if stmt.Where == nil {
		t.Error("expected WHERE clause, got nil")
	}
	if len(stmt.OrderBy) == 0 {
		t.Error("expected ORDER BY clause")
	}
}
