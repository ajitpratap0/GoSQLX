// Package parser - filter_clause_test.go
// Tests for FILTER clause parsing in aggregate functions (SQL:2003 T612)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// setupParserForFilter creates parser with tokenized SQL for FILTER tests
func setupParserForFilter(sql string) (*Parser, *ast.AST, error) {
	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, nil, err
	}

	// Parse tokens directly from model tokens
	parser := NewParser()
	astObj, err := parser.ParseFromModelTokens(tokens)
	return parser, astObj, err
}

// TestParser_FilterClause_BasicCount tests basic COUNT with FILTER
func TestParser_FilterClause_BasicCount(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER (WHERE id > 100) FROM users"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	if len(result.Statements) == 0 {
		t.Fatal("Expected at least one statement")
	}

	selectStmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SelectStatement")
	}

	if len(selectStmt.Columns) != 1 {
		t.Fatalf("Expected 1 column, got %d", len(selectStmt.Columns))
	}

	funcCall, ok := selectStmt.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatal("Expected FunctionCall")
	}

	if funcCall.Name != "COUNT" {
		t.Errorf("Expected COUNT, got %s", funcCall.Name)
	}

	if funcCall.Filter == nil {
		t.Fatal("Expected FILTER clause to be parsed")
	}

	// Verify filter condition is a binary expression
	binaryExpr, ok := funcCall.Filter.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("Expected BinaryExpression in filter, got %T", funcCall.Filter)
	}

	if binaryExpr.Operator != ">" {
		t.Errorf("Expected > operator, got %s", binaryExpr.Operator)
	}
}

// TestParser_FilterClause_Sum tests SUM with FILTER
func TestParser_FilterClause_Sum(t *testing.T) {
	sql := "SELECT SUM(amount) FILTER (WHERE year = 2024) FROM orders"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

	if funcCall.Name != "SUM" {
		t.Errorf("Expected SUM, got %s", funcCall.Name)
	}

	if len(funcCall.Arguments) != 1 {
		t.Fatalf("Expected 1 argument, got %d", len(funcCall.Arguments))
	}

	if funcCall.Filter == nil {
		t.Fatal("Expected FILTER clause to be parsed")
	}
}

// TestParser_FilterClause_MultipleAggregates tests multiple aggregates with FILTER
func TestParser_FilterClause_MultipleAggregates(t *testing.T) {
	sql := `SELECT
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE id > 100) as active_count,
		SUM(amount) FILTER (WHERE paid = true) as paid_total
	FROM orders`

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)

	if len(selectStmt.Columns) != 3 {
		t.Fatalf("Expected 3 columns, got %d", len(selectStmt.Columns))
	}

	// First column: COUNT(*) without FILTER
	aliasExpr1, ok := selectStmt.Columns[0].(*ast.AliasedExpression)
	if !ok {
		t.Fatal("Expected AliasedExpression for first column")
	}
	funcCall1, ok := aliasExpr1.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatal("Expected FunctionCall for first column")
	}
	if funcCall1.Filter != nil {
		t.Error("First COUNT should not have FILTER clause")
	}

	// Second column: COUNT(*) FILTER (WHERE id > 100)
	aliasExpr2, ok := selectStmt.Columns[1].(*ast.AliasedExpression)
	if !ok {
		t.Fatal("Expected AliasedExpression for second column")
	}
	funcCall2, ok := aliasExpr2.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatal("Expected FunctionCall for second column")
	}
	if funcCall2.Filter == nil {
		t.Error("Second COUNT should have FILTER clause")
	}

	// Third column: SUM(amount) FILTER (WHERE paid = true)
	aliasExpr3, ok := selectStmt.Columns[2].(*ast.AliasedExpression)
	if !ok {
		t.Fatal("Expected AliasedExpression for third column")
	}
	funcCall3, ok := aliasExpr3.Expr.(*ast.FunctionCall)
	if !ok {
		t.Fatal("Expected FunctionCall for third column")
	}
	if funcCall3.Filter == nil {
		t.Error("Third SUM should have FILTER clause")
	}
	if funcCall3.Name != "SUM" {
		t.Errorf("Expected SUM, got %s", funcCall3.Name)
	}
}

// TestParser_FilterClause_WithDistinct tests DISTINCT with FILTER
func TestParser_FilterClause_WithDistinct(t *testing.T) {
	sql := "SELECT COUNT(DISTINCT user_id) FILTER (WHERE active = true) FROM sessions"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

	if !funcCall.Distinct {
		t.Error("Expected DISTINCT to be set")
	}

	if funcCall.Filter == nil {
		t.Error("Expected FILTER clause")
	}

	if funcCall.Name != "COUNT" {
		t.Errorf("Expected COUNT, got %s", funcCall.Name)
	}
}

// TestParser_FilterClause_AvgMinMax tests other aggregate functions with FILTER
func TestParser_FilterClause_AvgMinMax(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		funcName string
	}{
		{
			name:     "AVG with FILTER",
			sql:      "SELECT AVG(score) FILTER (WHERE score > 0) FROM tests",
			funcName: "AVG",
		},
		{
			name:     "MIN with FILTER",
			sql:      "SELECT MIN(price) FILTER (WHERE available = true) FROM products",
			funcName: "MIN",
		},
		{
			name:     "MAX with FILTER",
			sql:      "SELECT MAX(salary) FILTER (WHERE salary > 0) FROM employees",
			funcName: "MAX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, result, err := setupParserForFilter(tt.sql)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			defer parser.Release()
			defer ast.ReleaseAST(result)

			selectStmt := result.Statements[0].(*ast.SelectStatement)
			funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

			if funcCall.Name != tt.funcName {
				t.Errorf("Expected %s, got %s", tt.funcName, funcCall.Name)
			}

			if funcCall.Filter == nil {
				t.Error("Expected FILTER clause")
			}
		})
	}
}

// TestParser_FilterClause_ComplexCondition tests FILTER with complex WHERE condition
func TestParser_FilterClause_ComplexCondition(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER (WHERE id > 100 AND amount > 1000) FROM orders"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

	if funcCall.Filter == nil {
		t.Fatal("Expected FILTER clause")
	}

	// Should be an AND binary expression
	andExpr, ok := funcCall.Filter.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("Expected BinaryExpression for AND, got %T", funcCall.Filter)
	}

	if andExpr.Operator != "AND" {
		t.Errorf("Expected AND operator, got %s", andExpr.Operator)
	}
}

// TestParser_FilterClause_Between tests FILTER with BETWEEN
func TestParser_FilterClause_Between(t *testing.T) {
	sql := "SELECT SUM(amount) FILTER (WHERE amount BETWEEN 100 AND 500) FROM orders"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

	if funcCall.Filter == nil {
		t.Fatal("Expected FILTER clause")
	}

	// Should be a BETWEEN expression
	betweenExpr, ok := funcCall.Filter.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("Expected BetweenExpression, got %T", funcCall.Filter)
	}

	if betweenExpr.Expr == nil || betweenExpr.Lower == nil || betweenExpr.Upper == nil {
		t.Error("BETWEEN expression should have Expr, Lower, and Upper")
	}
}

// TestParser_FilterClause_WithWindowFunction tests FILTER with window function (FILTER before OVER)
func TestParser_FilterClause_WithWindowFunction(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER (WHERE id > 100) OVER (PARTITION BY department) FROM employees"

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)
	funcCall := selectStmt.Columns[0].(*ast.FunctionCall)

	if funcCall.Filter == nil {
		t.Error("Expected FILTER clause")
	}

	if funcCall.Over == nil {
		t.Error("Expected OVER clause (window function)")
	}

	if len(funcCall.Over.PartitionBy) == 0 {
		t.Error("Expected PARTITION BY in window spec")
	}
}

// TestParser_FilterClause_ErrorMissingWhere tests error handling for missing WHERE
func TestParser_FilterClause_ErrorMissingWhere(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER (id > 100) FROM users"

	_, _, err := setupParserForFilter(sql)
	if err == nil {
		t.Fatal("Expected parse error for missing WHERE keyword")
	}

	// Error message should mention WHERE
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("Expected non-empty error message")
	}
}

// TestParser_FilterClause_ErrorMissingParenthesis tests error handling for missing parenthesis
func TestParser_FilterClause_ErrorMissingParenthesis(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER WHERE id > 100 FROM users"

	_, _, err := setupParserForFilter(sql)
	if err == nil {
		t.Fatal("Expected parse error for missing opening parenthesis")
	}
}

// TestParser_FilterClause_ErrorUnclosedParenthesis tests error handling for unclosed parenthesis
func TestParser_FilterClause_ErrorUnclosedParenthesis(t *testing.T) {
	sql := "SELECT COUNT(*) FILTER (WHERE id > 100 FROM users"

	_, _, err := setupParserForFilter(sql)
	if err == nil {
		t.Fatal("Expected parse error for unclosed parenthesis")
	}
}

// TestParser_FilterClause_RealWorldExample tests realistic production queries
func TestParser_FilterClause_RealWorldExample(t *testing.T) {
	sql := `
	SELECT
		customer_id,
		COUNT(*) as total_orders,
		COUNT(*) FILTER (WHERE status_id = 1) as completed_orders,
		COUNT(*) FILTER (WHERE status_id = 2) as cancelled_orders,
		SUM(amount) as total_amount,
		SUM(amount) FILTER (WHERE status_id = 1) as revenue,
		AVG(amount) FILTER (WHERE status_id = 1) as avg_order_value
	FROM orders
	WHERE created_at >= 1704067200
	GROUP BY customer_id
	ORDER BY customer_id DESC
	`

	parser, result, err := setupParserForFilter(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	defer parser.Release()
	defer ast.ReleaseAST(result)

	selectStmt := result.Statements[0].(*ast.SelectStatement)

	if len(selectStmt.Columns) != 7 {
		t.Fatalf("Expected 7 columns, got %d", len(selectStmt.Columns))
	}

	// Verify specific columns have FILTER
	columnsWithFilter := 0
	for i, col := range selectStmt.Columns {
		if aliasExpr, ok := col.(*ast.AliasedExpression); ok {
			if funcCall, ok := aliasExpr.Expr.(*ast.FunctionCall); ok {
				if funcCall.Filter != nil {
					columnsWithFilter++
					t.Logf("Column %d (%s) has FILTER clause", i, funcCall.Name)
				}
			}
		}
	}

	if columnsWithFilter != 4 {
		t.Errorf("Expected 4 columns with FILTER, got %d", columnsWithFilter)
	}
}
