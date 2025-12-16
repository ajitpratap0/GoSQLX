// Package parser - between_complex_test.go
// Comprehensive tests for BETWEEN with complex expressions (Issue #180)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_BetweenWithIntervalArithmetic tests BETWEEN with INTERVAL expressions
// Example: SELECT * FROM orders WHERE created_at BETWEEN NOW() - INTERVAL '30 days' AND NOW()
func TestParser_BetweenWithIntervalArithmetic(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "created_at"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "IDENT", Literal: "NOW"},
		{Type: "(", Literal: "("},
		{Type: ")", Literal: ")"},
		{Type: "MINUS", Literal: "-"},
		{Type: "INTERVAL", Literal: "INTERVAL"},
		{Type: "STRING", Literal: "30 days"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "NOW"},
		{Type: "(", Literal: "("},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify main expression is 'created_at'
	ident, ok := betweenExpr.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected Expr to be Identifier, got %T", betweenExpr.Expr)
	}
	if ident.Name != "created_at" {
		t.Errorf("expected Expr name 'created_at', got '%s'", ident.Name)
	}

	// Verify lower bound is a binary expression (NOW() - INTERVAL '30 days')
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "-" {
		t.Errorf("expected lower bound operator '-', got '%s'", lowerBinary.Operator)
	}

	// Verify lower bound left side is NOW() function call
	lowerFunc, ok := lowerBinary.Left.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected lower bound left to be FunctionCall, got %T", lowerBinary.Left)
	}
	if lowerFunc.Name != "NOW" {
		t.Errorf("expected function name 'NOW', got '%s'", lowerFunc.Name)
	}

	// Verify lower bound right side is INTERVAL expression
	intervalExpr, ok := lowerBinary.Right.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected lower bound right to be IntervalExpression, got %T", lowerBinary.Right)
	}
	if intervalExpr.Value != "30 days" {
		t.Errorf("expected interval value '30 days', got '%s'", intervalExpr.Value)
	}

	// Verify upper bound is NOW() function call
	upperFunc, ok := betweenExpr.Upper.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected upper bound to be FunctionCall, got %T", betweenExpr.Upper)
	}
	if upperFunc.Name != "NOW" {
		t.Errorf("expected function name 'NOW', got '%s'", upperFunc.Name)
	}
}

// TestParser_BetweenWithSubqueries tests BETWEEN with subquery expressions
// Example: SELECT * FROM data WHERE value BETWEEN (SELECT min_val FROM limits) AND (SELECT max_val FROM limits)
func TestParser_BetweenWithSubqueries(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "data"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "value"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "(", Literal: "("},
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "min_val"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "limits"},
		{Type: ")", Literal: ")"},
		{Type: "AND", Literal: "AND"},
		{Type: "(", Literal: "("},
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "max_val"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "limits"},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify main expression is 'value'
	ident, ok := betweenExpr.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected Expr to be Identifier, got %T", betweenExpr.Expr)
	}
	if ident.Name != "value" {
		t.Errorf("expected Expr name 'value', got '%s'", ident.Name)
	}

	// Verify lower bound is a subquery
	lowerSubquery, ok := betweenExpr.Lower.(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be SubqueryExpression, got %T", betweenExpr.Lower)
	}

	lowerSelect, ok := lowerSubquery.Subquery.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected lower subquery to be SelectStatement, got %T", lowerSubquery.Subquery)
	}
	if len(lowerSelect.Columns) != 1 {
		t.Errorf("expected 1 column in lower subquery, got %d", len(lowerSelect.Columns))
	}

	// Verify upper bound is a subquery
	upperSubquery, ok := betweenExpr.Upper.(*ast.SubqueryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be SubqueryExpression, got %T", betweenExpr.Upper)
	}

	upperSelect, ok := upperSubquery.Subquery.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected upper subquery to be SelectStatement, got %T", upperSubquery.Subquery)
	}
	if len(upperSelect.Columns) != 1 {
		t.Errorf("expected 1 column in upper subquery, got %d", len(upperSelect.Columns))
	}
}

// TestParser_BetweenWithMixedComplexExpressions tests BETWEEN with various complex expression types
// Example: SELECT * FROM sales WHERE amount BETWEEN (price * 0.8) + discount AND (price * 1.2) - fee
func TestParser_BetweenWithMixedComplexExpressions(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "sales"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "amount"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "price"},
		{Type: "*", Literal: "*"},
		{Type: "FLOAT", Literal: "0.8"},
		{Type: ")", Literal: ")"},
		{Type: "PLUS", Literal: "+"},
		{Type: "IDENT", Literal: "discount"},
		{Type: "AND", Literal: "AND"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "price"},
		{Type: "*", Literal: "*"},
		{Type: "FLOAT", Literal: "1.2"},
		{Type: ")", Literal: ")"},
		{Type: "MINUS", Literal: "-"},
		{Type: "IDENT", Literal: "fee"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify main expression
	ident, ok := betweenExpr.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected Expr to be Identifier, got %T", betweenExpr.Expr)
	}
	if ident.Name != "amount" {
		t.Errorf("expected Expr name 'amount', got '%s'", ident.Name)
	}

	// Verify lower bound is addition: (price * 0.8) + discount
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "+" {
		t.Errorf("expected lower bound operator '+', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is subtraction: (price * 1.2) - fee
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "-" {
		t.Errorf("expected upper bound operator '-', got '%s'", upperBinary.Operator)
	}
}

// TestParser_BetweenWithNestedFunctionCalls tests BETWEEN with nested function calls
// Example: SELECT * FROM metrics WHERE score BETWEEN ROUND(AVG(baseline)) AND CEIL(MAX(threshold))
func TestParser_BetweenWithNestedFunctionCalls(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "metrics"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "score"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "IDENT", Literal: "ROUND"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "AVG"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "baseline"},
		{Type: ")", Literal: ")"},
		{Type: ")", Literal: ")"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "CEIL"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "MAX"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "threshold"},
		{Type: ")", Literal: ")"},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is ROUND function with nested AVG
	lowerFunc, ok := betweenExpr.Lower.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected lower bound to be FunctionCall, got %T", betweenExpr.Lower)
	}
	if lowerFunc.Name != "ROUND" {
		t.Errorf("expected lower function name 'ROUND', got '%s'", lowerFunc.Name)
	}
	if len(lowerFunc.Arguments) != 1 {
		t.Errorf("expected 1 argument for ROUND, got %d", len(lowerFunc.Arguments))
	}

	// Verify nested AVG function
	nestedAvg, ok := lowerFunc.Arguments[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected nested function to be FunctionCall, got %T", lowerFunc.Arguments[0])
	}
	if nestedAvg.Name != "AVG" {
		t.Errorf("expected nested function name 'AVG', got '%s'", nestedAvg.Name)
	}

	// Verify upper bound is CEIL function with nested MAX
	upperFunc, ok := betweenExpr.Upper.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected upper bound to be FunctionCall, got %T", betweenExpr.Upper)
	}
	if upperFunc.Name != "CEIL" {
		t.Errorf("expected upper function name 'CEIL', got '%s'", upperFunc.Name)
	}

	// Verify nested MAX function
	nestedMax, ok := upperFunc.Arguments[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected nested function to be FunctionCall, got %T", upperFunc.Arguments[0])
	}
	if nestedMax.Name != "MAX" {
		t.Errorf("expected nested function name 'MAX', got '%s'", nestedMax.Name)
	}
}

// TestParser_BetweenWithCastExpressions tests BETWEEN with CAST expressions
// Example: SELECT * FROM products WHERE price BETWEEN CAST(min_price AS DECIMAL) AND CAST(max_price AS DECIMAL)
func TestParser_BetweenWithCastExpressions(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "products"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "price"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "CAST", Literal: "CAST"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "min_price"},
		{Type: "AS", Literal: "AS"},
		{Type: "IDENT", Literal: "DECIMAL"},
		{Type: ")", Literal: ")"},
		{Type: "AND", Literal: "AND"},
		{Type: "CAST", Literal: "CAST"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "max_price"},
		{Type: "AS", Literal: "AS"},
		{Type: "IDENT", Literal: "DECIMAL"},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is a CAST expression
	lowerCast, ok := betweenExpr.Lower.(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected lower bound to be CastExpression, got %T", betweenExpr.Lower)
	}
	if lowerCast.Type != "DECIMAL" {
		t.Errorf("expected lower cast type 'DECIMAL', got '%s'", lowerCast.Type)
	}

	// Verify upper bound is a CAST expression
	upperCast, ok := betweenExpr.Upper.(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected upper bound to be CastExpression, got %T", betweenExpr.Upper)
	}
	if upperCast.Type != "DECIMAL" {
		t.Errorf("expected upper cast type 'DECIMAL', got '%s'", upperCast.Type)
	}
}

// TestParser_BetweenWithCaseExpressions tests BETWEEN with CASE expressions
// Example: SELECT * FROM orders WHERE total BETWEEN CASE WHEN discount THEN 100 ELSE 200 END AND 1000
func TestParser_BetweenWithCaseExpressions(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "total"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "discount"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "100"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "200"},
		{Type: "END", Literal: "END"},
		{Type: "AND", Literal: "AND"},
		{Type: "INT", Literal: "1000"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is a CASE expression
	lowerCase, ok := betweenExpr.Lower.(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected lower bound to be CaseExpression, got %T", betweenExpr.Lower)
	}
	if len(lowerCase.WhenClauses) != 1 {
		t.Errorf("expected 1 WHEN clause, got %d", len(lowerCase.WhenClauses))
	}

	// Verify upper bound is a literal
	upperLit, ok := betweenExpr.Upper.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected upper bound to be LiteralValue, got %T", betweenExpr.Upper)
	}
	if upperLit.Value != "1000" {
		t.Errorf("expected upper bound value '1000', got '%v'", upperLit.Value)
	}
}

// TestParser_NotBetweenWithComplexExpressions tests NOT BETWEEN with complex expressions
// Example: SELECT * FROM products WHERE price NOT BETWEEN price * 0.5 AND price * 2
func TestParser_NotBetweenWithComplexExpressions(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "products"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "price"},
		{Type: "NOT", Literal: "NOT"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "IDENT", Literal: "price"},
		{Type: "*", Literal: "*"},
		{Type: "FLOAT", Literal: "0.5"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "price"},
		{Type: "*", Literal: "*"},
		{Type: "INT", Literal: "2"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify NOT flag is set
	if !betweenExpr.Not {
		t.Error("expected NOT BETWEEN, but Not flag is false")
	}

	// Verify lower bound is multiplication
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "*" {
		t.Errorf("expected lower bound operator '*', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is multiplication
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "*" {
		t.Errorf("expected upper bound operator '*', got '%s'", upperBinary.Operator)
	}
}

// TestParser_BetweenWithStringConcatenation tests BETWEEN with string concatenation
// Example: SELECT * FROM users WHERE full_name BETWEEN first_name || ' A' AND first_name || ' Z'
func TestParser_BetweenWithStringConcatenation(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "full_name"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "IDENT", Literal: "first_name"},
		{Type: "STRING_CONCAT", Literal: "||"},
		{Type: "STRING", Literal: " A"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "first_name"},
		{Type: "STRING_CONCAT", Literal: "||"},
		{Type: "STRING", Literal: " Z"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BetweenExpression, got %T", stmt.Where)
	}

	// Verify lower bound is string concatenation
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "||" {
		t.Errorf("expected lower bound operator '||', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is string concatenation
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "||" {
		t.Errorf("expected upper bound operator '||', got '%s'", upperBinary.Operator)
	}
}
