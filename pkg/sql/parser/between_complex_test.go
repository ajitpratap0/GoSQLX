// Package parser - between_complex_test.go
// Comprehensive tests for BETWEEN with complex expressions (Issue #180)

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_BetweenWithIntervalArithmetic tests BETWEEN with INTERVAL expressions
// Example: SELECT * FROM orders WHERE created_at BETWEEN NOW() - INTERVAL '30 days' AND NOW()
func TestParser_BetweenWithIntervalArithmetic(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "created_at"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "NOW"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeMinus, Literal: "-"},
		{Type: models.TokenTypeInterval, Literal: "INTERVAL"},
		{Type: models.TokenTypeString, Literal: "30 days"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "NOW"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeRParen, Literal: ")"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "data"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "value"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "min_val"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "limits"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "max_val"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "limits"},
		{Type: models.TokenTypeRParen, Literal: ")"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "sales"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "amount"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "0.8"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypePlus, Literal: "+"},
		{Type: models.TokenTypeIdentifier, Literal: "discount"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "1.2"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeMinus, Literal: "-"},
		{Type: models.TokenTypeIdentifier, Literal: "fee"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "metrics"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "score"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "ROUND"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "AVG"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "baseline"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "CEIL"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "MAX"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "threshold"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "min_price"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "DECIMAL"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "max_price"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "DECIMAL"},
		{Type: models.TokenTypeRParen, Literal: ")"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "total"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeCase, Literal: "CASE"},
		{Type: models.TokenTypeWhen, Literal: "WHEN"},
		{Type: models.TokenTypeIdentifier, Literal: "discount"},
		{Type: models.TokenTypeThen, Literal: "THEN"},
		{Type: models.TokenTypeNumber, Literal: "100"},
		{Type: models.TokenTypeElse, Literal: "ELSE"},
		{Type: models.TokenTypeNumber, Literal: "200"},
		{Type: models.TokenTypeEnd, Literal: "END"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeNumber, Literal: "1000"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "0.5"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "2"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "full_name"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "first_name"},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeString, Literal: " A"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "first_name"},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeString, Literal: " Z"},
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
