// Package parser - cast_test.go
// Tests for CAST expression parsing (Issue #167)

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_CastExpression_Simple tests basic CAST expression parsing
func TestParser_CastExpression_Simple(t *testing.T) {
	// SELECT CAST(id AS VARCHAR) FROM users
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "VARCHAR"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	castExpr, ok := stmt.Columns[0].(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected CastExpression, got %T", stmt.Columns[0])
	}

	if castExpr.Type != "VARCHAR" {
		t.Errorf("expected type VARCHAR, got %s", castExpr.Type)
	}

	ident, ok := castExpr.Expr.(*ast.Identifier)
	if !ok || ident.Name != "id" {
		t.Error("expected Expr to be identifier 'id'")
	}
}

// TestParser_CastExpression_WithPrecision tests CAST with type precision
func TestParser_CastExpression_WithPrecision(t *testing.T) {
	// SELECT CAST(price AS DECIMAL(10,2)) FROM products
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "DECIMAL"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "2"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	castExpr := stmt.Columns[0].(*ast.CastExpression)

	if castExpr.Type != "DECIMAL(10,2)" {
		t.Errorf("expected type DECIMAL(10,2), got %s", castExpr.Type)
	}
}

// TestParser_CastExpression_VarcharWithLength tests CAST to VARCHAR with length
func TestParser_CastExpression_VarcharWithLength(t *testing.T) {
	// SELECT CAST(name AS VARCHAR(100)) FROM users
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "VARCHAR"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeNumber, Literal: "100"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	castExpr := stmt.Columns[0].(*ast.CastExpression)

	if castExpr.Type != "VARCHAR(100)" {
		t.Errorf("expected type VARCHAR(100), got %s", castExpr.Type)
	}
}

// TestParser_CastExpression_MultipleCasts tests multiple CAST expressions
func TestParser_CastExpression_MultipleCasts(t *testing.T) {
	// SELECT CAST(id AS VARCHAR), CAST(price AS DECIMAL) FROM products
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "VARCHAR"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "DECIMAL"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)

	if len(stmt.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
	}

	// Check first CAST
	cast1, ok := stmt.Columns[0].(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected first column to be CastExpression, got %T", stmt.Columns[0])
	}
	if cast1.Type != "VARCHAR" {
		t.Errorf("expected first CAST type VARCHAR, got %s", cast1.Type)
	}

	// Check second CAST
	cast2, ok := stmt.Columns[1].(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected second column to be CastExpression, got %T", stmt.Columns[1])
	}
	if cast2.Type != "DECIMAL" {
		t.Errorf("expected second CAST type DECIMAL, got %s", cast2.Type)
	}
}

// TestParser_CastExpression_WithArithmetic tests CAST with arithmetic expression
func TestParser_CastExpression_WithArithmetic(t *testing.T) {
	// SELECT CAST(price * 1.1 AS DECIMAL) FROM products
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "1.1"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "DECIMAL"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	castExpr := stmt.Columns[0].(*ast.CastExpression)

	// Verify the expression being cast is a binary expression (price * 1.1)
	if _, ok := castExpr.Expr.(*ast.BinaryExpression); !ok {
		t.Errorf("expected Expr to be BinaryExpression, got %T", castExpr.Expr)
	}
}

// TestParser_CastExpression_InWhereClause tests CAST in WHERE clause
func TestParser_CastExpression_InWhereClause(t *testing.T) {
	// SELECT * FROM users WHERE CAST(id AS INT) = 1
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "INT"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeNumber, Literal: "1"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)

	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// WHERE clause should be a binary expression (CAST(id AS INT) = 1)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression in WHERE, got %T", stmt.Where)
	}

	// Left side should be a CAST expression
	if _, ok := binExpr.Left.(*ast.CastExpression); !ok {
		t.Errorf("expected left side to be CastExpression, got %T", binExpr.Left)
	}
}

// TestParser_CastExpression_Nested tests nested CAST expressions
func TestParser_CastExpression_Nested(t *testing.T) {
	// SELECT CAST(CAST(id AS VARCHAR) AS TEXT) FROM users
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeCast, Literal: "CAST"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "VARCHAR"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "TEXT"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	outerCast := stmt.Columns[0].(*ast.CastExpression)

	if outerCast.Type != "TEXT" {
		t.Errorf("expected outer CAST type TEXT, got %s", outerCast.Type)
	}

	// Inner expression should be another CAST
	innerCast, ok := outerCast.Expr.(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected inner expression to be CastExpression, got %T", outerCast.Expr)
	}

	if innerCast.Type != "VARCHAR" {
		t.Errorf("expected inner CAST type VARCHAR, got %s", innerCast.Type)
	}
}
