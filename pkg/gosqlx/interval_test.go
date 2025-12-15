// Package gosqlx - interval_test.go
// Integration tests for INTERVAL expression parsing (Issue #189)

package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParse_IntervalExpression_Simple tests basic INTERVAL expression parsing
func TestParse_IntervalExpression_Simple(t *testing.T) {
	sql := "SELECT INTERVAL '1 day'"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
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

	intervalExpr, ok := stmt.Columns[0].(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected IntervalExpression, got %T", stmt.Columns[0])
	}

	if intervalExpr.Value != "1 day" {
		t.Errorf("expected interval value '1 day', got '%s'", intervalExpr.Value)
	}

	if intervalExpr.TokenLiteral() != "INTERVAL" {
		t.Errorf("expected TokenLiteral 'INTERVAL', got '%s'", intervalExpr.TokenLiteral())
	}
}

// TestParse_IntervalExpression_WithArithmetic tests INTERVAL in arithmetic expressions
func TestParse_IntervalExpression_WithArithmetic(t *testing.T) {
	sql := "SELECT NOW() - INTERVAL '1 day'"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
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

	// The column should be a BinaryExpression (NOW() - INTERVAL '1 day')
	binExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Columns[0])
	}

	if binExpr.Operator != "-" {
		t.Errorf("expected operator '-', got '%s'", binExpr.Operator)
	}

	// Right side should be IntervalExpression
	intervalExpr, ok := binExpr.Right.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected right side to be IntervalExpression, got %T", binExpr.Right)
	}

	if intervalExpr.Value != "1 day" {
		t.Errorf("expected interval value '1 day', got '%s'", intervalExpr.Value)
	}
}

// TestParse_IntervalExpression_Multiple tests multiple INTERVAL values
func TestParse_IntervalExpression_Multiple(t *testing.T) {
	sql := "SELECT INTERVAL '2 hours', INTERVAL '30 days', INTERVAL '1 year'"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(stmt.Columns))
	}

	// Check first interval
	interval1, ok := stmt.Columns[0].(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected first column to be IntervalExpression, got %T", stmt.Columns[0])
	}
	if interval1.Value != "2 hours" {
		t.Errorf("expected first interval '2 hours', got '%s'", interval1.Value)
	}

	// Check second interval
	interval2, ok := stmt.Columns[1].(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected second column to be IntervalExpression, got %T", stmt.Columns[1])
	}
	if interval2.Value != "30 days" {
		t.Errorf("expected second interval '30 days', got '%s'", interval2.Value)
	}

	// Check third interval
	interval3, ok := stmt.Columns[2].(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected third column to be IntervalExpression, got %T", stmt.Columns[2])
	}
	if interval3.Value != "1 year" {
		t.Errorf("expected third interval '1 year', got '%s'", interval3.Value)
	}
}

// TestParse_IntervalExpression_InWhereClause tests INTERVAL in WHERE clause
func TestParse_IntervalExpression_InWhereClause(t *testing.T) {
	sql := "SELECT * FROM orders WHERE created_at > INTERVAL '30 days'"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// WHERE condition should be: created_at > INTERVAL '30 days'
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != ">" {
		t.Errorf("expected operator '>', got '%s'", binExpr.Operator)
	}

	// Right side of > should be INTERVAL
	intervalExpr, ok := binExpr.Right.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected right side to be IntervalExpression, got %T", binExpr.Right)
	}

	if intervalExpr.Value != "30 days" {
		t.Errorf("expected interval value '30 days', got '%s'", intervalExpr.Value)
	}
}

// TestParse_IntervalExpression_Addition tests INTERVAL with addition
func TestParse_IntervalExpression_Addition(t *testing.T) {
	sql := "SELECT created_at + INTERVAL '2 hours' FROM events"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
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

	// The column should be a BinaryExpression (created_at + INTERVAL '2 hours')
	binExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Columns[0])
	}

	if binExpr.Operator != "+" {
		t.Errorf("expected operator '+', got '%s'", binExpr.Operator)
	}

	// Right side should be IntervalExpression
	intervalExpr, ok := binExpr.Right.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected right side to be IntervalExpression, got %T", binExpr.Right)
	}

	if intervalExpr.Value != "2 hours" {
		t.Errorf("expected interval value '2 hours', got '%s'", intervalExpr.Value)
	}
}

// TestParse_IntervalExpression_ComplexValue tests INTERVAL with complex values
func TestParse_IntervalExpression_ComplexValue(t *testing.T) {
	sql := "SELECT INTERVAL '1 year 2 months 3 days'"

	tree, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
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

	intervalExpr, ok := stmt.Columns[0].(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected IntervalExpression, got %T", stmt.Columns[0])
	}

	if intervalExpr.Value != "1 year 2 months 3 days" {
		t.Errorf("expected interval value '1 year 2 months 3 days', got '%s'", intervalExpr.Value)
	}
}
