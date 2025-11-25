package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_SearchedCaseExpression tests CASE WHEN condition THEN result END
func TestParser_SearchedCaseExpression(t *testing.T) {
	// SELECT CASE WHEN age > 18 THEN 1 ELSE 0 END FROM users
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "age"},
		{Type: ">", Literal: ">"},
		{Type: "INT", Literal: "18"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "1"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "0"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
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

	caseExpr, ok := stmt.Columns[0].(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected CaseExpression, got %T", stmt.Columns[0])
	}

	// Verify it's a searched CASE (no value)
	if caseExpr.Value != nil {
		t.Error("expected nil Value for searched CASE")
	}

	// Verify WHEN clause
	if len(caseExpr.WhenClauses) != 1 {
		t.Fatalf("expected 1 WHEN clause, got %d", len(caseExpr.WhenClauses))
	}

	// Verify ELSE clause
	if caseExpr.ElseClause == nil {
		t.Error("expected ELSE clause")
	}
}

// TestParser_SimpleCaseExpression tests CASE value WHEN match THEN result END
func TestParser_SimpleCaseExpression(t *testing.T) {
	// SELECT CASE status WHEN 1 THEN 2 ELSE 3 END FROM tasks
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "IDENT", Literal: "status"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "INT", Literal: "1"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "2"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "3"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "tasks"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	caseExpr := stmt.Columns[0].(*ast.CaseExpression)

	// Verify it's a simple CASE (has value)
	if caseExpr.Value == nil {
		t.Error("expected Value for simple CASE")
	}

	// Verify WHEN clause
	if len(caseExpr.WhenClauses) != 1 {
		t.Fatalf("expected 1 WHEN clause, got %d", len(caseExpr.WhenClauses))
	}

	// Verify ELSE clause
	if caseExpr.ElseClause == nil {
		t.Error("expected ELSE clause")
	}
}

// TestParser_CaseMultipleWhenClauses tests CASE with multiple WHEN clauses
func TestParser_CaseMultipleWhenClauses(t *testing.T) {
	// SELECT CASE WHEN age < 18 THEN 1 WHEN age < 65 THEN 2 ELSE 3 END FROM users
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "age"},
		{Type: "<", Literal: "<"},
		{Type: "INT", Literal: "18"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "1"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "age"},
		{Type: "<", Literal: "<"},
		{Type: "INT", Literal: "65"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "2"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "3"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	caseExpr := stmt.Columns[0].(*ast.CaseExpression)

	// Verify multiple WHEN clauses
	if len(caseExpr.WhenClauses) != 2 {
		t.Fatalf("expected 2 WHEN clauses, got %d", len(caseExpr.WhenClauses))
	}
}

// TestParser_CaseWithoutElse tests CASE without ELSE clause
func TestParser_CaseWithoutElse(t *testing.T) {
	// SELECT CASE WHEN active = TRUE THEN 1 END FROM users
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "1"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	caseExpr := stmt.Columns[0].(*ast.CaseExpression)

	// Verify no ELSE clause
	if caseExpr.ElseClause != nil {
		t.Error("expected nil ELSE clause")
	}
}

// TestParser_CaseInWhere tests CASE expressions in WHERE clause
func TestParser_CaseInWhere(t *testing.T) {
	// SELECT * FROM users WHERE CASE WHEN premium = TRUE THEN 1 ELSE 0 END = 1
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "premium"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "1"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "0"},
		{Type: "END", Literal: "END"},
		{Type: "=", Literal: "="},
		{Type: "INT", Literal: "1"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)

	// Verify WHERE clause exists
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// WHERE should be a binary expression (CASE expr = 1)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression in WHERE, got %T", stmt.Where)
	}

	// Left side should be CASE expression
	_, ok = binExpr.Left.(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected CaseExpression in WHERE, got %T", binExpr.Left)
	}
}

// TestParser_NestedCaseExpressions tests CASE expressions nested in WHEN/ELSE
func TestParser_NestedCaseExpressions(t *testing.T) {
	// SELECT CASE WHEN status = 1 THEN CASE priority WHEN 1 THEN 2 END ELSE 0 END FROM tasks
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "status"},
		{Type: "=", Literal: "="},
		{Type: "INT", Literal: "1"},
		{Type: "THEN", Literal: "THEN"},
		// Nested CASE starts here
		{Type: "CASE", Literal: "CASE"},
		{Type: "IDENT", Literal: "priority"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "INT", Literal: "1"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "2"},
		{Type: "END", Literal: "END"},
		// Back to outer CASE
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "0"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "tasks"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error parsing nested CASE: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	outerCase := stmt.Columns[0].(*ast.CaseExpression)

	// Verify outer CASE has one WHEN clause
	if len(outerCase.WhenClauses) != 1 {
		t.Fatalf("expected 1 WHEN clause in outer CASE, got %d", len(outerCase.WhenClauses))
	}

	// Verify THEN result is a nested CASE
	innerCase, ok := outerCase.WhenClauses[0].Result.(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected nested CaseExpression in THEN, got %T", outerCase.WhenClauses[0].Result)
	}

	// Verify inner CASE is a simple CASE with value
	if innerCase.Value == nil {
		t.Error("expected Value in inner CASE")
	}
}

// TestParser_CaseWithStrings tests CASE with string literals
func TestParser_CaseWithStrings(t *testing.T) {
	// SELECT CASE status WHEN 'active' THEN 'ok' ELSE 'not ok' END FROM users
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "IDENT", Literal: "status"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "STRING", Literal: "active"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "STRING", Literal: "ok"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "STRING", Literal: "not ok"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	caseExpr := stmt.Columns[0].(*ast.CaseExpression)

	// Verify it's a simple CASE
	if caseExpr.Value == nil {
		t.Error("expected Value in simple CASE")
	}

	// Verify WHEN clause contains string literal
	if len(caseExpr.WhenClauses) != 1 {
		t.Fatalf("expected 1 WHEN clause, got %d", len(caseExpr.WhenClauses))
	}

	whenLit, ok := caseExpr.WhenClauses[0].Condition.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected LiteralValue in WHEN, got %T", caseExpr.WhenClauses[0].Condition)
	}

	if whenLit.Type != "string" {
		t.Errorf("expected string type, got %s", whenLit.Type)
	}
}

// TestParser_CaseWithComplexConditions tests CASE with AND/OR in conditions
func TestParser_CaseWithComplexConditions(t *testing.T) {
	// SELECT CASE WHEN status = 1 AND active = TRUE THEN 1 ELSE 0 END FROM users
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "status"},
		{Type: "=", Literal: "="},
		{Type: "INT", Literal: "1"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "1"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "0"},
		{Type: "END", Literal: "END"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	caseExpr := stmt.Columns[0].(*ast.CaseExpression)

	// Verify WHEN clause has complex condition
	if len(caseExpr.WhenClauses) != 1 {
		t.Fatalf("expected 1 WHEN clause, got %d", len(caseExpr.WhenClauses))
	}

	// Condition should be a binary expression (AND)
	_, ok := caseExpr.WhenClauses[0].Condition.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression in WHEN condition, got %T", caseExpr.WhenClauses[0].Condition)
	}
}

// TestParser_CaseInOrderBy tests CASE in ORDER BY clause
func TestParser_CaseInOrderBy(t *testing.T) {
	// SELECT * FROM users ORDER BY CASE status WHEN 1 THEN 0 ELSE 1 END
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "CASE", Literal: "CASE"},
		{Type: "IDENT", Literal: "status"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "INT", Literal: "1"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "INT", Literal: "0"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "1"},
		{Type: "END", Literal: "END"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)

	// Verify ORDER BY clause
	if len(stmt.OrderBy) != 1 {
		t.Fatalf("expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}

	// Verify ORDER BY expression is CASE
	_, ok := stmt.OrderBy[0].Expression.(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected CaseExpression in ORDER BY, got %T", stmt.OrderBy[0].Expression)
	}
}

// TestParser_CaseInFunctionArgument tests CASE as function argument
func TestParser_CaseInFunctionArgument(t *testing.T) {
	// SELECT SUM(CASE WHEN status = 1 THEN amount ELSE 0 END) FROM orders
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "SUM"},
		{Type: "(", Literal: "("},
		{Type: "CASE", Literal: "CASE"},
		{Type: "WHEN", Literal: "WHEN"},
		{Type: "IDENT", Literal: "status"},
		{Type: "=", Literal: "="},
		{Type: "INT", Literal: "1"},
		{Type: "THEN", Literal: "THEN"},
		{Type: "IDENT", Literal: "amount"},
		{Type: "ELSE", Literal: "ELSE"},
		{Type: "INT", Literal: "0"},
		{Type: "END", Literal: "END"},
		{Type: ")", Literal: ")"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "orders"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)

	// Verify column is a function call
	funcCall, ok := stmt.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected FunctionCall, got %T", stmt.Columns[0])
	}

	// Verify function has CASE as argument
	if len(funcCall.Arguments) != 1 {
		t.Fatalf("expected 1 argument, got %d", len(funcCall.Arguments))
	}

	_, ok = funcCall.Arguments[0].(*ast.CaseExpression)
	if !ok {
		t.Fatalf("expected CaseExpression as argument, got %T", funcCall.Arguments[0])
	}
}

// TestParser_CaseErrorCases tests error handling in CASE expressions
func TestParser_CaseErrorCases(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name: "CASE without END",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "CASE", Literal: "CASE"},
				{Type: "WHEN", Literal: "WHEN"},
				{Type: "INT", Literal: "1"},
				{Type: "THEN", Literal: "THEN"},
				{Type: "INT", Literal: "2"},
				{Type: "FROM", Literal: "FROM"}, // Missing END
				{Type: "IDENT", Literal: "users"},
			},
		},
		{
			name: "CASE without THEN",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "CASE", Literal: "CASE"},
				{Type: "WHEN", Literal: "WHEN"},
				{Type: "INT", Literal: "1"},
				{Type: "INT", Literal: "2"}, // Missing THEN
				{Type: "END", Literal: "END"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
