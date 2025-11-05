package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func TestParserSimpleSelect(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "name"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if len(stmt.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
}

func TestParserComplexSelect(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "IDENT", Literal: "u"},
		{Type: "JOIN", Literal: "JOIN"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "IDENT", Literal: "o"},
		{Type: "ON", Literal: "ON"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: "=", Literal: "="},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "user_id"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "DESC", Literal: "DESC"},
		{Type: "LIMIT", Literal: "LIMIT"},
		{Type: "INT", Literal: "10"},
		{Type: "OFFSET", Literal: "OFFSET"},
		{Type: "INT", Literal: "20"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if len(stmt.Columns) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(stmt.Columns))
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
	if len(stmt.OrderBy) == 0 {
		t.Fatal("expected ORDER BY clause, got nil or empty")
	}
	if stmt.Limit == nil {
		t.Fatal("expected LIMIT clause, got nil")
	}
	if stmt.Offset == nil {
		t.Fatal("expected OFFSET clause, got nil")
	}
}

func TestParserInsert(t *testing.T) {
	tokens := []token.Token{
		{Type: "INSERT", Literal: "INSERT"},
		{Type: "INTO", Literal: "INTO"},
		{Type: "IDENT", Literal: "users"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "email"},
		{Type: ")", Literal: ")"},
		{Type: "VALUES", Literal: "VALUES"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "John"},
		{Type: ",", Literal: ","},
		{Type: "STRING", Literal: "john@example.com"},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatal("expected InsertStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if len(stmt.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
	}
	if len(stmt.Values) != 2 {
		t.Fatalf("expected 2 values, got %d", len(stmt.Values))
	}
}

func TestParserUpdate(t *testing.T) {
	tokens := []token.Token{
		{Type: "UPDATE", Literal: "UPDATE"},
		{Type: "IDENT", Literal: "users"},
		{Type: "SET", Literal: "SET"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "last_login"},
		{Type: "<", Literal: "<"},
		{Type: "STRING", Literal: "2024-01-01"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.UpdateStatement)
	if !ok {
		t.Fatal("expected UpdateStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if len(stmt.Updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(stmt.Updates))
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
}

func TestParserDelete(t *testing.T) {
	tokens := []token.Token{
		{Type: "DELETE", Literal: "DELETE"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.DeleteStatement)
	if !ok {
		t.Fatal("expected DeleteStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
}

func TestParserParallel(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	t.Run("Parallel", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 100; i++ {
			parser := NewParser()
			tree, err := parser.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tree == nil {
				t.Fatal("expected AST, got nil")
			}
			parser.Release()
		}
	})
}

func TestParserReuse(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	queries := [][]token.Token{
		{ // Simple SELECT
			{Type: "SELECT", Literal: "SELECT"},
			{Type: "IDENT", Literal: "id"},
			{Type: "FROM", Literal: "FROM"},
			{Type: "IDENT", Literal: "users"},
		},
		{ // INSERT
			{Type: "INSERT", Literal: "INSERT"},
			{Type: "INTO", Literal: "INTO"},
			{Type: "IDENT", Literal: "users"},
			{Type: "VALUES", Literal: "VALUES"},
			{Type: "(", Literal: "("},
			{Type: "STRING", Literal: "test"},
			{Type: ")", Literal: ")"},
		},
		{ // UPDATE
			{Type: "UPDATE", Literal: "UPDATE"},
			{Type: "IDENT", Literal: "users"},
			{Type: "SET", Literal: "SET"},
			{Type: "IDENT", Literal: "name"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "test"},
		},
	}

	for i, tokens := range queries {
		tree, err := parser.Parse(tokens)
		if err != nil {
			t.Fatalf("query %d: unexpected error: %v", i, err)
		}
		if tree == nil {
			t.Fatalf("query %d: expected AST, got nil", i)
		}
		if len(tree.Statements) != 1 {
			t.Fatalf("query %d: expected 1 statement, got %d", i, len(tree.Statements))
		}
	}
}

// TestRecursionDepthLimit_DeeplyNestedBinaryExpressions tests that deeply nested binary expressions
// are properly rejected when they exceed the maximum recursion depth.
func TestRecursionDepthLimit_DeeplyNestedBinaryExpressions(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build a deeply nested binary expression: a = b = c = d = ... (150 levels deep)
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "col"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
		{Type: "WHERE", Literal: "WHERE"},
	}

	// Add deeply nested binary expression
	for i := 0; i < 150; i++ {
		tokens = append(tokens,
			token.Token{Type: "IDENT", Literal: "x"},
			token.Token{Type: "=", Literal: "="},
		)
	}
	// Add final identifier to complete the expression
	tokens = append(tokens, token.Token{Type: "INT", Literal: "1"})

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for deeply nested binary expressions, got nil")
	}
	if err.Error() != "maximum recursion depth exceeded (100) - expression too deeply nested" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRecursionDepthLimit_DeeplyNestedFunctionCalls tests that deeply nested function calls
// are properly rejected when they exceed the maximum recursion depth.
func TestRecursionDepthLimit_DeeplyNestedFunctionCalls(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build tokens for: SELECT f1(f2(f3(...f150(x)...))) FROM t
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
	}

	// Add opening function calls
	for i := 0; i < 150; i++ {
		tokens = append(tokens,
			token.Token{Type: "IDENT", Literal: "func"},
			token.Token{Type: "(", Literal: "("},
		)
	}

	// Add innermost argument
	tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})

	// Add closing parentheses
	for i := 0; i < 150; i++ {
		tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
	}

	tokens = append(tokens,
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "t"},
	)

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for deeply nested function calls, got nil")
	}
	if !containsSubstring(err.Error(), "maximum recursion depth exceeded") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRecursionDepthLimit_DeeplyNestedCTEs tests that deeply nested CTEs
// are properly rejected when they exceed the maximum recursion depth.
func TestRecursionDepthLimit_DeeplyNestedCTEs(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build tokens for nested CTEs: WITH cte1 AS (WITH cte2 AS (WITH cte3 AS ...))
	tokens := []token.Token{}

	// Add nested WITH clauses (150 levels deep)
	for i := 0; i < 150; i++ {
		tokens = append(tokens,
			token.Token{Type: "WITH", Literal: "WITH"},
			token.Token{Type: "IDENT", Literal: "cte"},
			token.Token{Type: "AS", Literal: "AS"},
			token.Token{Type: "(", Literal: "("},
		)
	}

	// Add innermost SELECT
	tokens = append(tokens,
		token.Token{Type: "SELECT", Literal: "SELECT"},
		token.Token{Type: "IDENT", Literal: "x"},
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "t"},
	)

	// Close all CTEs
	for i := 0; i < 150; i++ {
		tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
	}

	// Add final SELECT
	tokens = append(tokens,
		token.Token{Type: "SELECT", Literal: "SELECT"},
		token.Token{Type: "*", Literal: "*"},
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "cte"},
	)

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for deeply nested CTEs, got nil")
	}
	if !containsSubstring(err.Error(), "maximum recursion depth exceeded") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRecursionDepthLimit_AtLimit tests that expressions at a reasonable depth work correctly.
func TestRecursionDepthLimit_AtLimit(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build a binary expression chain at a reasonable depth (50 levels)
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "col"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
		{Type: "WHERE", Literal: "WHERE"},
	}

	for i := 0; i < 50; i++ {
		tokens = append(tokens,
			token.Token{Type: "IDENT", Literal: "x"},
			token.Token{Type: "=", Literal: "="},
		)
	}
	tokens = append(tokens, token.Token{Type: "INT", Literal: "1"})

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("expected successful parse at reasonable depth, got error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
}

// TestRecursionDepthLimit_BarelyOverLimit tests edge case just over the limit.
func TestRecursionDepthLimit_BarelyOverLimit(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build tokens that will definitely exceed the limit
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "col"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
		{Type: "WHERE", Literal: "WHERE"},
	}

	for i := 0; i < 120; i++ {
		tokens = append(tokens,
			token.Token{Type: "IDENT", Literal: "x"},
			token.Token{Type: "=", Literal: "="},
		)
	}
	tokens = append(tokens, token.Token{Type: "INT", Literal: "1"})

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for expression just over limit, got nil")
	}
	if !containsSubstring(err.Error(), "maximum recursion depth exceeded") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRecursionDepthLimit_DepthResetAfterError tests that depth is properly reset after an error.
func TestRecursionDepthLimit_DepthResetAfterError(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// First, parse a query that exceeds the limit
	deepTokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "col"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
		{Type: "WHERE", Literal: "WHERE"},
	}

	for i := 0; i < 150; i++ {
		deepTokens = append(deepTokens,
			token.Token{Type: "IDENT", Literal: "x"},
			token.Token{Type: "=", Literal: "="},
		)
	}
	deepTokens = append(deepTokens, token.Token{Type: "INT", Literal: "1"})

	_, err := parser.Parse(deepTokens)
	if err == nil {
		t.Fatal("expected error for deeply nested expression")
	}

	// Now parse a simple query - it should succeed, proving depth was reset
	simpleTokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	tree, err := parser.Parse(simpleTokens)
	if err != nil {
		t.Fatalf("expected successful parse after error, got: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST after reset")
	}
}

// TestRecursionDepthLimit_RecursiveCTELimit tests recursive CTEs at a reasonable depth.
func TestRecursionDepthLimit_RecursiveCTELimit(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build a simple recursive CTE - this should work
	tokens := []token.Token{
		{Type: "WITH", Literal: "WITH"},
		{Type: "RECURSIVE", Literal: "RECURSIVE"},
		{Type: "IDENT", Literal: "cte"},
		{Type: "AS", Literal: "AS"},
		{Type: "(", Literal: "("},
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
		{Type: ")", Literal: ")"},
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "cte"},
	}

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("expected successful parse for simple recursive CTE, got: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
}

// TestRecursionDepthLimit_ComplexWindowFunctions tests window functions with nested expressions.
func TestRecursionDepthLimit_ComplexWindowFunctions(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Test a reasonable window function - should work
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "ROW_NUMBER"},
		{Type: "(", Literal: "("},
		{Type: ")", Literal: ")"},
		{Type: "OVER", Literal: "OVER"},
		{Type: "(", Literal: "("},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "id"},
		{Type: ")", Literal: ")"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "t"},
	}

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("expected successful parse for window function, got: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
}
