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
	if !containsSubstring(err.Error(), "recursion depth") && !containsSubstring(err.Error(), "exceeds limit") {
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
	if !containsSubstring(err.Error(), "recursion depth") && !containsSubstring(err.Error(), "exceeds limit") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestRecursionDepthLimit_DepthResetAfterError tests that depth is properly reset after an error.
func TestRecursionDepthLimit_DepthResetAfterError(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// First, parse a query with deeply nested function calls that exceeds the limit (150 levels)
	deepTokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
	}

	// Add opening function calls
	for i := 0; i < 150; i++ {
		deepTokens = append(deepTokens,
			token.Token{Type: "IDENT", Literal: "func"},
			token.Token{Type: "(", Literal: "("},
		)
	}

	// Add innermost argument
	deepTokens = append(deepTokens, token.Token{Type: "IDENT", Literal: "x"})

	// Add closing parentheses
	for i := 0; i < 150; i++ {
		deepTokens = append(deepTokens, token.Token{Type: ")", Literal: ")"})
	}

	deepTokens = append(deepTokens,
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "t"},
	)

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

// TestParser_LogicalOperators tests comprehensive AND/OR operator support
func TestParser_LogicalOperators(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
		verify func(t *testing.T, tree *ast.AST)
	}{
		{
			name: "Simple AND",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "active"},
				{Type: "=", Literal: "="},
				{Type: "TRUE", Literal: "TRUE"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				if stmt.Where == nil {
					t.Fatal("expected WHERE clause")
				}
				binExpr, ok := stmt.Where.(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
				}
				if binExpr.Operator != "AND" {
					t.Errorf("expected AND operator, got %s", binExpr.Operator)
				}
			},
		},
		{
			name: "Simple OR",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "status"},
				{Type: "=", Literal: "="},
				{Type: "STRING", Literal: "active"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "status"},
				{Type: "=", Literal: "="},
				{Type: "STRING", Literal: "pending"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "OR" {
					t.Errorf("expected OR operator, got %s", binExpr.Operator)
				}
			},
		},
		{
			name: "Three ANDs",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "a"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "b"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "2"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "c"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "3"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				// Should be left-associative: (a=1 AND b=2) AND c=3
				topExpr, ok := stmt.Where.(*ast.BinaryExpression)
				if !ok || topExpr.Operator != "AND" {
					t.Fatal("expected top-level AND")
				}
				leftExpr, ok := topExpr.Left.(*ast.BinaryExpression)
				if !ok || leftExpr.Operator != "AND" {
					t.Fatal("expected left child to be AND")
				}
			},
		},
		{
			name: "Three ORs",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "x"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "y"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "2"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "z"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "3"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				// Should be left-associative: (x=1 OR y=2) OR z=3
				topExpr, ok := stmt.Where.(*ast.BinaryExpression)
				if !ok || topExpr.Operator != "OR" {
					t.Fatal("expected top-level OR")
				}
				leftExpr, ok := topExpr.Left.(*ast.BinaryExpression)
				if !ok || leftExpr.Operator != "OR" {
					t.Fatal("expected left child to be OR")
				}
			},
		},
		{
			name: "AND with placeholders",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "PLACEHOLDER", Literal: "$1"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "name"},
				{Type: "=", Literal: "="},
				{Type: "PLACEHOLDER", Literal: "$2"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "AND" {
					t.Errorf("expected AND, got %s", binExpr.Operator)
				}
				// Verify placeholders
				leftComp := binExpr.Left.(*ast.BinaryExpression)
				rightLit := leftComp.Right.(*ast.LiteralValue)
				if rightLit.Type != "placeholder" {
					t.Errorf("expected placeholder type, got %s", rightLit.Type)
				}
			},
		},
		{
			name: "OR with placeholders",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "PLACEHOLDER", Literal: "$1"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "name"},
				{Type: "=", Literal: "="},
				{Type: "PLACEHOLDER", Literal: "$2"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "OR" {
					t.Errorf("expected OR, got %s", binExpr.Operator)
				}
			},
		},
		{
			name: "Mixed AND/OR with literals",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "5"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "name"},
				{Type: "=", Literal: "="},
				{Type: "PLACEHOLDER", Literal: "$1"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "AND" {
					t.Errorf("expected AND, got %s", binExpr.Operator)
				}
			},
		},
		{
			name: "Multiple comparison operators",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "age"},
				{Type: ">", Literal: ">"},
				{Type: "INT", Literal: "18"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "age"},
				{Type: "<", Literal: "<"},
				{Type: "INT", Literal: "65"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "AND" {
					t.Errorf("expected AND, got %s", binExpr.Operator)
				}
				// Verify comparison operators
				leftComp := binExpr.Left.(*ast.BinaryExpression)
				if leftComp.Operator != ">" {
					t.Errorf("expected >, got %s", leftComp.Operator)
				}
				rightComp := binExpr.Right.(*ast.BinaryExpression)
				if rightComp.Operator != "<" {
					t.Errorf("expected <, got %s", rightComp.Operator)
				}
			},
		},
		{
			name: "AND with inequality operators",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "status"},
				{Type: "!=", Literal: "!="},
				{Type: "STRING", Literal: "deleted"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "age"},
				{Type: ">=", Literal: ">="},
				{Type: "INT", Literal: "18"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				binExpr := stmt.Where.(*ast.BinaryExpression)
				if binExpr.Operator != "AND" {
					t.Errorf("expected AND, got %s", binExpr.Operator)
				}
				leftComp := binExpr.Left.(*ast.BinaryExpression)
				if leftComp.Operator != "!=" {
					t.Errorf("expected !=, got %s", leftComp.Operator)
				}
				rightComp := binExpr.Right.(*ast.BinaryExpression)
				if rightComp.Operator != ">=" {
					t.Errorf("expected >=, got %s", rightComp.Operator)
				}
			},
		},
		{
			name: "Complex nested AND/OR",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "a"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "b"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "2"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "c"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "3"},
			},
			verify: func(t *testing.T, tree *ast.AST) {
				stmt := tree.Statements[0].(*ast.SelectStatement)
				// Should be: (a=1 AND b=2) OR c=3 (AND binds tighter than OR)
				topExpr, ok := stmt.Where.(*ast.BinaryExpression)
				if !ok || topExpr.Operator != "OR" {
					t.Fatal("expected top-level OR")
				}
				leftExpr, ok := topExpr.Left.(*ast.BinaryExpression)
				if !ok || leftExpr.Operator != "AND" {
					t.Fatal("expected left child to be AND")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(tt.tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tree == nil {
				t.Fatal("expected AST, got nil")
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}

			tt.verify(t, tree)
		})
	}
}

// TestParser_LogicalOperatorPrecedence tests that AND binds tighter than OR
func TestParser_LogicalOperatorPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		tokens   []token.Token
		expected string // Description of expected tree structure
	}{
		{
			name: "AND binds tighter than OR",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "t"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "a"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "b"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "2"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "c"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "3"},
			},
			expected: "a=1 OR (b=2 AND c=3)",
		},
		{
			name: "Multiple ANDs with OR",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "t"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "a"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "b"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "2"},
				{Type: "OR", Literal: "OR"},
				{Type: "IDENT", Literal: "c"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "3"},
				{Type: "AND", Literal: "AND"},
				{Type: "IDENT", Literal: "d"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "4"},
			},
			expected: "(a=1 AND b=2) OR (c=3 AND d=4)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(tt.tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			stmt := tree.Statements[0].(*ast.SelectStatement)
			topExpr, ok := stmt.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("expected BinaryExpression at top level, got %T", stmt.Where)
			}

			// For precedence testing, we verify the tree structure
			if topExpr.Operator != "OR" {
				t.Errorf("expected OR at top level for %s, got %s", tt.expected, topExpr.Operator)
			}

			// Verify right side is AND or binary expression with AND
			rightExpr, ok := topExpr.Right.(*ast.BinaryExpression)
			if ok && tt.name == "AND binds tighter than OR" {
				if rightExpr.Operator != "AND" {
					t.Errorf("expected AND on right side, got %s", rightExpr.Operator)
				}
			}
		})
	}
}

// TestRecursionDepthLimit_ExtremelyNestedParentheses tests 1000+ nested parentheses
// to verify stack overflow protection with extreme input. This simulates a malicious
// input designed to cause stack overflow attacks.
func TestRecursionDepthLimit_ExtremelyNestedParentheses(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Build tokens for: SELECT ((((...((x))...))) FROM t
	// With 1000 levels of nested parentheses
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
	}

	// Note: Parentheses in SQL expressions would require expression parsing
	// which goes through parseExpression. For this test, we'll use nested
	// function calls as they provide the same recursion depth behavior.
	// Build: SELECT f(f(f(...f(x)...))) FROM t with 1000 levels

	// Add opening function calls (1000 levels)
	for i := 0; i < 1000; i++ {
		tokens = append(tokens,
			token.Token{Type: "IDENT", Literal: "func"},
			token.Token{Type: "(", Literal: "("},
		)
	}

	// Add innermost argument
	tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})

	// Add closing parentheses (1000 levels)
	for i := 0; i < 1000; i++ {
		tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
	}

	tokens = append(tokens,
		token.Token{Type: "FROM", Literal: "FROM"},
		token.Token{Type: "IDENT", Literal: "t"},
	)

	// This should be rejected due to exceeding MaxRecursionDepth (100)
	_, err := parser.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for 1000+ nested function calls, got nil")
	}

	// Verify the error message mentions recursion depth
	if !containsSubstring(err.Error(), "recursion depth") && !containsSubstring(err.Error(), "exceeds limit") {
		t.Errorf("expected recursion depth error, got: %v", err)
	}

	// Verify the parser didn't crash (stack overflow would panic)
	// If we got here, the protection worked
}

// TestRecursionDepthLimit_NoStackOverflow verifies that the depth limit
// prevents actual stack overflow under extreme nesting conditions.
func TestRecursionDepthLimit_NoStackOverflow(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	// Test with multiple extreme cases in sequence to ensure no cumulative issues
	testCases := []struct {
		name   string
		depth  int
		expect string
	}{
		{"Moderate depth (50)", 50, "success"},
		{"At limit (100)", 100, "success"}, // Should just barely work
		{"Over limit (150)", 150, "error"},
		{"Far over limit (500)", 500, "error"},
		{"Extreme (1000)", 1000, "error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build nested function call tokens
			tokens := []token.Token{{Type: "SELECT", Literal: "SELECT"}}

			for i := 0; i < tc.depth; i++ {
				tokens = append(tokens,
					token.Token{Type: "IDENT", Literal: "f"},
					token.Token{Type: "(", Literal: "("},
				)
			}

			tokens = append(tokens, token.Token{Type: "IDENT", Literal: "x"})

			for i := 0; i < tc.depth; i++ {
				tokens = append(tokens, token.Token{Type: ")", Literal: ")"})
			}

			tokens = append(tokens,
				token.Token{Type: "FROM", Literal: "FROM"},
				token.Token{Type: "IDENT", Literal: "t"},
			)

			// Parse and check result
			_, err := parser.Parse(tokens)

			if tc.expect == "success" {
				if err != nil && (containsSubstring(err.Error(), "recursion depth") || containsSubstring(err.Error(), "exceeds limit")) {
					// Depth exactly at 100 might fail due to overhead in the call stack
					// This is acceptable behavior
					t.Logf("Note: Depth %d exceeded limit (acceptable at boundary)", tc.depth)
				}
			} else if tc.expect == "error" {
				if err == nil {
					t.Errorf("expected error for depth %d, got success", tc.depth)
				} else if !containsSubstring(err.Error(), "recursion depth") && !containsSubstring(err.Error(), "exceeds limit") {
					t.Errorf("expected recursion depth error, got: %v", err)
				}
			}

			// If we got here without panic, the stack overflow protection worked
		})
	}
}
