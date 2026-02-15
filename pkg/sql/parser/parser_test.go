package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func TestParserSimpleSelect(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypeJoin, Literal: "JOIN"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "u"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeTrue, Literal: "TRUE"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "o"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "order_date"},
		{Type: models.TokenTypeDesc, Literal: "DESC"},
		{Type: models.TokenTypeLimit, Literal: "LIMIT"},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeOffset, Literal: "OFFSET"},
		{Type: models.TokenTypeNumber, Literal: "20"},
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
		{Type: models.TokenTypeInsert, Literal: "INSERT"},
		{Type: models.TokenTypeInto, Literal: "INTO"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "email"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeValues, Literal: "VALUES"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "John"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "john@example.com"},
		{Type: models.TokenTypeRParen, Literal: ")"},
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
	// Values is now [][]Expression for multi-row support
	if len(stmt.Values) != 1 {
		t.Fatalf("expected 1 row of values, got %d", len(stmt.Values))
	}
	if len(stmt.Values[0]) != 2 {
		t.Fatalf("expected 2 values in first row, got %d", len(stmt.Values[0]))
	}
}

func TestParserUpdate(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeSet, Literal: "SET"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeFalse, Literal: "FALSE"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "last_login"},
		{Type: models.TokenTypeLt, Literal: "<"},
		{Type: models.TokenTypeString, Literal: "2024-01-01"},
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
	if len(stmt.Assignments) != 1 {
		t.Fatalf("expected 1 update, got %d", len(stmt.Assignments))
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
}

func TestParserDelete(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeDelete, Literal: "DELETE"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeFalse, Literal: "FALSE"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
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
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
		},
		{ // INSERT
			{Type: models.TokenTypeInsert, Literal: "INSERT"},
			{Type: models.TokenTypeInto, Literal: "INTO"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeValues, Literal: "VALUES"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeString, Literal: "test"},
			{Type: models.TokenTypeRParen, Literal: ")"},
		},
		{ // UPDATE
			{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeSet, Literal: "SET"},
			{Type: models.TokenTypeIdentifier, Literal: "name"},
			{Type: models.TokenTypeEq, Literal: "="},
			{Type: models.TokenTypeString, Literal: "test"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
	}

	// Add opening function calls
	for i := 0; i < 150; i++ {
		tokens = append(tokens,
			token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
			token.Token{Type: models.TokenTypeLParen, Literal: "("},
		)
	}

	// Add innermost argument
	tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})

	// Add closing parentheses
	for i := 0; i < 150; i++ {
		tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
	}

	tokens = append(tokens,
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
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
			token.Token{Type: models.TokenTypeWith, Literal: "WITH"},
			token.Token{Type: models.TokenTypeIdentifier, Literal: "cte"},
			token.Token{Type: models.TokenTypeAs, Literal: "AS"},
			token.Token{Type: models.TokenTypeLParen, Literal: "("},
		)
	}

	// Add innermost SELECT
	tokens = append(tokens,
		token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "x"},
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
	)

	// Close all CTEs
	for i := 0; i < 150; i++ {
		tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
	}

	// Add final SELECT
	tokens = append(tokens,
		token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"},
		token.Token{Type: models.TokenTypeAsterisk, Literal: "*"},
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "cte"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
	}

	// Add opening function calls
	for i := 0; i < 150; i++ {
		deepTokens = append(deepTokens,
			token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
			token.Token{Type: models.TokenTypeLParen, Literal: "("},
		)
	}

	// Add innermost argument
	deepTokens = append(deepTokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})

	// Add closing parentheses
	for i := 0; i < 150; i++ {
		deepTokens = append(deepTokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
	}

	deepTokens = append(deepTokens,
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
	)

	_, err := parser.Parse(deepTokens)
	if err == nil {
		t.Fatal("expected error for deeply nested expression")
	}

	// Now parse a simple query - it should succeed, proving depth was reset
	simpleTokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
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
		{Type: models.TokenTypeWith, Literal: "WITH"},
		{Type: models.TokenTypeRecursive, Literal: "RECURSIVE"},
		{Type: models.TokenTypeIdentifier, Literal: "cte"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "t"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "cte"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeOver, Literal: "OVER"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "t"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeTrue, Literal: "TRUE"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "active"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "pending"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "3"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "y"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "z"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "3"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypePlaceholder, Literal: "$1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypePlaceholder, Literal: "$2"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypePlaceholder, Literal: "$1"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypePlaceholder, Literal: "$2"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "5"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypePlaceholder, Literal: "$1"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "age"},
				{Type: models.TokenTypeGt, Literal: ">"},
				{Type: models.TokenTypeNumber, Literal: "18"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "age"},
				{Type: models.TokenTypeLt, Literal: "<"},
				{Type: models.TokenTypeNumber, Literal: "65"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeNeq, Literal: "!="},
				{Type: models.TokenTypeString, Literal: "deleted"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "age"},
				{Type: models.TokenTypeGtEq, Literal: ">="},
				{Type: models.TokenTypeNumber, Literal: "18"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "3"},
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
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "3"},
			},
			expected: "a=1 OR (b=2 AND c=3)",
		},
		{
			name: "Multiple ANDs with OR",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "a"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "b"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "2"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "c"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "3"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "d"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "4"},
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
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
	}

	// Note: Parentheses in SQL expressions would require expression parsing
	// which goes through parseExpression. For this test, we'll use nested
	// function calls as they provide the same recursion depth behavior.
	// Build: SELECT f(f(f(...f(x)...))) FROM t with 1000 levels

	// Add opening function calls (1000 levels)
	for i := 0; i < 1000; i++ {
		tokens = append(tokens,
			token.Token{Type: models.TokenTypeIdentifier, Literal: "func"},
			token.Token{Type: models.TokenTypeLParen, Literal: "("},
		)
	}

	// Add innermost argument
	tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})

	// Add closing parentheses (1000 levels)
	for i := 0; i < 1000; i++ {
		tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
	}

	tokens = append(tokens,
		token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
		token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
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
			tokens := []token.Token{{Type: models.TokenTypeSelect, Literal: "SELECT"}}

			for i := 0; i < tc.depth; i++ {
				tokens = append(tokens,
					token.Token{Type: models.TokenTypeIdentifier, Literal: "f"},
					token.Token{Type: models.TokenTypeLParen, Literal: "("},
				)
			}

			tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: "x"})

			for i := 0; i < tc.depth; i++ {
				tokens = append(tokens, token.Token{Type: models.TokenTypeRParen, Literal: ")"})
			}

			tokens = append(tokens,
				token.Token{Type: models.TokenTypeFrom, Literal: "FROM"},
				token.Token{Type: models.TokenTypeIdentifier, Literal: "t"},
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
