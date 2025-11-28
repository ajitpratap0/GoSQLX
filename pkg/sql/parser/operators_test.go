package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_BetweenExpression tests BETWEEN operator parsing
func TestParser_BetweenExpression(t *testing.T) {
	// SELECT * FROM products WHERE price BETWEEN 10 AND 100
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "products"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "price"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "INT", Literal: "10"},
		{Type: "AND", Literal: "AND"},
		{Type: "INT", Literal: "100"},
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

	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	if betweenExpr.Not {
		t.Error("expected Not to be false")
	}

	// Verify expr is identifier "price"
	ident, ok := betweenExpr.Expr.(*ast.Identifier)
	if !ok || ident.Name != "price" {
		t.Error("expected Expr to be identifier 'price'")
	}
}

// TestParser_NotBetweenExpression tests NOT BETWEEN operator
func TestParser_NotBetweenExpression(t *testing.T) {
	// SELECT * FROM products WHERE price NOT BETWEEN 10 AND 100
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "products"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "price"},
		{Type: "NOT", Literal: "NOT"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "INT", Literal: "10"},
		{Type: "AND", Literal: "AND"},
		{Type: "INT", Literal: "100"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	if !betweenExpr.Not {
		t.Error("expected Not to be true for NOT BETWEEN")
	}
}

// TestParser_InExpression tests IN operator
func TestParser_InExpression(t *testing.T) {
	// SELECT * FROM orders WHERE status IN ('pending', 'processing', 'shipped')
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "status"},
		{Type: "IN", Literal: "IN"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "pending"},
		{Type: ",", Literal: ","},
		{Type: "STRING", Literal: "processing"},
		{Type: ",", Literal: ","},
		{Type: "STRING", Literal: "shipped"},
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
	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	if inExpr.Not {
		t.Error("expected Not to be false")
	}

	if len(inExpr.List) != 3 {
		t.Errorf("expected 3 values in IN list, got %d", len(inExpr.List))
	}
}

// TestParser_NotInExpression tests NOT IN operator
func TestParser_NotInExpression(t *testing.T) {
	// SELECT * FROM orders WHERE status NOT IN ('cancelled')
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "status"},
		{Type: "NOT", Literal: "NOT"},
		{Type: "IN", Literal: "IN"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "cancelled"},
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
	inExpr := stmt.Where.(*ast.InExpression)

	if !inExpr.Not {
		t.Error("expected Not to be true for NOT IN")
	}
}

// TestParser_LikeExpression tests LIKE operator
func TestParser_LikeExpression(t *testing.T) {
	// SELECT * FROM users WHERE email LIKE '%@example.com'
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "email"},
		{Type: "LIKE", Literal: "LIKE"},
		{Type: "STRING", Literal: "%@example.com"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "LIKE" {
		t.Errorf("expected operator 'LIKE', got %q", binExpr.Operator)
	}

	if binExpr.Not {
		t.Error("expected Not to be false")
	}
}

// TestParser_NotLikeExpression tests NOT LIKE operator
func TestParser_NotLikeExpression(t *testing.T) {
	// SELECT * FROM users WHERE name NOT LIKE 'Admin%'
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "name"},
		{Type: "NOT", Literal: "NOT"},
		{Type: "LIKE", Literal: "LIKE"},
		{Type: "STRING", Literal: "Admin%"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr := stmt.Where.(*ast.BinaryExpression)

	if !binExpr.Not {
		t.Error("expected Not to be true for NOT LIKE")
	}
}

// TestParser_IsNullExpression tests IS NULL operator
func TestParser_IsNullExpression(t *testing.T) {
	// SELECT * FROM customers WHERE deleted_at IS NULL
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "customers"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "deleted_at"},
		{Type: "IS", Literal: "IS"},
		{Type: "NULL", Literal: "NULL"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "IS NULL" {
		t.Errorf("expected operator 'IS NULL', got %q", binExpr.Operator)
	}

	if binExpr.Not {
		t.Error("expected Not to be false for IS NULL")
	}
}

// TestParser_IsNotNullExpression tests IS NOT NULL operator
func TestParser_IsNotNullExpression(t *testing.T) {
	// SELECT * FROM posts WHERE published_at IS NOT NULL
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "posts"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "published_at"},
		{Type: "IS", Literal: "IS"},
		{Type: "NOT", Literal: "NOT"},
		{Type: "NULL", Literal: "NULL"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr := stmt.Where.(*ast.BinaryExpression)

	if binExpr.Operator != "IS NULL" {
		t.Errorf("expected operator 'IS NULL', got %q", binExpr.Operator)
	}

	if !binExpr.Not {
		t.Error("expected Not to be true for IS NOT NULL")
	}
}

// TestParser_BetweenWithIdentifiers tests BETWEEN with column references
func TestParser_BetweenWithIdentifiers(t *testing.T) {
	// SELECT * FROM events WHERE event_date BETWEEN start_date AND end_date
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "events"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "event_date"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "IDENT", Literal: "start_date"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "end_date"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	// Verify lower bound is identifier
	lowerIdent, ok := betweenExpr.Lower.(*ast.Identifier)
	if !ok || lowerIdent.Name != "start_date" {
		t.Error("expected lower bound to be identifier 'start_date'")
	}

	// Verify upper bound is identifier
	upperIdent, ok := betweenExpr.Upper.(*ast.Identifier)
	if !ok || upperIdent.Name != "end_date" {
		t.Error("expected upper bound to be identifier 'end_date'")
	}
}

// TestParser_InWithNumbers tests IN with numeric values
func TestParser_InWithNumbers(t *testing.T) {
	// SELECT * FROM products WHERE category_id IN (1, 2, 3)
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "products"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "category_id"},
		{Type: "IN", Literal: "IN"},
		{Type: "(", Literal: "("},
		{Type: "INT", Literal: "1"},
		{Type: ",", Literal: ","},
		{Type: "INT", Literal: "2"},
		{Type: ",", Literal: ","},
		{Type: "INT", Literal: "3"},
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
	inExpr := stmt.Where.(*ast.InExpression)

	if len(inExpr.List) != 3 {
		t.Errorf("expected 3 values, got %d", len(inExpr.List))
	}

	// Verify all are literal values
	for i, val := range inExpr.List {
		lit, ok := val.(*ast.LiteralValue)
		if !ok {
			t.Errorf("expected LiteralValue at index %d, got %T", i, val)
		}
		if lit.Type != "int" {
			t.Errorf("expected int type at index %d, got %s", i, lit.Type)
		}
	}
}

// TestParser_CombinedOperators tests multiple operators in one query
func TestParser_CombinedOperators(t *testing.T) {
	// SELECT * FROM users WHERE age BETWEEN 18 AND 65 AND status IN ('active') AND name LIKE 'J%' AND deleted_at IS NULL
	// This is a complex test combining all operators with AND
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "age"},
		{Type: "BETWEEN", Literal: "BETWEEN"},
		{Type: "INT", Literal: "18"},
		{Type: "AND", Literal: "AND"},
		{Type: "INT", Literal: "65"},
		{Type: "AND", Literal: "AND"},
		{Type: "IDENT", Literal: "status"},
		{Type: "IN", Literal: "IN"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "active"},
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
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// The WHERE clause should be a binary expression (AND)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "AND" {
		t.Errorf("expected AND operator, got %q", binExpr.Operator)
	}
}

// TestParser_OperatorErrors tests error cases
func TestParser_OperatorErrors(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name: "BETWEEN without AND",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "t"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "x"},
				{Type: "BETWEEN", Literal: "BETWEEN"},
				{Type: "INT", Literal: "1"},
				{Type: "INT", Literal: "10"}, // Missing AND
			},
		},
		{
			name: "IN without closing paren",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "t"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "x"},
				{Type: "IN", Literal: "IN"},
				{Type: "(", Literal: "("},
				{Type: "INT", Literal: "1"},
				// Missing )
			},
		},
		{
			name: "IS without NULL",
			tokens: []token.Token{
				{Type: "SELECT", Literal: "SELECT"},
				{Type: "*", Literal: "*"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "t"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "x"},
				{Type: "IS", Literal: "IS"},
				{Type: "INT", Literal: "1"}, // Should be NULL
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
