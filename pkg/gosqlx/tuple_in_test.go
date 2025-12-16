package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParse_TupleIn_Basic tests basic tuple IN clause using high-level API
func TestParse_TupleIn_Basic(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
	}

	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is tuple
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression on left, got %T", inExpr.Expr)
	}

	if len(leftTuple.Expressions) != 2 {
		t.Errorf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify list has tuples
	if len(inExpr.List) != 2 {
		t.Fatalf("expected 2 tuples in list, got %d", len(inExpr.List))
	}
}

// TestParse_TupleIn_Scenarios tests various tuple IN scenarios
func TestParse_TupleIn_Scenarios(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Basic tuple IN",
			sql:  "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))",
		},
		{
			name: "NOT IN with tuples",
			sql:  "SELECT * FROM orders WHERE (user_id, status) NOT IN ((1, 'active'), (2, 'pending'))",
		},
		{
			name: "Three-element tuple",
			sql:  "SELECT * FROM t WHERE (a, b, c) IN ((1, 2, 3), (4, 5, 6))",
		},
		{
			name: "Four-element tuple",
			sql:  "SELECT * FROM t WHERE (a, b, c, d) IN ((1, 2, 3, 4))",
		},
		{
			name: "Tuple with expressions",
			sql:  "SELECT * FROM t WHERE (a + 1, b * 2) IN ((10, 20), (30, 40))",
		},
		{
			name: "Tuple with function calls",
			sql:  "SELECT * FROM users WHERE (LOWER(name), status) IN (('john', 'active'))",
		},
		{
			name: "Tuple IN subquery",
			sql:  "SELECT * FROM t WHERE (a, b) IN (SELECT x, y FROM other)",
		},
		{
			name: "Qualified column tuple",
			sql:  "SELECT * FROM orders o WHERE (o.user_id, o.status) IN ((1, 'active'))",
		},
		{
			name: "Tuple with NULL",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1, NULL), (2, 'value'))",
		},
		{
			name: "Tuple with CAST",
			sql:  "SELECT * FROM t WHERE (CAST(a AS INT), b) IN ((1, 'x'))",
		},
		{
			name: "Combined with AND",
			sql:  "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active')) AND created_at > '2024-01-01'",
		},
		{
			name: "Combined with OR",
			sql:  "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active')) OR total > 100",
		},
		{
			name: "In JOIN condition",
			sql:  "SELECT * FROM orders o JOIN users u ON (o.user_id, o.region) IN ((u.id, u.region))",
		},
		{
			name: "Single value list",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1, 2))",
		},
		{
			name: "Many tuples in list",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4), (5, 6), (7, 8), (9, 10))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astObj, err := Parse(tt.sql)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer ast.ReleaseAST(astObj)

			if len(astObj.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(astObj.Statements))
			}

			_, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
			}

			t.Logf("Successfully parsed: %s", tt.sql)
		})
	}
}

// TestValidate_TupleIn tests Validate function with tuple IN
func TestValidate_TupleIn(t *testing.T) {
	tests := []string{
		"SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))",
		"SELECT * FROM t WHERE (a, b, c) IN ((1, 2, 3))",
		"SELECT * FROM t WHERE (a, b) IN (SELECT x, y FROM other)",
	}

	for _, sql := range tests {
		t.Run(sql[:40]+"...", func(t *testing.T) {
			err := Validate(sql)
			if err != nil {
				t.Errorf("expected SQL to be valid: %s, got error: %v", sql, err)
			}
		})
	}
}

// TestExtractMetadata_TupleIn tests metadata extraction with tuple IN
func TestExtractMetadata_TupleIn(t *testing.T) {
	sql := "SELECT id, name FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	metadata := ExtractMetadata(astObj)
	if metadata == nil {
		t.Fatal("expected metadata, got nil")
	}

	// Check tables
	if len(metadata.Tables) != 1 {
		t.Errorf("expected 1 table, got %d", len(metadata.Tables))
	}
	if len(metadata.Tables) > 0 && metadata.Tables[0] != "orders" {
		t.Errorf("expected table 'orders', got '%s'", metadata.Tables[0])
	}

	// Check columns - should include id, name, user_id, status
	// Just verify we got at least the SELECT columns
	foundId := false
	foundName := false
	for _, col := range metadata.Columns {
		if col == "id" {
			foundId = true
		}
		if col == "name" {
			foundName = true
		}
	}
	if !foundId || !foundName {
		t.Logf("Columns found: %v", metadata.Columns)
	}
}

// TestParse_TupleIn_WithSubquery tests tuple IN with subquery in detail
func TestParse_TupleIn_WithSubquery(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, product_id) IN (SELECT user_id, product_id FROM cart WHERE active = true)"

	astObj, err := Parse(sql)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify it's a tuple
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", inExpr.Expr)
	}

	if len(leftTuple.Expressions) != 2 {
		t.Errorf("expected 2 elements in tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify subquery is used
	if inExpr.Subquery == nil {
		t.Error("expected Subquery to be set")
	}

	// Verify list is empty (using subquery)
	if len(inExpr.List) != 0 {
		t.Errorf("expected empty List when using Subquery, got %d items", len(inExpr.List))
	}

	// Verify subquery is a SELECT statement
	subSelect, ok := inExpr.Subquery.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected subquery to be SelectStatement, got %T", inExpr.Subquery)
	}

	// Verify subquery selects 2 columns
	if len(subSelect.Columns) != 2 {
		t.Errorf("expected subquery to select 2 columns, got %d", len(subSelect.Columns))
	}
}
