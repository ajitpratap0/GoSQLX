package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestRegexOperators_EndToEnd tests PostgreSQL regex operators using the full tokenizer->parser pipeline
// This ensures the entire flow works: tokenizer -> token converter -> parser -> AST
// Issue #190: Support PostgreSQL regular expression operators (~, ~*, !~, !~*)
func TestRegexOperators_EndToEnd(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		operator string
	}{
		{
			name:     "Case-sensitive regex match (~)",
			sql:      "SELECT * FROM users WHERE name ~ '^J.*'",
			operator: "~",
		},
		{
			name:     "Case-insensitive regex match (~*)",
			sql:      "SELECT * FROM products WHERE description ~* 'sale|discount'",
			operator: "~*",
		},
		{
			name:     "Case-sensitive regex non-match (!~)",
			sql:      "SELECT * FROM logs WHERE message !~ 'DEBUG'",
			operator: "!~",
		},
		{
			name:     "Case-insensitive regex non-match (!~*)",
			sql:      "SELECT * FROM emails WHERE subject !~* 'spam'",
			operator: "!~*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use Parse which goes through full tokenizer -> parser pipeline
			astObj, err := Parse(tt.sql)
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

			binExpr, ok := stmt.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
			}

			if binExpr.Operator != tt.operator {
				t.Errorf("expected operator %q, got %q", tt.operator, binExpr.Operator)
			}

			// Verify left side is an identifier
			leftIdent, ok := binExpr.Left.(*ast.Identifier)
			if !ok {
				t.Errorf("expected left side to be Identifier, got %T", binExpr.Left)
			} else {
				t.Logf("Left identifier: %s", leftIdent.Name)
			}

			// Verify right side is a literal (the regex pattern)
			rightLit, ok := binExpr.Right.(*ast.LiteralValue)
			if !ok {
				t.Errorf("expected right side to be LiteralValue, got %T", binExpr.Right)
			} else {
				t.Logf("Right literal: %v", rightLit.Value)
			}
		})
	}
}

// TestRegexOperators_ComplexQueries tests regex operators in complex queries
func TestRegexOperators_ComplexQueries(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Regex with AND condition",
			sql:  "SELECT * FROM users WHERE name ~ '^[A-Z]' AND email ~* '@example.com$'",
		},
		{
			name: "Regex with OR condition",
			sql:  "SELECT * FROM products WHERE name !~ 'deprecated' OR status = 'active'",
		},
		{
			name: "Multiple regex operators",
			sql:  "SELECT * FROM logs WHERE message ~ 'ERROR' AND message !~* 'ignored'",
		},
		{
			name: "Regex with parentheses",
			sql:  "SELECT * FROM users WHERE (name ~ '^Admin' OR email ~* '@admin.com') AND status = 'active'",
		},
		{
			name: "Regex in JOIN condition",
			sql:  "SELECT * FROM users u JOIN logs l ON l.user_id = u.id WHERE l.message ~ 'ERROR'",
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

			stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", astObj.Statements[0])
			}

			// Just verify we can parse it successfully - structure validation is done in other tests
			if stmt.Where == nil {
				t.Fatal("expected WHERE clause")
			}

			t.Logf("Successfully parsed: %s", tt.sql)
		})
	}
}

// TestRegexOperators_Subqueries tests regex operators in subqueries
func TestRegexOperators_Subqueries(t *testing.T) {
	sql := "SELECT * FROM users WHERE id IN (SELECT user_id FROM logs WHERE message ~ 'ERROR')"

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

	// The WHERE clause should be an IN expression
	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	if inExpr.Subquery == nil {
		t.Fatal("expected subquery in IN expression")
	}

	t.Log("Successfully parsed regex operator in subquery")
}

// TestRegexOperators_TypeCasting tests regex operators with type casting
func TestRegexOperators_TypeCasting(t *testing.T) {
	sql := "SELECT * FROM users WHERE id::text ~ '^[0-9]+$'"

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

	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "~" {
		t.Errorf("expected operator '~', got %q", binExpr.Operator)
	}

	// Left side should be a cast expression
	castExpr, ok := binExpr.Left.(*ast.CastExpression)
	if !ok {
		t.Fatalf("expected left side to be CastExpression, got %T", binExpr.Left)
	}

	if castExpr.Type != "text" {
		t.Errorf("expected cast type 'text', got %q", castExpr.Type)
	}

	t.Log("Successfully parsed regex operator with type cast")
}
