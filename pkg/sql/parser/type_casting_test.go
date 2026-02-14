// Package parser - type_casting_test.go
// Tests for PostgreSQL type casting (::) operator parsing

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_TypeCasting(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "Simple integer cast",
			input: "SELECT '123'::INTEGER",
		},
		{
			name:  "Cast to VARCHAR with length",
			input: "SELECT name::VARCHAR(100) FROM users",
		},
		{
			name:  "Cast in WHERE clause",
			input: "SELECT * FROM orders WHERE amount::INTEGER > 100",
		},
		{
			name:  "Cast to TEXT",
			input: "SELECT id::TEXT FROM users",
		},
		{
			name:  "Cast to NUMERIC with precision",
			input: "SELECT price::NUMERIC(10,2) FROM products",
		},
		{
			name:  "Cast to BOOLEAN",
			input: "SELECT active::BOOLEAN FROM users",
		},
		{
			name:  "Cast to TIMESTAMP",
			input: "SELECT created_at::TIMESTAMP FROM events",
		},
		{
			name:  "Cast to DATE",
			input: "SELECT birth_date::DATE FROM users",
		},
		{
			name:  "Chained casts",
			input: "SELECT value::TEXT::VARCHAR(50) FROM data",
		},
		{
			name:  "Cast with expression",
			input: "SELECT (amount * 100)::INTEGER FROM orders",
		},
		{
			name:  "Cast array type",
			input: "SELECT tags::TEXT[] FROM posts",
		},
		{
			name:  "Cast in function argument",
			input: "SELECT LENGTH(name::TEXT) FROM users",
		},
		{
			name:  "Cast NULL",
			input: "SELECT NULL::INTEGER",
		},
		{
			name:  "Cast column in ORDER BY",
			input: "SELECT * FROM users ORDER BY id::TEXT",
		},
		{
			name:  "Cast in CASE expression",
			input: "SELECT CASE WHEN status = 'active' THEN 1::TEXT ELSE 0::TEXT END FROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			p := NewParser()
			defer p.Release()
			result, err := p.ParseFromModelTokens(tokens)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if len(result.Statements) != 1 {
				t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
			}
		})
	}
}

func TestParser_TypeCastingAST(t *testing.T) {
	input := "SELECT value::INTEGER FROM data"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}

	p := NewParser()
	defer p.Release()
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	selectStmt, ok := result.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", result.Statements[0])
	}

	if len(selectStmt.Columns) != 1 {
		t.Fatalf("Expected 1 column, got %d", len(selectStmt.Columns))
	}

	// The column should be a CastExpression directly
	castExpr, ok := selectStmt.Columns[0].(*ast.CastExpression)
	if !ok {
		t.Fatalf("Expected CastExpression, got %T", selectStmt.Columns[0])
	}

	if castExpr.Type != "INTEGER" {
		t.Errorf("Expected cast type INTEGER, got %s", castExpr.Type)
	}

	// Check that the inner expression is an identifier
	ident, ok := castExpr.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("Expected Identifier in cast expression, got %T", castExpr.Expr)
	}

	if ident.Name != "value" {
		t.Errorf("Expected identifier 'value', got %s", ident.Name)
	}
}

func TestParser_TypeCastingWithJSON(t *testing.T) {
	// Test that type casting works with JSON operators
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Cast JSON field to text",
			input: "SELECT (data->>'name')::TEXT FROM users",
		},
		{
			name:  "Cast JSON to integer",
			input: "SELECT (data->>'age')::INTEGER FROM users",
		},
		{
			name:  "Cast with JSON containment",
			input: "SELECT * FROM users WHERE (data->>'score')::INTEGER > 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			p := NewParser()
			defer p.Release()
			_, err = p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestParser_TypeCastingErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Missing type after cast",
			input: "SELECT value:: FROM data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				// Tokenizer error is acceptable
				return
			}

			p := NewParser()
			defer p.Release()
			_, err = p.ParseFromModelTokens(tokens)
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}
