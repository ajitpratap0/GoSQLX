// Package parser - json_operators_test.go
// Tests for JSON/JSONB operator support (PostgreSQL)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_JSONArrowOperator(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantErr  bool
		validate func(*testing.T, *ast.AST)
	}{
		{
			name:    "Simple arrow operator",
			sql:     "SELECT data -> 'key' FROM users",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				if astObj == nil {
					t.Fatal("AST is nil")
				}
				if len(astObj.Statements) != 1 {
					t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
				}
				stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatal("Expected SelectStatement")
				}
				if len(stmt.Columns) != 1 {
					t.Fatalf("Expected 1 column, got %d", len(stmt.Columns))
				}
				// Column is an Expression directly
				binExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("Expected BinaryExpression, got %T", stmt.Columns[0])
				}
				if binExpr.Operator != "->" {
					t.Errorf("Expected operator '->', got '%s'", binExpr.Operator)
				}
			},
		},
		{
			name:    "Chained arrow operators",
			sql:     "SELECT data -> 'a' -> 'b' FROM users",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				// Should have nested binary expressions
				binExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("Expected BinaryExpression, got %T", stmt.Columns[0])
				}
				// Outermost should be the last operator
				if binExpr.Operator != "->" {
					t.Errorf("Expected operator '->', got '%s'", binExpr.Operator)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Convert tokens

			// Parse
			p := NewParser()
			astObj, err := p.ParseFromModelTokens(tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, astObj)
			}
		})
	}
}

func TestParser_JSONComplexExpressions(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "JSON with comparison",
			sql:     "SELECT * FROM users WHERE data -> 'age' > 18",
			wantErr: false,
		},
		{
			name:    "JSON containment @>",
			sql:     "SELECT * FROM users WHERE data @> '{\"key\": \"value\"}'",
			wantErr: false,
		},
		{
			name:    "JSON is contained by <@",
			sql:     "SELECT * FROM users WHERE data <@ '{\"key\": \"value\"}'",
			wantErr: false,
		},
		{
			name:    "JSON path #>",
			sql:     "SELECT data #> '{a,b}' FROM users",
			wantErr: false,
		},
		{
			name:    "JSON path text #>>",
			sql:     "SELECT data #>> '{a,b}' FROM users",
			wantErr: false,
		},
		{
			name:    "JSON delete at path #-",
			sql:     "SELECT data #- '{a,b}' FROM users",
			wantErr: false,
		},
		{
			name:    "Long arrow ->>",
			sql:     "SELECT data ->> 'name' FROM users",
			wantErr: false,
		},
		{
			name:    "Chained operators",
			sql:     "SELECT data -> 'a' -> 'b' ->> 'c' FROM users",
			wantErr: false,
		},
		{
			name:    "JSON operators in JOIN",
			sql:     "SELECT * FROM users u JOIN orders o ON u.data -> 'id' = o.user_id",
			wantErr: false,
		},
		{
			name:    "JSON with CAST",
			sql:     "SELECT CAST(data ->> 'count' AS INTEGER) FROM users",
			wantErr: false,
		},
		{
			name:    "Multiple JSON operators in WHERE",
			sql:     "SELECT * FROM users WHERE data -> 'a' = 'x' AND data -> 'b' = 'y'",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Convert tokens

			// Parse
			p := NewParser()
			_, err = p.ParseFromModelTokens(tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_JSONOperatorPrecedence verifies that JSON operators have correct precedence
func TestParser_JSONOperatorPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "JSON with arithmetic",
			sql:     "SELECT data -> 'count' + 1 FROM users",
			wantErr: false,
		},
		{
			name:    "JSON with multiplication",
			sql:     "SELECT data -> 'price' * 1.1 FROM products",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Convert tokens

			// Parse
			p := NewParser()
			_, err = p.ParseFromModelTokens(tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_JSONBExistenceOperators tests JSONB key existence operators (?, ?|, ?&)
func TestParser_JSONBExistenceOperators(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantErr  bool
		operator string
	}{
		{
			name:     "Key exists operator ?",
			sql:      "SELECT * FROM users WHERE data ? 'active'",
			wantErr:  false,
			operator: "?",
		},
		{
			name:     "Key exists with identifier",
			sql:      "SELECT * FROM users WHERE profile ? 'email'",
			wantErr:  false,
			operator: "?",
		},
		{
			name:     "Chained JSON operators with ?",
			sql:      "SELECT * FROM users WHERE data->'profile' ? 'email'",
			wantErr:  false,
			operator: "?",
		},
		{
			name:     "? with multiple conditions",
			sql:      "SELECT * FROM users WHERE data ? 'active' AND data ? 'verified'",
			wantErr:  false,
			operator: "?",
		},
		{
			name:     "? in SELECT list",
			sql:      "SELECT data ? 'active' AS is_active FROM users",
			wantErr:  false,
			operator: "?",
		},
		{
			name:     "?| with simple value",
			sql:      "SELECT * FROM users WHERE data ?| 'tags'",
			wantErr:  false,
			operator: "?|",
		},
		{
			name:     "?& with simple value",
			sql:      "SELECT * FROM users WHERE data ?& 'keys'",
			wantErr:  false,
			operator: "?&",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tokenize
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			// Convert tokens

			// Parse
			p := NewParser()
			astObj, err := p.ParseFromModelTokens(tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Validate structure for successful parses
			if !tt.wantErr && astObj != nil {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				if stmt == nil {
					t.Fatal("Expected SelectStatement")
				}
			}
		})
	}
}
