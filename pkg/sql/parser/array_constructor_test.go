// Package parser - array_constructor_test.go
// Tests for PostgreSQL ARRAY constructor syntax

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_ArrayConstructor(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantErr  bool
		validate func(*testing.T, *ast.AST)
	}{
		{
			name:    "Simple ARRAY with integers",
			sql:     "SELECT ARRAY[1, 2, 3]",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				if astObj == nil {
					t.Fatal("AST is nil")
				}
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				if len(stmt.Columns) != 1 {
					t.Fatalf("Expected 1 column, got %d", len(stmt.Columns))
				}
				arrExpr, ok := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if !ok {
					t.Fatalf("Expected ArrayConstructorExpression, got %T", stmt.Columns[0])
				}
				if len(arrExpr.Elements) != 3 {
					t.Errorf("Expected 3 elements, got %d", len(arrExpr.Elements))
				}
			},
		},
		{
			name:    "ARRAY with strings",
			sql:     "SELECT ARRAY['a', 'b', 'c']",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if len(arrExpr.Elements) != 3 {
					t.Errorf("Expected 3 elements, got %d", len(arrExpr.Elements))
				}
			},
		},
		{
			name:    "Empty ARRAY",
			sql:     "SELECT ARRAY[]",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if len(arrExpr.Elements) != 0 {
					t.Errorf("Expected 0 elements, got %d", len(arrExpr.Elements))
				}
			},
		},
		{
			name:    "ARRAY with single element",
			sql:     "SELECT ARRAY[42]",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if len(arrExpr.Elements) != 1 {
					t.Errorf("Expected 1 element, got %d", len(arrExpr.Elements))
				}
			},
		},
		{
			name:    "ARRAY in WHERE with containment",
			sql:     "SELECT * FROM users WHERE tags @> ARRAY['admin', 'moderator']",
			wantErr: false,
		},
		{
			name:    "ARRAY in WHERE with contained by",
			sql:     "SELECT * FROM users WHERE ARRAY['user'] <@ roles",
			wantErr: false,
		},
		{
			name:    "ARRAY with expressions",
			sql:     "SELECT ARRAY[1 + 2, 3 * 4, 5 - 1]",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if len(arrExpr.Elements) != 3 {
					t.Errorf("Expected 3 elements, got %d", len(arrExpr.Elements))
				}
				// Verify first element is a binary expression
				_, ok := arrExpr.Elements[0].(*ast.BinaryExpression)
				if !ok {
					t.Errorf("Expected BinaryExpression for first element, got %T", arrExpr.Elements[0])
				}
			},
		},
		{
			name:    "ARRAY with column references",
			sql:     "SELECT ARRAY[id, name, email] FROM users",
			wantErr: false,
		},
		{
			name:    "Multiple ARRAYs in SELECT",
			sql:     "SELECT ARRAY[1, 2], ARRAY['a', 'b']",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				if len(stmt.Columns) != 2 {
					t.Fatalf("Expected 2 columns, got %d", len(stmt.Columns))
				}
				_, ok1 := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				_, ok2 := stmt.Columns[1].(*ast.ArrayConstructorExpression)
				if !ok1 || !ok2 {
					t.Error("Expected both columns to be ArrayConstructorExpression")
				}
			},
		},
		{
			name:    "ARRAY comparison with =",
			sql:     "SELECT * FROM users WHERE tags = ARRAY['admin']",
			wantErr: false,
		},
		{
			name:    "ARRAY comparison with <>",
			sql:     "SELECT * FROM users WHERE roles <> ARRAY['guest']",
			wantErr: false,
		},
		{
			name:    "ARRAY with alias",
			sql:     "SELECT ARRAY[1, 2, 3] AS numbers",
			wantErr: false,
		},
		{
			name:    "Nested function calls in ARRAY",
			sql:     "SELECT ARRAY[UPPER('a'), LOWER('B')]",
			wantErr: false,
		},
		{
			name:    "ARRAY in INSERT VALUES",
			sql:     "INSERT INTO users (tags) VALUES (ARRAY['user', 'active'])",
			wantErr: false,
		},
		{
			name:    "ARRAY in UPDATE SET",
			sql:     "UPDATE users SET tags = ARRAY['updated']",
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
			convertedTokens, err := ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("ConvertTokensForParser failed: %v", err)
			}

			// Parse
			p := NewParser()
			astObj, err := p.Parse(convertedTokens)
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

func TestParser_ArraySubquery(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantErr  bool
		validate func(*testing.T, *ast.AST)
	}{
		{
			name:    "ARRAY with subquery",
			sql:     "SELECT ARRAY(SELECT id FROM users)",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				if astObj == nil {
					t.Fatal("AST is nil")
				}
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr, ok := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if !ok {
					t.Fatalf("Expected ArrayConstructorExpression, got %T", stmt.Columns[0])
				}
				if arrExpr.Subquery == nil {
					t.Error("Expected Subquery to be set")
				}
				if len(arrExpr.Elements) != 0 {
					t.Errorf("Expected no elements when using subquery, got %d", len(arrExpr.Elements))
				}
			},
		},
		{
			name:    "ARRAY subquery with WHERE",
			sql:     "SELECT ARRAY(SELECT name FROM users WHERE active = true)",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				arrExpr := stmt.Columns[0].(*ast.ArrayConstructorExpression)
				if arrExpr.Subquery == nil {
					t.Error("Expected Subquery to be set")
				}
				if arrExpr.Subquery.Where == nil {
					t.Error("Expected subquery to have WHERE clause")
				}
			},
		},
		{
			name:    "ARRAY subquery with ORDER BY",
			sql:     "SELECT ARRAY(SELECT name FROM users ORDER BY created_at)",
			wantErr: false,
		},
		{
			name:    "ARRAY subquery with alias",
			sql:     "SELECT ARRAY(SELECT id FROM users WHERE active = true) AS user_ids",
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
			convertedTokens, err := ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("ConvertTokensForParser failed: %v", err)
			}

			// Parse
			p := NewParser()
			astObj, err := p.Parse(convertedTokens)
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

// TestParser_ArrayConstructorPooling verifies proper pool usage
func TestParser_ArrayConstructorPooling(t *testing.T) {
	sql := "SELECT ARRAY[1, 2, 3]"

	// Run multiple times to exercise pooling
	for i := 0; i < 100; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			t.Fatalf("Tokenize failed: %v", err)
		}

		convertedTokens, err := ConvertTokensForParser(tokens)
		if err != nil {
			t.Fatalf("ConvertTokensForParser failed: %v", err)
		}

		p := NewParser()
		astObj, err := p.Parse(convertedTokens)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		// Release AST back to pool
		ast.ReleaseAST(astObj)
	}
}
