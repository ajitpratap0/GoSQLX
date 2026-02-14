// Package parser - within_group_test.go
// Tests for SQL:2003 WITHIN GROUP ordered-set aggregate functions

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_WithinGroup(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantErr  bool
		validate func(*testing.T, *ast.AST)
	}{
		{
			name:    "PERCENTILE_CONT with WITHIN GROUP",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				if astObj == nil {
					t.Fatal("AST is nil")
				}
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				if len(stmt.Columns) != 1 {
					t.Fatalf("Expected 1 column, got %d", len(stmt.Columns))
				}
				funcCall, ok := stmt.Columns[0].(*ast.FunctionCall)
				if !ok {
					t.Fatalf("Expected FunctionCall, got %T", stmt.Columns[0])
				}
				if funcCall.Name != "PERCENTILE_CONT" {
					t.Errorf("Expected function name 'PERCENTILE_CONT', got '%s'", funcCall.Name)
				}
				if len(funcCall.WithinGroup) != 1 {
					t.Errorf("Expected 1 WithinGroup expression, got %d", len(funcCall.WithinGroup))
				}
			},
		},
		{
			name:    "PERCENTILE_DISC with WITHIN GROUP",
			sql:     "SELECT PERCENTILE_DISC(0.5) WITHIN GROUP (ORDER BY salary DESC) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if funcCall.Name != "PERCENTILE_DISC" {
					t.Errorf("Expected function name 'PERCENTILE_DISC', got '%s'", funcCall.Name)
				}
				if len(funcCall.WithinGroup) != 1 {
					t.Errorf("Expected 1 WithinGroup expression, got %d", len(funcCall.WithinGroup))
				}
				if funcCall.WithinGroup[0].Ascending {
					t.Error("Expected DESC ordering")
				}
			},
		},
		{
			name:    "MODE with WITHIN GROUP",
			sql:     "SELECT MODE() WITHIN GROUP (ORDER BY department) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if funcCall.Name != "MODE" {
					t.Errorf("Expected function name 'MODE', got '%s'", funcCall.Name)
				}
				if len(funcCall.WithinGroup) != 1 {
					t.Errorf("Expected 1 WithinGroup expression, got %d", len(funcCall.WithinGroup))
				}
			},
		},
		{
			name:    "WITHIN GROUP with NULLS LAST",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary DESC NULLS LAST) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if len(funcCall.WithinGroup) != 1 {
					t.Fatalf("Expected 1 WithinGroup expression, got %d", len(funcCall.WithinGroup))
				}
				if funcCall.WithinGroup[0].NullsFirst == nil {
					t.Error("Expected NullsFirst to be set")
				} else if *funcCall.WithinGroup[0].NullsFirst {
					t.Error("Expected NULLS LAST (false), got NULLS FIRST")
				}
			},
		},
		{
			name:    "WITHIN GROUP with NULLS FIRST",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary NULLS FIRST) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if funcCall.WithinGroup[0].NullsFirst == nil {
					t.Error("Expected NullsFirst to be set")
				} else if !*funcCall.WithinGroup[0].NullsFirst {
					t.Error("Expected NULLS FIRST (true), got NULLS LAST")
				}
			},
		},
		{
			name:    "WITHIN GROUP with multiple ORDER BY columns",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY dept, salary DESC) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if len(funcCall.WithinGroup) != 2 {
					t.Errorf("Expected 2 WithinGroup expressions, got %d", len(funcCall.WithinGroup))
				}
				// First column should be ASC (default)
				if !funcCall.WithinGroup[0].Ascending {
					t.Error("Expected first column to be ASC")
				}
				// Second column should be DESC
				if funcCall.WithinGroup[1].Ascending {
					t.Error("Expected second column to be DESC")
				}
			},
		},
		{
			name:    "WITHIN GROUP with expression in ORDER BY",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary * 12) FROM employees",
			wantErr: false,
		},
		{
			name:    "WITHIN GROUP with FILTER clause",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) FILTER (WHERE active = true) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				funcCall := stmt.Columns[0].(*ast.FunctionCall)
				if len(funcCall.WithinGroup) != 1 {
					t.Errorf("Expected 1 WithinGroup expression, got %d", len(funcCall.WithinGroup))
				}
				if funcCall.Filter == nil {
					t.Error("Expected Filter to be set")
				}
			},
		},
		{
			name:    "Multiple WITHIN GROUP functions",
			sql:     "SELECT PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY salary), PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY salary) FROM employees",
			wantErr: false,
			validate: func(t *testing.T, astObj *ast.AST) {
				stmt := astObj.Statements[0].(*ast.SelectStatement)
				if len(stmt.Columns) != 2 {
					t.Fatalf("Expected 2 columns, got %d", len(stmt.Columns))
				}
				for i, col := range stmt.Columns {
					funcCall, ok := col.(*ast.FunctionCall)
					if !ok {
						t.Fatalf("Column %d: Expected FunctionCall, got %T", i, col)
					}
					if len(funcCall.WithinGroup) != 1 {
						t.Errorf("Column %d: Expected 1 WithinGroup expression, got %d", i, len(funcCall.WithinGroup))
					}
				}
			},
		},
		{
			name:    "WITHIN GROUP with alias",
			sql:     "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) AS median_salary FROM employees",
			wantErr: false,
		},
		{
			name:    "WITHIN GROUP in GROUP BY query",
			sql:     "SELECT department, PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) FROM employees GROUP BY department",
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

func TestParser_WithinGroupLISTAGG(t *testing.T) {
	// LISTAGG is Oracle's syntax, but WITHIN GROUP is standard SQL:2003
	tests := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "LISTAGG with WITHIN GROUP",
			sql:     "SELECT LISTAGG(name, ', ') WITHIN GROUP (ORDER BY name) FROM employees",
			wantErr: false,
		},
		{
			name:    "LISTAGG with WITHIN GROUP and GROUP BY",
			sql:     "SELECT department, LISTAGG(name, ', ') WITHIN GROUP (ORDER BY name) FROM employees GROUP BY department",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize failed: %v", err)
			}

			p := NewParser()
			_, err = p.ParseFromModelTokens(tokens)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParser_WithinGroupPooling verifies proper pool usage
func TestParser_WithinGroupPooling(t *testing.T) {
	sql := "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary) FROM employees"

	// Run multiple times to exercise pooling
	for i := 0; i < 100; i++ {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			t.Fatalf("Tokenize failed: %v", err)
		}

		p := NewParser()
		astObj, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		// Release AST back to pool
		ast.ReleaseAST(astObj)
	}
}
