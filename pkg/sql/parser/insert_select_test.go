package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestInsertSelect(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantQuery bool
		wantCols  int
	}{
		{"with columns", "INSERT INTO t1 (a) SELECT a FROM t2", true, 1},
		{"without columns", "INSERT INTO t1 SELECT * FROM t2", true, 0},
		{"multiple columns and WHERE", "INSERT INTO t1 (a, b) SELECT a, b FROM t2 WHERE x > 1", true, 2},
		{"with UNION", "INSERT INTO t1 SELECT a FROM t2 UNION SELECT a FROM t3", true, 0},
		{"VALUES still works", "INSERT INTO t1 VALUES (1)", false, 0},
		{"VALUES with columns", "INSERT INTO t1 (a, b) VALUES (1, 2)", false, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.input)
			p := NewParser()
			result, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.input, err)
			}
			if len(result.Statements) < 1 {
				t.Fatalf("expected at least 1 statement, got %d", len(result.Statements))
			}

			// For UNION case, the top-level might be SetOperation
			if tt.name == "with UNION" {
				// The top-level should be InsertStatement with a SetOperation query
				insert, ok := result.Statements[0].(*ast.InsertStatement)
				if !ok {
					t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
				}
				if insert.Query == nil {
					t.Fatal("expected Query to be set for UNION case")
				}
				if _, ok := insert.Query.(*ast.SetOperation); !ok {
					t.Fatalf("expected Query to be *SetOperation, got %T", insert.Query)
				}
				return
			}

			insert, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
			}

			if (insert.Query != nil) != tt.wantQuery {
				t.Errorf("Query present = %v, want %v", insert.Query != nil, tt.wantQuery)
			}
			if len(insert.Columns) != tt.wantCols {
				t.Errorf("columns = %d, want %d", len(insert.Columns), tt.wantCols)
			}

			// Verify SQL() roundtrip doesn't panic
			_ = insert.SQL()
		})
	}
}

func TestInsertNoValuesOrSelect(t *testing.T) {
	tokens := tokenizeSQL(t, "INSERT INTO t1")
	p := NewParser()
	_, err := p.Parse(tokens)
	if err == nil {
		t.Fatal("expected error for INSERT INTO t1 with no VALUES or SELECT")
	}
}
