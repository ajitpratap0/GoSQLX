// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
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

// parseInsertCTEWithDialect tokenizes and parses sql with the given dialect
// ("" means the parser default). The caller must release the returned AST.
func parseInsertCTEWithDialect(t *testing.T, sql, dialect string) (*ast.AST, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if dialect != "" {
		tkz.SetDialect(keywords.SQLDialect(dialect))
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q, %q): %v", sql, dialect, err)
	}
	p := NewParser(WithDialect(dialect))
	defer p.Release()
	return p.ParseFromModelTokens(tokens)
}

// mustParseInsertCTE parses sql and returns its single InsertStatement. The
// caller must release the returned AST.
func mustParseInsertCTE(t *testing.T, sql, dialect string) (*ast.InsertStatement, *ast.AST) {
	t.Helper()
	tree, err := parseInsertCTEWithDialect(t, sql, dialect)
	if err != nil {
		t.Fatalf("parse(%q, dialect %q): %v", sql, dialect, err)
	}
	if len(tree.Statements) != 1 {
		n := len(tree.Statements)
		ast.ReleaseAST(tree)
		t.Fatalf("parse(%q, dialect %q): expected 1 statement, got %d", sql, dialect, n)
	}
	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		got := tree.Statements[0]
		ast.ReleaseAST(tree)
		t.Fatalf("parse(%q, dialect %q): expected *ast.InsertStatement, got %T", sql, dialect, got)
	}
	return ins, tree
}

// assertInsertCTERoundTrip re-parses rendered SQL and requires the re-rendered
// SQL to be identical.
func assertInsertCTERoundTrip(t *testing.T, rendered, dialect string) {
	t.Helper()
	ins, tree := mustParseInsertCTE(t, rendered, dialect)
	defer ast.ReleaseAST(tree)
	if again := ins.SQL(); again != rendered {
		t.Errorf("round-trip not stable (dialect %q):\n first: %s\nsecond: %s", dialect, rendered, again)
	}
}

// TestInsertWithCTE_Issue537_Dialects reproduces #537: a WITH clause after the
// INSERT column list must parse in every dialect, with the CTE attached to the
// query rather than to the INSERT.
func TestInsertWithCTE_Issue537_Dialects(t *testing.T) {
	const sql = "INSERT INTO test(a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main"
	const want = "INSERT INTO test (a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main"

	dialects := []string{"", "postgresql", "mysql", "mariadb", "sqlite", "oracle", "snowflake", "clickhouse", "sqlserver"}
	for _, d := range dialects {
		t.Run("dialect="+d, func(t *testing.T) {
			ins, tree := mustParseInsertCTE(t, sql, d)
			defer ast.ReleaseAST(tree)

			if ins.TableName != "test" {
				t.Errorf("TableName = %q, want %q", ins.TableName, "test")
			}
			if len(ins.Columns) != 2 {
				t.Errorf("len(Columns) = %d, want 2", len(ins.Columns))
			}
			if ins.With != nil {
				t.Errorf("InsertStatement.With = %+v, want nil (CTE belongs to the query)", ins.With)
			}
			if ins.Values != nil {
				t.Errorf("Values = %v, want nil", ins.Values)
			}
			sel, ok := ins.Query.(*ast.SelectStatement)
			if !ok {
				t.Fatalf("Query: expected *ast.SelectStatement, got %T", ins.Query)
			}
			if sel.With == nil {
				t.Fatal("Query.With is nil, want WITH clause")
			}
			if sel.With.Recursive {
				t.Error("With.Recursive = true, want false")
			}
			if len(sel.With.CTEs) != 1 {
				t.Fatalf("len(With.CTEs) = %d, want 1", len(sel.With.CTEs))
			}
			cte := sel.With.CTEs[0]
			if cte.Name != "main" {
				t.Errorf("CTE name = %q, want %q", cte.Name, "main")
			}
			if _, ok := cte.Statement.(*ast.SelectStatement); !ok {
				t.Errorf("CTE statement: expected *ast.SelectStatement, got %T", cte.Statement)
			}

			got := ins.SQL()
			if got != want {
				t.Fatalf("SQL():\n got: %s\nwant: %s", got, want)
			}
			assertInsertCTERoundTrip(t, got, d)
		})
	}
}

// TestInsertWithCTE_Issue537_Shapes covers the variants of an inner WITH
// clause on INSERT ... SELECT.
func TestInsertWithCTE_Issue537_Shapes(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantSQL string
		check   func(t *testing.T, ins *ast.InsertStatement)
	}{
		{
			name:    "no column list",
			sql:     "INSERT INTO test WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
			wantSQL: "INSERT INTO test WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				if len(ins.Columns) != 0 {
					t.Errorf("len(Columns) = %d, want 0", len(ins.Columns))
				}
				sel, ok := ins.Query.(*ast.SelectStatement)
				if !ok {
					t.Fatalf("Query: expected *ast.SelectStatement, got %T", ins.Query)
				}
				if sel.With == nil || len(sel.With.CTEs) != 1 {
					t.Fatalf("Query.With = %+v, want 1 CTE", sel.With)
				}
			},
		},
		{
			name:    "recursive with CTE column list",
			sql:     "INSERT INTO test(a, b) WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < 5) SELECT n, n FROM r",
			wantSQL: "INSERT INTO test (a, b) WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT n, n FROM r",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				sel, ok := ins.Query.(*ast.SelectStatement)
				if !ok {
					t.Fatalf("Query: expected *ast.SelectStatement, got %T", ins.Query)
				}
				if sel.With == nil || !sel.With.Recursive {
					t.Fatalf("Query.With = %+v, want RECURSIVE", sel.With)
				}
				if len(sel.With.CTEs) != 1 {
					t.Fatalf("len(CTEs) = %d, want 1", len(sel.With.CTEs))
				}
				cols := sel.With.CTEs[0].Columns
				if len(cols) != 1 || cols[0] != "n" {
					t.Errorf("CTE columns = %v, want [n]", cols)
				}
			},
		},
		{
			name:    "multiple CTEs and UNION",
			sql:     "INSERT INTO test(a, b) WITH x AS (SELECT 1), y AS (SELECT 2) SELECT a, b FROM x UNION SELECT a, b FROM y",
			wantSQL: "INSERT INTO test (a, b) WITH x AS (SELECT 1), y AS (SELECT 2) SELECT a, b FROM x UNION SELECT a, b FROM y",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				setOp, ok := ins.Query.(*ast.SetOperation)
				if !ok {
					t.Fatalf("Query: expected *ast.SetOperation, got %T", ins.Query)
				}
				left, ok := setOp.Left.(*ast.SelectStatement)
				if !ok {
					t.Fatalf("SetOperation.Left: expected *ast.SelectStatement, got %T", setOp.Left)
				}
				if left.With == nil || len(left.With.CTEs) != 2 {
					t.Fatalf("Left.With = %+v, want 2 CTEs", left.With)
				}
			},
		},
		{
			name:    "ON CONFLICT and RETURNING after CTE query",
			sql:     "INSERT INTO test(a, b) WITH m AS (SELECT a, b FROM src) SELECT a, b FROM m ON CONFLICT (a) DO NOTHING RETURNING a",
			wantSQL: "INSERT INTO test (a, b) WITH m AS (SELECT a, b FROM src) SELECT a, b FROM m ON CONFLICT (a) DO NOTHING RETURNING a",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				if ins.OnConflict == nil {
					t.Error("OnConflict is nil")
				}
				if len(ins.Returning) != 1 {
					t.Errorf("len(Returning) = %d, want 1", len(ins.Returning))
				}
			},
		},
		{
			name:    "MATERIALIZED CTE",
			sql:     "INSERT INTO test(a, b) WITH m AS MATERIALIZED (SELECT a, b FROM src) SELECT a, b FROM m",
			wantSQL: "INSERT INTO test (a, b) WITH m AS MATERIALIZED (SELECT a, b FROM src) SELECT a, b FROM m",
		},
		{
			name:    "leading and inner WITH",
			sql:     "WITH o AS (SELECT 1) INSERT INTO test(a, b) WITH m AS (SELECT a, b FROM src) SELECT a, b FROM m",
			wantSQL: "WITH o AS (SELECT 1) INSERT INTO test (a, b) WITH m AS (SELECT a, b FROM src) SELECT a, b FROM m",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				if ins.With == nil || len(ins.With.CTEs) != 1 || ins.With.CTEs[0].Name != "o" {
					t.Fatalf("InsertStatement.With = %+v, want CTE o", ins.With)
				}
				sel, ok := ins.Query.(*ast.SelectStatement)
				if !ok {
					t.Fatalf("Query: expected *ast.SelectStatement, got %T", ins.Query)
				}
				if sel.With == nil || len(sel.With.CTEs) != 1 || sel.With.CTEs[0].Name != "m" {
					t.Fatalf("Query.With = %+v, want CTE m", sel.With)
				}
			},
		},
		{
			name:    "leading WITH unchanged",
			sql:     "WITH main AS (SELECT a, b FROM src) INSERT INTO test(a, b) SELECT a, b FROM main",
			wantSQL: "WITH main AS (SELECT a, b FROM src) INSERT INTO test (a, b) SELECT a, b FROM main",
			check: func(t *testing.T, ins *ast.InsertStatement) {
				if ins.With == nil {
					t.Fatal("InsertStatement.With is nil, want leading WITH")
				}
				sel, ok := ins.Query.(*ast.SelectStatement)
				if !ok {
					t.Fatalf("Query: expected *ast.SelectStatement, got %T", ins.Query)
				}
				if sel.With != nil {
					t.Errorf("Query.With = %+v, want nil", sel.With)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, tree := mustParseInsertCTE(t, tt.sql, "postgresql")
			defer ast.ReleaseAST(tree)

			if tt.check != nil {
				tt.check(t, ins)
			}
			got := ins.SQL()
			if got != tt.wantSQL {
				t.Fatalf("SQL():\n got: %s\nwant: %s", got, tt.wantSQL)
			}
			assertInsertCTERoundTrip(t, got, "postgresql")
		})
	}
}

// TestInsertWithCTE_Issue537_Errors pins the rejected forms around #537.
func TestInsertWithCTE_Issue537_Errors(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr string // substring; empty means any error
	}{
		{
			name:    "issue literal SQL missing AS",
			sql:     "INSERT INTO test(a, b) WITH main (SELECT a, b FROM src) SELECT a, b FROM main",
			wantErr: "expected AS",
		},
		{
			name:    "inner WITH followed by UPDATE",
			sql:     "INSERT INTO test(a, b) WITH m AS (SELECT a, b FROM src) UPDATE x SET a = 1",
			wantErr: "expected SELECT or set operation",
		},
		{
			name: "inner WITH followed by INSERT",
			sql:  "INSERT INTO test(a, b) WITH m AS (SELECT a, b FROM src) INSERT INTO x SELECT 1",
		},
		{
			name: "inner WITH without main query",
			sql:  "INSERT INTO test(a, b) WITH m AS (SELECT a, b FROM src)",
		},
		{
			name: "dangling WITH",
			sql:  "INSERT INTO test(a, b) WITH",
		},
		{
			name:    "no source",
			sql:     "INSERT INTO t1 (a) DEFAULT",
			wantErr: "VALUES, SELECT, or WITH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseInsertCTEWithDialect(t, tt.sql, "postgresql")
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Fatalf("parse(%q): expected error, got nil", tt.sql)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parse(%q) error = %q, want substring %q", tt.sql, err.Error(), tt.wantErr)
			}
		})
	}
}
