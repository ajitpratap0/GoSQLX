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

package ast_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// quotedRenderDialects are the nine dialects every issue #611 case must
// round-trip in.
var quotedRenderDialects = []keywords.SQLDialect{
	keywords.DialectGeneric,
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectMariaDB,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSQLite,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
}

// nameSignature summarizes the names an AST carries in the positions issue
// #611 is about: CTE names and column lists, view names and column lists,
// table references and identifiers (with whether SQL() quotes the name; a
// case-only quoted name renders bare, so its Quoted flag is not kept).
func nameSignature(tree *ast.AST) string {
	var parts []string
	visit := func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CommonTableExpr:
			parts = append(parts, fmt.Sprintf("cte:%s(%s)", v.Name, strings.Join(v.Columns, "|")))
		case *ast.CreateViewStatement:
			parts = append(parts, fmt.Sprintf("view:%s(%s)", v.Name, strings.Join(v.Columns, "|")))
		case *ast.CreateMaterializedViewStatement:
			parts = append(parts, fmt.Sprintf("mview:%s(%s)", v.Name, strings.Join(v.Columns, "|")))
		case *ast.TableReference:
			parts = append(parts, "table:"+v.Name)
		case ast.TableReference:
			parts = append(parts, "table:"+v.Name)
		case *ast.Identifier:
			parts = append(parts, fmt.Sprintf("id:%s/%s/%t", v.Table, v.Name, strings.HasSuffix(v.SQL(), `"`)))
		}
		return true
	}
	for _, stmt := range tree.Statements {
		ast.Inspect(stmt, visit)
	}
	return strings.Join(parts, " ")
}

// assertQuotedRoundTrip parses sql in dialect d, checks that SQL() equals
// want, that the output re-parses, renders identically again and carries the
// same names as the original tree.
func assertQuotedRoundTrip(t *testing.T, sql, want string, d keywords.SQLDialect) *ast.AST {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	got := tree.SQL()
	if got != want {
		t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, want)
	}
	tree2, err := gosqlx.ParseWithDialect(got, d)
	if err != nil {
		t.Fatalf("re-parse of SQL() %q: %v", got, err)
	}
	defer ast.ReleaseAST(tree2)
	if got2 := tree2.SQL(); got2 != got {
		t.Errorf("SQL() not idempotent\n first: %s\nsecond: %s", got, got2)
	}
	if s1, s2 := nameSignature(tree), nameSignature(tree2); s1 != s2 {
		t.Errorf("re-parsed AST names differ\n orig: %s\nreparse: %s", s1, s2)
	}
	return tree
}

// TestQuotedIdentifierRender_Issue611 covers quoted identifiers that are
// reserved words or contain spaces: SQL() must keep the quotes so the output
// re-parses as the same names in every dialect. A name quoted for its case
// keeps its quotes too where the dialect folds unquoted names (the parser
// records it, see ast.NameQuote): upper-case letters in PostgreSQL and
// generic SQL, lower-case letters in Oracle and Snowflake. Dialects that do
// not fold drop quotes needed only for case, as before.
func TestQuotedIdentifierRender_Issue611(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		want      string // "" means identical to sql
		upperWant string // want in Oracle and Snowflake; "" means want
		noneWant  string // want in dialects that do not fold; "" means want
	}{
		{"cte_column_reserved", `WITH c ("select") AS (SELECT 1) SELECT * FROM c`, "", "", ""},
		{"cte_column_space", `WITH c ("a b") AS (SELECT 1) SELECT * FROM c`, "", "", ""},
		{"view_column_reserved", `CREATE VIEW v ("select") AS SELECT 1`, "", "", ""},
		{"select_reserved", `SELECT "select" FROM t`, "", "", ""},
		{"select_space_case_table_space", `SELECT "a b", "Mixed" FROM "my table"`, "", "", `SELECT "a b", Mixed FROM "my table"`},
		{"cte_name_reserved", `WITH "select" AS (SELECT 1) SELECT * FROM "select"`, "", "", ""},
		{"mview_column_reserved", `CREATE MATERIALIZED VIEW mv ("select") AS SELECT 1`, "", "", ""},
		{"cte_column_key", `WITH c ("key") AS (SELECT 1) SELECT * FROM c`, "", "", ""},
		{"select_null_true", `SELECT "null", "true" FROM t`, "", "", ""},
		{"join_reserved_table", `SELECT * FROM a JOIN "order" o ON a.id = o.id`, `SELECT * FROM a INNER JOIN "order" o ON a.id = o.id`, "", ""},
		{"qualified_reserved", `SELECT "T"."select" FROM t`, "", `SELECT T."select" FROM t`, `SELECT T."select" FROM t`},
		{"qualified_table_space", `SELECT * FROM "db"."My T"`, `SELECT * FROM db."My T"`, `SELECT * FROM "db"."My T"`, ""},
		// No-change guards: unquoted input renders as before.
		{"guard_mixed_case_bare", `SELECT Mixed, id FROM Users`, "", "", ""},
		{"guard_from_key", `SELECT * FROM key`, "", "", ""},
		{"guard_cte_columns_bare", `WITH c (a, b) AS (SELECT 1, 2) SELECT * FROM c`, "", "", ""},
		// Bare names with combining marks (Devanagari vowel signs, a
		// decomposed accent) are valid bare identifiers and stay unquoted.
		{"guard_devanagari_table", `SELECT * FROM उपयोगकर्ता`, "", "", ""},
		{"guard_devanagari_cte", `WITH उपयोगकर्ता AS (SELECT 1) SELECT * FROM उपयोगकर्ता`, "", "", ""},
		{"guard_decomposed_table", "SELECT * FROM Cafe\u0301", "", "", ""},
		{"guard_decomposed_join", "SELECT * FROM a LEFT JOIN cafe\u0301_tbl c ON a.id = c.id", "", "", ""},
	}
	for _, tc := range cases {
		for _, d := range quotedRenderDialects {
			want := tc.want
			if want == "" {
				want = tc.sql
			}
			switch d {
			case keywords.DialectOracle, keywords.DialectSnowflake:
				if tc.upperWant != "" {
					want = tc.upperWant
				}
			case keywords.DialectGeneric, keywords.DialectPostgreSQL:
			default:
				if tc.noneWant != "" {
					want = tc.noneWant
				}
			}
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				tree := assertQuotedRoundTrip(t, tc.sql, want, d)
				defer ast.ReleaseAST(tree)
				if tc.name == "select_null_true" {
					sel, ok := tree.Statements[0].(*ast.SelectStatement)
					if !ok {
						t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
					}
					for i, col := range sel.Columns {
						id, ok := col.(*ast.Identifier)
						if !ok {
							t.Fatalf("column %d: expected *ast.Identifier, got %T", i, col)
						}
						if !id.Quoted {
							t.Errorf("column %d (%s): Quoted = false, want true", i, id.Name)
						}
					}
				}
			})
		}
	}
}

// TestQuotedIdentifierRender_DialectGuards_Issue611 pins dialect-specific
// forms that must render unchanged.
func TestQuotedIdentifierRender_DialectGuards_Issue611(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"postgres_qualified_key", keywords.DialectPostgreSQL, `SELECT t.key FROM t`, `SELECT t.key FROM t`},
		{"sqlserver_temp_table", keywords.DialectSQLServer, `SELECT * FROM #temp`, `SELECT * FROM #temp`},
		{"snowflake_stage", keywords.DialectSnowflake, `SELECT * FROM @stage`, `SELECT * FROM @stage`},
		{"snowflake_stage_path", keywords.DialectSnowflake, `SELECT $1 FROM @mystage/data`, `SELECT $1 FROM @mystage/data`},
		{"clickhouse_tuple_access", keywords.DialectClickHouse, `SELECT d.1 FROM t`, `SELECT d.1 FROM t`},
		{"oracle_dual", keywords.DialectOracle, `SELECT 1 FROM DUAL`, `SELECT 1 FROM DUAL`},
		// Backtick-quoted names are not ANSI-quoted: Quoted stays false,
		// QuoteStyle records the backtick, and a plain name renders bare.
		{"mysql_backtick", keywords.DialectMySQL, "SELECT `id` FROM t", `SELECT id FROM t`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := assertQuotedRoundTrip(t, tc.sql, tc.want, tc.dialect)
			defer ast.ReleaseAST(tree)
			if tc.name == "mysql_backtick" {
				sel, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				id, ok := sel.Columns[0].(*ast.Identifier)
				if !ok {
					t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[0])
				}
				if id.Quoted {
					t.Errorf("backtick identifier: Quoted = true, want false")
				}
				if id.QuoteStyle != '`' {
					t.Errorf("backtick identifier: QuoteStyle = %q, want '`'", id.QuoteStyle)
				}
			}
		})
	}
}

// TestIdentifierQuotedFlag_Issue611 checks which select-list identifiers the
// parser marks as Quoted: only those whose final name part was double-quoted.
func TestIdentifierQuotedFlag_Issue611(t *testing.T) {
	sql := `SELECT "a", b, "T"."c", t."d", x.y."Z", "q".* FROM t`
	want := []bool{true, false, true, true, true, false}
	for _, d := range quotedRenderDialects {
		t.Run(string(d), func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, d)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.Columns) != len(want) {
				t.Fatalf("got %d columns, want %d", len(sel.Columns), len(want))
			}
			for i, col := range sel.Columns {
				id, ok := col.(*ast.Identifier)
				if !ok {
					t.Fatalf("column %d: expected *ast.Identifier, got %T", i, col)
				}
				if id.Quoted != want[i] {
					t.Errorf("column %d (%s.%s): Quoted = %t, want %t", i, id.Table, id.Name, id.Quoted, want[i])
				}
			}
		})
	}
}
