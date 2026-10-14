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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestPivot_FormatAST_QuotedNamesAndStrings_PR632 checks that FormatAST keeps
// the quoting of PIVOT/UNPIVOT names and IN-list string literals, so the
// output re-parses as one statement with the same meaning.
func TestPivot_FormatAST_QuotedNamesAndStrings_PR632(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		input   string
	}{
		{"oracle_string_in_value", keywords.DialectOracle,
			`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('a)) AS p; DROP TABLE y; --')) AS p`},
		{"oracle_string_in_values_benign", keywords.DialectOracle,
			`SELECT * FROM s PIVOT (SUM(v) FOR k IN ('JAN', 'FEB')) AS p`},
		{"oracle_unpivot_string_alias", keywords.DialectOracle,
			`SELECT * FROM s UNPIVOT (v FOR n IN (c1 AS 'x)) AS u; DROP TABLE y; --')) AS u`},
		{"snowflake_unpivot_value_column", keywords.DialectSnowflake,
			`SELECT * FROM s UNPIVOT ("v FOR k IN (a)) AS u; DROP TABLE y; --" FOR k IN (a, b)) AS u`},
		{"sqlserver_pivot_column", keywords.DialectSQLServer,
			`SELECT * FROM s PIVOT (SUM(v) FOR "k IN (1)) AS p; DROP TABLE y; --" IN ([a])) AS p`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)
			for i, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
				got := formatter.FormatAST(tree, opts)
				if i == 0 && got != tc.input {
					t.Errorf("FormatAST(compact) mismatch\n got: %s\nwant: %s", got, tc.input)
				}
				tree2, err := gosqlx.ParseWithDialect(got, tc.dialect)
				if err != nil {
					t.Fatalf("re-parse of %q: %v", got, err)
				}
				n := len(tree2.Statements)
				ast.ReleaseAST(tree2)
				if n != 1 {
					t.Fatalf("FormatAST output re-parses to %d statements, want 1: %s", n, got)
				}
			}
		})
	}
}

// TestHintsPivot_FormatAST_HandBuiltUnsafe_PR632 checks that FormatAST quotes
// hand-built table hints, pivot columns and IN-list entries that are not
// well formed instead of writing them verbatim.
func TestHintsPivot_FormatAST_HandBuiltUnsafe_PR632(t *testing.T) {
	const evil = "x)) AS p; DROP TABLE y; --"
	tree := &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From: []ast.TableReference{
			{Name: "t", TableHints: []string{"NOLOCK", "X); DROP TABLE Y; --"}},
			{Name: "s", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "v"}, PivotColumn: evil, InValues: []string{"'a'", evil}}},
			{Name: "u", Unpivot: &ast.UnpivotClause{ValueColumn: evil, NameColumn: "n", InColumns: []string{"c1", evil}}},
		},
	}}}
	got := formatter.FormatAST(tree, ast.CompactStyle())
	want := `SELECT * FROM t WITH (NOLOCK, "X); DROP TABLE Y; --"), ` +
		`s PIVOT (v FOR "x)) AS p; DROP TABLE y; --" IN ('a', "x)) AS p; DROP TABLE y; --")), ` +
		`u UNPIVOT ("x)) AS p; DROP TABLE y; --" FOR n IN (c1, "x)) AS p; DROP TABLE y; --"))`
	if got != want {
		t.Fatalf("FormatAST mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestQuotedIdentifier_Format_ConsistentWithDefinitions_PR632 checks that
// gosqlx.Format renders a quoted reference with the same quoting as the alias
// or CTE column it refers to, so case folding keeps them matching.
func TestQuotedIdentifier_Format_ConsistentWithDefinitions_PR632(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{"order_by_alias", `SELECT amount AS "Total" FROM t ORDER BY "Total"`, "SELECT amount AS Total\nFROM t\nORDER BY Total"},
		{"cte_column", `WITH cte (a, "B") AS (SELECT 1, 2) SELECT "B" FROM cte`, "WITH cte (a, B) AS (SELECT 1, 2)\nSELECT B\nFROM cte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gosqlx.Format(tc.sql, gosqlx.DefaultFormatOptions())
			if err != nil {
				t.Fatalf("Format %q: %v", tc.sql, err)
			}
			if strings.TrimSpace(got) != tc.want {
				t.Fatalf("Format mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}
