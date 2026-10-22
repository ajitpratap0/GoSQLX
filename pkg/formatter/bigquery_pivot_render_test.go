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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestBigQueryPivot_FormatRoundTrip_Issue854 verifies BigQuery PIVOT / UNPIVOT
// (including aggregate aliases, multiple aggregates, INCLUDE/EXCLUDE NULLS and
// the multi-column UNPIVOT form) render through both pkg/formatter and
// ast SQL(), and that the output re-parses to the same rendering.
func TestBigQueryPivot_FormatRoundTrip_Issue854(t *testing.T) {
	bq := keywords.DialectBigQuery
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"issue_repro",
			"SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2'))",
			"SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2'))",
		},
		{
			"aliases_and_multiple_aggregates",
			"SELECT * FROM produce PIVOT (SUM(sales) total_sales, COUNT(*) AS num_records FOR quarter IN ('Q1' AS q1, 'Q2' q2)) p",
			"SELECT * FROM produce PIVOT (SUM(sales) AS total_sales, COUNT(*) AS num_records FOR quarter IN ('Q1' AS q1, 'Q2' AS q2)) AS p",
		},
		{
			"backtick_alias",
			"SELECT * FROM sales PIVOT (SUM(amount) AS `total amount` FOR quarter IN ('Q1' AS `q 1`))",
			"SELECT * FROM sales PIVOT (SUM(amount) AS `total amount` FOR quarter IN ('Q1' AS `q 1`))",
		},
		{"backtick_first_and_extra_alias", "SELECT * FROM sales PIVOT (SUM(amount) AS `日本`, COUNT(*) `a``b` FOR quarter IN ('Q1'))", "SELECT * FROM sales PIVOT (SUM(amount) AS `日本`, COUNT(*) AS `a``b` FOR quarter IN ('Q1'))"},
		{"unpivot_backtick_value", "SELECT * FROM sales UNPIVOT (`日本` FOR quarter IN (Q1, Q2))", "SELECT * FROM sales UNPIVOT (`日本` FOR quarter IN (Q1, Q2))"},
		{"unpivot_backtick_value_set", "SELECT * FROM sales UNPIVOT ((`日本`, `a``b`) FOR quarter IN ((Q1, Q2)))", "SELECT * FROM sales UNPIVOT ((`日本`, `a``b`) FOR quarter IN ((Q1, Q2)))"},
		{
			"unpivot_include_nulls",
			"SELECT * FROM produce UNPIVOT INCLUDE NULLS (sales FOR quarter IN (Q1 'first', Q2 AS 2)) AS u",
			"SELECT * FROM produce UNPIVOT INCLUDE NULLS (sales FOR quarter IN (Q1 AS 'first', Q2 AS 2)) AS u",
		},
		{
			"unpivot_multi_column",
			"SELECT * FROM produce UNPIVOT EXCLUDE NULLS ((h1, h2) FOR semesters IN ((Q1, Q2) AS 'semester_1', (Q3, Q4) AS 'semester_2'))",
			"SELECT * FROM produce UNPIVOT EXCLUDE NULLS ((h1, h2) FOR semesters IN ((Q1, Q2) AS 'semester_1', (Q3, Q4) AS 'semester_2'))",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, bq)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)

			got := formatter.FormatAST(tree, ast.CompactStyle())
			if got != tc.want {
				t.Errorf("FormatAST(compact) mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if sqlOut := sel.SQL(); sqlOut != tc.want {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", sqlOut, tc.want)
			}

			// Re-parse the formatted output (compact and readable styles)
			// and check it renders identically.
			for _, style := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
				out := formatter.FormatAST(tree, style)
				tree2, err := gosqlx.ParseWithDialect(out, bq)
				if err != nil {
					t.Fatalf("re-parse %q: %v", out, err)
				}
				again := formatter.FormatAST(tree2, ast.CompactStyle())
				ast.ReleaseAST(tree2)
				if again != tc.want {
					t.Errorf("round trip mismatch\n got: %s\nwant: %s", again, tc.want)
				}
			}
		})
	}
}

// TestPivotItem_ColumnSetQuoting_Issue854 verifies a hand-built UNPIVOT IN
// column set is written verbatim only when well formed.
func TestPivotItem_ColumnSetQuoting_Issue854(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"(a, b)", "(a, b)"},
		{"(a, `b c`) AS 'k'", "(a, `b c`) AS 'k'"},
		{"(a, b) AS 1", "(a, b) AS 1"},
		{"(a, (b))", `"(a, (b))"`},
		{"(a, b", `"(a, b"`},
		{"(a,b)", `"(a,b)"`},
		{"(a, b)) --", `"(a, b)) --"`},
		{"()", `"()"`},
	}
	for _, tc := range cases {
		if got := ast.QuotePivotItem(tc.in); got != tc.want {
			t.Errorf("QuotePivotItem(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestOraclePivotQuotedAggregateAliasRoundTrip(t *testing.T) {
	const want = `SELECT * FROM sales PIVOT (SUM(amount) AS "Total", COUNT(*) AS "Count" FOR quarter IN ('Q1'))`
	tree, err := gosqlx.ParseWithDialect(want, keywords.DialectOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	out := formatter.FormatAST(tree, ast.CompactStyle())
	if out != want {
		t.Errorf("formatted = %s, want %s", out, want)
	}
	reparsed, err := gosqlx.ParseWithDialect(out, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	defer ast.ReleaseAST(reparsed)
	if got := formatter.FormatAST(reparsed, ast.CompactStyle()); got != want {
		t.Errorf("reparsed = %s, want %s", got, want)
	}
	if got := tree.SQL(); got != want {
		t.Errorf("SQL() = %s, want %s", got, want)
	}
}

func TestPivotQuotedNameFallback(t *testing.T) {
	makeSelect := func(ref ast.TableReference) *ast.SelectStatement {
		return &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "*"}}, From: []ast.TableReference{ref}}
	}
	cases := []struct {
		name string
		ref  ast.TableReference
		want string
	}{
		{"first_alias", ast.TableReference{Name: "t", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "x"}, AggregateAlias: "a); DROP", PivotColumn: "q", InValues: []string{"a"}}}, `SELECT * FROM t PIVOT (x AS "a); DROP" FOR q IN (a))`},
		{"string_alias", ast.TableReference{Name: "t", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "x"}, AggregateAlias: "'total'", PivotColumn: "q", InValues: []string{"a"}}}, `SELECT * FROM t PIVOT (x AS "'total'" FOR q IN (a))`},
		{"extra_alias", ast.TableReference{Name: "t", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "x"}, ExtraAggregates: []ast.PivotAggregate{{Function: &ast.Identifier{Name: "y"}, Alias: "select"}}, PivotColumn: "q", InValues: []string{"a"}}}, `SELECT * FROM t PIVOT (x, y AS "select" FOR q IN (a))`},
		{"numeric_extra_alias", ast.TableReference{Name: "t", Pivot: &ast.PivotClause{AggregateFunction: &ast.Identifier{Name: "x"}, ExtraAggregates: []ast.PivotAggregate{{Function: &ast.Identifier{Name: "y"}, Alias: "123"}}, PivotColumn: "q", InValues: []string{"a"}}}, `SELECT * FROM t PIVOT (x, y AS "123" FOR q IN (a))`},
		{"single_value", ast.TableReference{Name: "t", Unpivot: &ast.UnpivotClause{ValueColumn: "a); DROP", NameColumn: "q", InColumns: []string{"a"}}}, `SELECT * FROM t UNPIVOT ("a); DROP" FOR q IN (a))`},
		{"string_value", ast.TableReference{Name: "t", Unpivot: &ast.UnpivotClause{ValueColumn: "'total'", NameColumn: "q", InColumns: []string{"a"}}}, `SELECT * FROM t UNPIVOT ("'total'" FOR q IN (a))`},
		{"multiple_values", ast.TableReference{Name: "t", Unpivot: &ast.UnpivotClause{ValueColumns: []string{"select", "a); DROP"}, NameColumn: "q", InColumns: []string{"(a, b)"}}}, `SELECT * FROM t UNPIVOT (("select", "a); DROP") FOR q IN ((a, b)))`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel := makeSelect(tc.ref)
			if got := sel.SQL(); got != tc.want {
				t.Errorf("SQL() = %s, want %s", got, tc.want)
			}
			tree := &ast.AST{Statements: []ast.Statement{sel}}
			if got := formatter.FormatAST(tree, ast.CompactStyle()); got != tc.want {
				t.Errorf("formatter = %s, want %s", got, tc.want)
			}
		})
	}
}
