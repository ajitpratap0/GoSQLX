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
			"SELECT * FROM sales PIVOT (SUM(amount) AS \"total amount\" FOR quarter IN ('Q1' AS `q 1`))",
		},
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
