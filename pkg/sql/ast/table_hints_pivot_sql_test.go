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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// hintsPivotCase is shared by the SQL() and formatter round-trip tests for
// issue #604 (SQL Server table hints and PIVOT/UNPIVOT dropped on render).
type hintsPivotCase struct {
	name    string
	dialect keywords.SQLDialect
	input   string
	want    string
}

const (
	pivotSQL   = "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"
	nolockSQL  = "SELECT * FROM t WITH (NOLOCK)"
	unpivotSQL = "SELECT * FROM t UNPIVOT (sales FOR region IN (north_sales, south_sales)) AS u"
)

func hintsPivotCases() []hintsPivotCase {
	ss := keywords.DialectSQLServer
	return []hintsPivotCase{
		{"hint_issue_repro", ss, nolockSQL, nolockSQL},
		{"hint_alias_multi", ss, "SELECT * FROM t AS x WITH (ROWLOCK, UPDLOCK)", "SELECT * FROM t x WITH (ROWLOCK, UPDLOCK)"},
		{"hint_lowercase", ss, "select * from t with (nolock)", nolockSQL},
		{"hint_no_commas", ss, "SELECT * FROM t WITH (ROWLOCK UPDLOCK)", "SELECT * FROM t WITH (ROWLOCK, UPDLOCK)"},
		{"hint_join", ss, "SELECT * FROM t x WITH (NOLOCK) INNER JOIN u y WITH (NOLOCK) ON x.id = y.id", "SELECT * FROM t x WITH (NOLOCK) INNER JOIN u y WITH (NOLOCK) ON x.id = y.id"},
		{"hint_second_from", ss, "SELECT * FROM t1, t2 WITH (NOLOCK) WHERE t1.a = t2.a", "SELECT * FROM t1, t2 WITH (NOLOCK) WHERE t1.a = t2.a"},
		{"hint_cte", ss, "WITH c AS (SELECT 1 AS a) SELECT * FROM c WITH (NOLOCK)", "WITH c AS (SELECT 1 AS a) SELECT * FROM c WITH (NOLOCK)"},
		{"hint_union", ss, "SELECT * FROM t WITH (NOLOCK) UNION SELECT * FROM u WITH (NOLOCK)", "SELECT * FROM t WITH (NOLOCK) UNION SELECT * FROM u WITH (NOLOCK)"},
		{"pivot_issue_repro", ss, pivotSQL, pivotSQL},
		{"pivot_bare_alias", ss, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) p", pivotSQL},
		{"pivot_no_alias", ss, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2]))", "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2]))"},
		{"hint_and_pivot", ss, "SELECT * FROM t WITH (NOLOCK) PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p", "SELECT * FROM t WITH (NOLOCK) PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"},
		{"unpivot", ss, unpivotSQL, unpivotSQL},
		{"pivot_join", ss, "SELECT * FROM a CROSS JOIN s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p", "SELECT * FROM a CROSS JOIN s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"},
		{"pivot_derived", ss, "SELECT * FROM (SELECT a, q, amt FROM s) PIVOT (SUM(amt) FOR q IN ([Q1])) AS p", "SELECT * FROM (SELECT a, q, amt FROM s) PIVOT (SUM(amt) FOR q IN ([Q1])) AS p"},
		{"oracle_pivot", keywords.DialectOracle, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1 AS a, 2 AS b)) AS p", "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1 AS a, 2 AS b)) AS p"},
		{"oracle_unpivot", keywords.DialectOracle, "SELECT * FROM s UNPIVOT (v FOR n IN (c1, c2))", "SELECT * FROM s UNPIVOT (v FOR n IN (c1, c2))"},
		{"snowflake_pivot", keywords.DialectSnowflake, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1, 2)) AS p", "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1, 2)) AS p"},
		{"snowflake_unpivot", keywords.DialectSnowflake, "SELECT * FROM s UNPIVOT (amount FOR quarter IN (q1, q2)) AS u", "SELECT * FROM s UNPIVOT (amount FOR quarter IN (q1, q2)) AS u"},
		{"postgres_pivot_is_alias", keywords.DialectPostgreSQL, "SELECT * FROM t pivot", "SELECT * FROM t pivot"},
	}
}

// hintsPivotSig summarizes alias, hints and pivot/unpivot presence of every
// table reference of the first SELECT in tree (FROM entries then JOIN right
// sides, recursing into nothing deeper) so re-parses can be compared.
func hintsPivotSig(t *testing.T, tree *ast.AST) string {
	t.Helper()
	if len(tree.Statements) == 0 {
		t.Fatalf("no statements")
	}
	var sel *ast.SelectStatement
	switch s := tree.Statements[0].(type) {
	case *ast.SelectStatement:
		sel = s
	case *ast.SetOperation:
		l, ok := s.Left.(*ast.SelectStatement)
		if !ok {
			t.Fatalf("set operation left is %T", s.Left)
		}
		sel = l
	default:
		t.Fatalf("unexpected statement %T", tree.Statements[0])
	}
	var parts []string
	add := func(r *ast.TableReference) {
		sig := "alias=" + r.Alias + ";hints=" + strings.Join(r.TableHints, ",")
		if r.Pivot != nil {
			sig += ";pivot"
		}
		if r.Unpivot != nil {
			sig += ";unpivot"
		}
		parts = append(parts, sig)
	}
	for i := range sel.From {
		add(&sel.From[i])
	}
	for i := range sel.Joins {
		add(&sel.Joins[i].Right)
	}
	return strings.Join(parts, " | ")
}

// TestTableHintsPivot_SQLRoundTrip_Issue604 verifies that SQL() renders SQL
// Server table hints and PIVOT/UNPIVOT, and that the output re-parses to an
// equivalent AST.
func TestTableHintsPivot_SQLRoundTrip_Issue604(t *testing.T) {
	for _, tc := range hintsPivotCases() {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)

			got := tree.SQL()
			if got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			sig1 := hintsPivotSig(t, tree)
			if strings.Contains(tc.want, "WITH (") && !strings.Contains(tc.name, "cte") && !strings.Contains(sig1, "hints=") {
				t.Fatalf("expected hints in AST, sig=%s", sig1)
			}

			tree2, err := gosqlx.ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if got2 := tree2.SQL(); got2 != tc.want {
				t.Errorf("re-parsed SQL() mismatch\n got: %s\nwant: %s", got2, tc.want)
			}
			if sig2 := hintsPivotSig(t, tree2); sig2 != sig1 {
				t.Errorf("AST changed across round trip\n first: %s\nsecond: %s", sig1, sig2)
			}
		})
	}
}

// TestTableRef_HintsPivot_HandBuilt_Issue604 exercises hand-built nodes.
func TestTableRef_HintsPivot_HandBuilt_Issue604(t *testing.T) {
	sel := func(r ast.TableReference) *ast.SelectStatement {
		return &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
			From:    []ast.TableReference{r},
		}
	}
	cases := []struct {
		name string
		ref  ast.TableReference
		want string
	}{
		{"empty_hints", ast.TableReference{Name: "t", TableHints: []string{}}, "SELECT * FROM t"},
		{"nil_aggregate", ast.TableReference{Name: "s", Pivot: &ast.PivotClause{PivotColumn: "q", InValues: []string{"x"}}}, "SELECT * FROM s PIVOT ( FOR q IN (x))"},
		{"unpivot_alias", ast.TableReference{Name: "t", Alias: "u", Unpivot: &ast.UnpivotClause{ValueColumn: "v", NameColumn: "n", InColumns: []string{"a", "b"}}}, "SELECT * FROM t UNPIVOT (v FOR n IN (a, b)) AS u"},
		{"alias_hints", ast.TableReference{Name: "t", Alias: "x", TableHints: []string{"NOLOCK"}}, "SELECT * FROM t x WITH (NOLOCK)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sel(tc.ref).SQL(); got != tc.want {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}
