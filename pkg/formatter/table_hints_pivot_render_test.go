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

type hintsFmtCase struct {
	name    string
	dialect keywords.SQLDialect
	input   string
	want    string
}

func hintsFmtCases() []hintsFmtCase {
	ss := keywords.DialectSQLServer
	return []hintsFmtCase{
		{"hint_issue_repro", ss, "SELECT * FROM t WITH (NOLOCK)", "SELECT * FROM t WITH (NOLOCK)"},
		{"hint_alias_multi", ss, "SELECT * FROM t AS x WITH (ROWLOCK, UPDLOCK)", "SELECT * FROM t x WITH (ROWLOCK, UPDLOCK)"},
		{"hint_join", ss, "SELECT * FROM t x WITH (NOLOCK) INNER JOIN u y WITH (NOLOCK) ON x.id = y.id", "SELECT * FROM t x WITH (NOLOCK) INNER JOIN u y WITH (NOLOCK) ON x.id = y.id"},
		{"hint_second_from", ss, "SELECT * FROM t1, t2 WITH (NOLOCK) WHERE t1.a = t2.a", "SELECT * FROM t1, t2 WITH (NOLOCK) WHERE t1.a = t2.a"},
		{"pivot_issue_repro", ss, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p", "SELECT * FROM s PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"},
		{"hint_and_pivot", ss, "SELECT * FROM t WITH (NOLOCK) PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p", "SELECT * FROM t WITH (NOLOCK) PIVOT (SUM(amt) FOR q IN ([Q1], [Q2])) AS p"},
		{"unpivot", ss, "SELECT * FROM t UNPIVOT (sales FOR region IN (north_sales, south_sales)) AS u", "SELECT * FROM t UNPIVOT (sales FOR region IN (north_sales, south_sales)) AS u"},
		{"oracle_pivot", keywords.DialectOracle, "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1 AS a, 2 AS b)) AS p", "SELECT * FROM s PIVOT (SUM(amt) FOR q IN (1 AS a, 2 AS b)) AS p"},
		{"snowflake_unpivot", keywords.DialectSnowflake, "SELECT * FROM s UNPIVOT (amount FOR quarter IN (q1, q2)) AS u", "SELECT * FROM s UNPIVOT (amount FOR quarter IN (q1, q2)) AS u"},
	}
}

// TestTableHints_FormatAST_Issue604 verifies pkg/formatter renders SQL Server
// table hints (and keeps rendering PIVOT/UNPIVOT) and that compact/readable
// output re-parses to the same SQL.
func TestTableHints_FormatAST_Issue604(t *testing.T) {
	for _, tc := range hintsFmtCases() {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)

			if got := formatter.FormatAST(tree, ast.CompactStyle()); got != tc.want {
				t.Errorf("FormatAST(compact) mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			if got := formatter.FormatAST(tree, ast.FormatOptions{}); got != tc.want {
				t.Errorf("FormatAST(zero opts) mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			if strings.Contains(tc.want, "WITH (NOLOCK)") {
				if got := gosqlx.FormatAST(tree); !strings.Contains(got, "WITH (NOLOCK)") {
					t.Errorf("gosqlx.FormatAST dropped hints: %s", got)
				}
			}

			readable := formatter.FormatAST(tree, ast.ReadableStyle())
			tree2, err := gosqlx.ParseWithDialect(readable, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse of readable output %q: %v", readable, err)
			}
			defer ast.ReleaseAST(tree2)
			if got := tree2.SQL(); got != tc.want {
				t.Errorf("readable round trip mismatch\n got: %s\nwant: %s\nreadable: %s", got, tc.want, readable)
			}
		})
	}
}

// TestTableHints_FormatAST_KeywordLower_Issue604 checks hints honor the
// keyword-case policy and still re-parse (the parser uppercases hints).
func TestTableHints_FormatAST_KeywordLower_Issue604(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT * FROM t WITH (NOLOCK)", keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)

	got := formatter.FormatAST(tree, ast.FormatOptions{KeywordCase: ast.KeywordLower})
	if !strings.Contains(got, "with (nolock)") {
		t.Fatalf("expected lower-case hints, got %s", got)
	}
	tree2, err := gosqlx.ParseWithDialect(got, keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("re-parse %q: %v", got, err)
	}
	defer ast.ReleaseAST(tree2)
	if s := tree2.SQL(); s != "SELECT * FROM t WITH (NOLOCK)" {
		t.Errorf("re-parsed SQL() = %s", s)
	}
}
