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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestParser_ConnectByExpressions_Issue783 checks that CONNECT BY and START
// WITH accept the general expression grammar, with PRIOR binding to its
// operand, and that SQL() round-trips.
func TestParser_ConnectByExpressions_Issue783(t *testing.T) {
	dialects := []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectMariaDB}
	cases := []struct {
		name      string
		suffix    string // text after "SELECT id FROM t "
		wantShape string // shape of the CONNECT BY condition
	}{
		{"prior_eq_rhs_plus", "CONNECT BY PRIOR id = parent_id + 1", "(= (PRIOR id) (+ parent_id 1))"},
		{"prior_lhs_plus", "CONNECT BY PRIOR a + 1 = b", "(= (+ (PRIOR a) 1) b)"},
		{"prior_rhs_arith", "CONNECT BY id = PRIOR parent_id * 2", "(= id (* (PRIOR parent_id) 2))"},
		{"prior_both_sides", "CONNECT BY PRIOR a + 1 = b - PRIOR c", "(= (+ (PRIOR a) 1) (- b (PRIOR c)))"},
		{"and", "CONNECT BY PRIOR id = parent_id AND active = 1", "(AND (= (PRIOR id) parent_id) (= active 1))"},
		{"or_and_precedence", "CONNECT BY PRIOR id = parent_id OR x = 1 AND y = 2", "(OR (= (PRIOR id) parent_id) (AND (= x 1) (= y 2)))"},
		{"not", "CONNECT BY PRIOR id = parent_id AND NOT archived", "(AND (= (PRIOR id) parent_id) (NOT archived))"},
		{"nocycle", "CONNECT BY NOCYCLE PRIOR id = parent_id + 1", "(= (PRIOR id) (+ parent_id 1))"},
		{"concat", "CONNECT BY PRIOR path || '/' = parent_path", "(= (|| (PRIOR path) '/') parent_path)"},
		{"function", "CONNECT BY PRIOR id = COALESCE(parent_id, 0)", ""},
		{"in_list", "CONNECT BY PRIOR id = parent_id AND level_no IN (1, 2)", "(AND (= (PRIOR id) parent_id) (IN level_no [1 2]))"},
		{"between", "CONNECT BY PRIOR id = parent_id AND x BETWEEN 1 AND 5", "(AND (= (PRIOR id) parent_id) (BETWEEN x 1 5))"},
		{"parenthesized", "CONNECT BY (PRIOR id = parent_id) AND active = 1", "(AND (PAREN (= (PRIOR id) parent_id)) (= active 1))"},
		{"start_with_expr", "START WITH parent_id IS NULL AND id + 1 > 0 CONNECT BY PRIOR id = parent_id", ""},
	}

	for _, tc := range cases {
		for _, d := range dialects {
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				sql := "SELECT id FROM t " + tc.suffix
				tree, err := ParseWithDialect(sql, d)
				if err != nil {
					t.Fatalf("ParseWithDialect(%q, %s): %v", sql, d, err)
				}
				defer ast.ReleaseAST(tree)
				stmt, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				if stmt.ConnectBy == nil {
					t.Fatal("ConnectBy is nil")
				}
				if tc.wantShape != "" {
					if got := rhs596Shape(t, stmt.ConnectBy.Condition); got != tc.wantShape {
						t.Fatalf("shape = %s, want %s", got, tc.wantShape)
					}
				}
				if tc.name == "nocycle" && !stmt.ConnectBy.NoCycle {
					t.Fatal("NoCycle not set")
				}
				if tc.name == "start_with_expr" && stmt.StartWith == nil {
					t.Fatal("StartWith is nil")
				}

				got := tree.SQL()
				if got != sql {
					t.Fatalf("SQL() = %q, want %q", got, sql)
				}
				tree2, err := ParseWithDialect(got, d)
				if err != nil {
					t.Fatalf("re-parse of %q: %v", got, err)
				}
				defer ast.ReleaseAST(tree2)
				if again := tree2.SQL(); again != got {
					t.Fatalf("re-parse SQL() = %q, want %q", again, got)
				}
			})
		}
	}
}

// TestParser_ConnectByPriorColumnName verifies a column literally named
// prior still parses outside CONNECT BY.
func TestParser_ConnectByPriorColumnName(t *testing.T) {
	tree, err := ParseWithDialect("SELECT prior FROM t WHERE prior = 1", keywords.DialectOracle)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	if got, want := tree.SQL(), "SELECT prior FROM t WHERE prior = 1"; got != want {
		t.Fatalf("SQL() = %q, want %q", got, want)
	}
}
