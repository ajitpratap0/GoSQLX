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
)

// joinUsingDialects lists every dialect the USING regression tests run under.
var joinUsingDialects = []keywords.SQLDialect{
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

// TestJoinUsing_AST_Issue603 checks that JOIN ... USING (cols) is stored in
// JoinClause.Using (one *ast.Identifier per column) with a nil Condition,
// rather than as a bare Identifier / ListExpression condition (#603).
func TestJoinUsing_AST_Issue603(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want [][]string // per join, the expected USING column names
	}{
		{"single column", "SELECT * FROM a JOIN b USING (id)", [][]string{{"id"}}},
		{"multi column", "SELECT * FROM a LEFT JOIN b USING (id, k)", [][]string{{"id", "k"}}},
		{"chained joins", "SELECT * FROM a JOIN b USING (id) JOIN c USING (k) WHERE x = 1", [][]string{{"id"}, {"k"}}},
	}

	for _, d := range joinUsingDialects {
		for _, tc := range cases {
			t.Run(string(d)+"/"+tc.name, func(t *testing.T) {
				tree, err := ParseWithDialect(tc.sql, d)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)

				sel, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				if len(sel.Joins) != len(tc.want) {
					t.Fatalf("got %d joins, want %d", len(sel.Joins), len(tc.want))
				}
				for i, wantCols := range tc.want {
					j := sel.Joins[i]
					if j.Condition != nil {
						t.Errorf("join %d: Condition = %T, want nil for USING", i, j.Condition)
					}
					if len(j.Using) != len(wantCols) {
						t.Fatalf("join %d: len(Using) = %d, want %d", i, len(j.Using), len(wantCols))
					}
					for k, col := range wantCols {
						id, ok := j.Using[k].(*ast.Identifier)
						if !ok || id == nil {
							t.Fatalf("join %d Using[%d]: got %T, want *ast.Identifier", i, k, j.Using[k])
						}
						if id.Name != col {
							t.Errorf("join %d Using[%d].Name = %q, want %q", i, k, id.Name, col)
						}
						if id.Pos.Line != 1 || id.Pos.Column <= 0 {
							t.Errorf("join %d Using[%d].Pos = %+v, want line 1 and a positive column", i, k, id.Pos)
						}
					}
				}
			})
		}

		t.Run(string(d)+"/ON join unchanged", func(t *testing.T) {
			tree, err := ParseWithDialect("SELECT * FROM a JOIN b ON a.id = b.id", d)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.Joins) != 1 {
				t.Fatalf("got %d joins, want 1", len(sel.Joins))
			}
			if _, ok := sel.Joins[0].Condition.(*ast.BinaryExpression); !ok {
				t.Errorf("Condition = %T, want *ast.BinaryExpression", sel.Joins[0].Condition)
			}
			if len(sel.Joins[0].Using) != 0 {
				t.Errorf("len(Using) = %d, want 0 for an ON join", len(sel.Joins[0].Using))
			}
		})
	}
}

// TestJoinUsing_Errors_Issue603 pins the USING error messages, which the
// #603 change must leave untouched.
func TestJoinUsing_Errors_Issue603(t *testing.T) {
	cases := []struct {
		sql     string
		wantMsg string
	}{
		{"SELECT * FROM a JOIN b USING ()", "column name in USING"},
		{"SELECT * FROM a JOIN b USING id", "( after USING"},
		{"SELECT * FROM a JOIN b USING (id", ") after USING column list"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectGeneric)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("expected an error for %q", tc.sql)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}
