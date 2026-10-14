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

package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestReplaceTable_TableFunction checks that ReplaceTable renames a
// function-call table reference (FROM my_udtf(1)) and keeps its arguments.
// Rendering takes the name from TableReference.TableFunc, so the rename must
// reach the call as well as TableReference.Name.
func TestReplaceTable_TableFunction(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		old     string
		new     string
		want    string
	}{
		{
			name:    "postgresql FROM udtf",
			dialect: keywords.DialectPostgreSQL,
			sql:     "SELECT * FROM my_udtf(1) AS u WHERE u.a = 1",
			old:     "my_udtf",
			new:     "my_udtf_v2",
			want:    "my_udtf_v2(1)",
		},
		{
			name:    "clickhouse comma-joined table function",
			dialect: keywords.DialectClickHouse,
			sql:     "SELECT * FROM t, numbers(10) AS n WHERE t.id = n.number",
			old:     "numbers",
			new:     "numbers_mt",
			want:    "numbers_mt(10)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := ParseSQLWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			if len(tree.Statements) == 0 {
				t.Fatalf("no statements from %q", tt.sql)
			}
			stmt := tree.Statements[0]
			if err := Apply(stmt, ReplaceTable(tt.old, tt.new)); err != nil {
				t.Fatal(err)
			}
			sql, ok := stmt.(interface{ SQL() string })
			if !ok {
				t.Fatalf("statement %T has no SQL()", stmt)
			}
			for label, out := range map[string]string{"FormatSQL": format(stmt), "SQL": sql.SQL()} {
				if !strings.Contains(out, tt.want) {
					t.Errorf("%s: expected %q in output, got: %s", label, tt.want, out)
				}
			}
		})
	}
}

// TestReplaceTable_TableFunctionRefs covers table references built directly
// (the parser does not yet produce table functions on the JOIN side): a
// matching call is renamed in FROM and JOIN, and a call whose name differs
// from TableReference.Name is left alone.
func TestReplaceTable_TableFunctionRefs(t *testing.T) {
	shared := &ast.FunctionCall{Name: "gen", Arguments: []ast.Expression{&ast.LiteralValue{Value: "3", Type: "INTEGER"}}}
	joinFn := &ast.FunctionCall{Name: "gen", Arguments: []ast.Expression{&ast.LiteralValue{Value: "5", Type: "INTEGER"}}}
	otherFn := &ast.FunctionCall{Name: "other_fn"}
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From: []ast.TableReference{
			{Name: "gen", TableFunc: shared},
			{Name: "other", TableFunc: otherFn},
		},
		Joins: []ast.JoinClause{{
			Type:  "CROSS",
			Left:  ast.TableReference{Name: "gen", TableFunc: shared},
			Right: ast.TableReference{Name: "gen", TableFunc: joinFn},
		}},
	}
	if err := Apply(stmt, ReplaceTable("gen", "gen2")); err != nil {
		t.Fatal(err)
	}
	if err := Apply(stmt, ReplaceTable("other", "renamed")); err != nil {
		t.Fatal(err)
	}
	if shared.Name != "gen2" || joinFn.Name != "gen2" {
		t.Errorf("table function names = %q, %q, want gen2", shared.Name, joinFn.Name)
	}
	if otherFn.Name != "other_fn" {
		t.Errorf("TableFunc.Name = %q, want other_fn unchanged", otherFn.Name)
	}
	out := stmt.SQL()
	for _, want := range []string{"gen2(3)", "gen2(5)", "other_fn()"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got: %s", want, out)
		}
	}
}
