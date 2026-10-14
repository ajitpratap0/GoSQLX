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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestClickHouseFromTableFunctions_Issue606 verifies that ClickHouse table
// functions in the FROM list (numbers, remote, file, url, merge, ...) parse
// into a TableReference with TableFunc set. Regression for #606.
func TestClickHouseFromTableFunctions_Issue606(t *testing.T) {
	cases := []struct {
		name        string
		sql         string
		fromIdx     int
		wantFromLen int
		wantFunc    string
		wantArgs    int
		wantAlias   string
		wantJoins   int
	}{
		{"numbers", `SELECT * FROM numbers(10)`, 0, 1, "numbers", 1, "", 0},
		{"numbers_alias", `SELECT number FROM numbers(10) AS n`, 0, 1, "numbers", 1, "n", 0},
		{"remote", `SELECT * FROM remote('host', db, tbl)`, 0, 1, "remote", 3, "", 0},
		{"comma_list", `SELECT * FROM t, numbers(3)`, 1, 2, "numbers", 1, "", 0},
		{"file", `SELECT * FROM file('data.csv', CSV)`, 0, 1, "file", 2, "", 0},
		{"url_keyword", `SELECT * FROM url('http://x/y', CSV, 'a UInt8')`, 0, 1, "url", 3, "", 0},
		{"merge_keyword", `SELECT * FROM merge('db', '^t') AS m`, 0, 1, "merge", 2, "m", 0},
		{"values_keyword", `SELECT * FROM values('a Int8', 1, 2)`, 0, 1, "values", 3, "", 0},
		{"null_keyword", `SELECT * FROM null('a Int8')`, 0, 1, "null", 1, "", 0},
		{"s3", `SELECT * FROM s3('https://b/k.csv', 'CSV')`, 0, 1, "s3", 2, "", 0},
		{"cluster", `SELECT * FROM cluster('c', db.t)`, 0, 1, "cluster", 2, "", 0},
		{"generate_random_limit", `SELECT * FROM generateRandom('a Int8', 1, 10, 2) LIMIT 3`, 0, 1, "generateRandom", 4, "", 0},
		{"numbers_join", `SELECT * FROM numbers(0, 10) n JOIN t ON n.number = t.id`, 0, 1, "numbers", 2, "n", 1},
		{"numbers_settings", `SELECT count() FROM numbers(1000000) SETTINGS max_threads = 1`, 0, 1, "numbers", 1, "", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("parse %q failed: %v", tc.sql, err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.From) != tc.wantFromLen {
				t.Fatalf("len(From) = %d, want %d", len(sel.From), tc.wantFromLen)
			}
			if len(sel.Joins) != tc.wantJoins {
				t.Fatalf("len(Joins) = %d, want %d", len(sel.Joins), tc.wantJoins)
			}
			ref := sel.From[tc.fromIdx]
			if ref.TableFunc == nil {
				t.Fatalf("From[%d].TableFunc is nil (Name=%q)", tc.fromIdx, ref.Name)
			}
			if ref.TableFunc.Name != tc.wantFunc {
				t.Errorf("TableFunc.Name = %q, want %q", ref.TableFunc.Name, tc.wantFunc)
			}
			if ref.Name != tc.wantFunc {
				t.Errorf("TableReference.Name = %q, want %q", ref.Name, tc.wantFunc)
			}
			if got := len(ref.TableFunc.Arguments); got != tc.wantArgs {
				t.Errorf("len(TableFunc.Arguments) = %d, want %d", got, tc.wantArgs)
			}
			if ref.Alias != tc.wantAlias {
				t.Errorf("Alias = %q, want %q", ref.Alias, tc.wantAlias)
			}
			if tc.name == "comma_list" {
				if sel.From[0].Name != "t" {
					t.Errorf("From[0].Name = %q, want %q", sel.From[0].Name, "t")
				}
				if sel.From[0].TableFunc != nil {
					t.Errorf("From[0].TableFunc = %+v, want nil", sel.From[0].TableFunc)
				}
			}
		})
	}
}

// TestClickHouseInsertSelectFromTableFunction_Issue606 verifies that a table
// function in the FROM of an INSERT ... SELECT parses in ClickHouse.
func TestClickHouseInsertSelectFromTableFunction_Issue606(t *testing.T) {
	sql := `INSERT INTO t SELECT * FROM numbers(10)`
	if _, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse); err != nil {
		t.Fatalf("parse %q failed: %v", sql, err)
	}
}
