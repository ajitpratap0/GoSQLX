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

package gosqlx_test

import (
	"context"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParseTree_WithPipesAsConcat_Issue781 checks that the gosqlx option
// reaches the parser: MySQL || is OR by default and concatenation with
// WithPipesAsConcat; PostgreSQL is concatenation either way.
func TestParseTree_WithPipesAsConcat_Issue781(t *testing.T) {
	const sql = "SELECT * FROM t WHERE a = 1 || b"
	cases := []struct {
		name    string
		opts    []gosqlx.Option
		wantTop string // operator at the top of the WHERE clause
		wantSQL string
	}{
		// SQL() keeps the || spelling of a MySQL OR, so rendering does not
		// change the meaning under PIPES_AS_CONCAT.
		{"mysql_default", []gosqlx.Option{gosqlx.WithDialect("mysql")}, "OR", sql},
		{"mariadb_default", []gosqlx.Option{gosqlx.WithDialect("mariadb")}, "OR", sql},
		{"mysql_pipes_as_concat", []gosqlx.Option{gosqlx.WithDialect("mysql"), gosqlx.WithPipesAsConcat()}, "=", sql},
		{"pipes_as_concat_first", []gosqlx.Option{gosqlx.WithPipesAsConcat(), gosqlx.WithDialect("mariadb")}, "=", sql},
		{"postgresql", []gosqlx.Option{gosqlx.WithDialect("postgresql")}, "=", sql},
		{"postgresql_pipes_as_concat", []gosqlx.Option{gosqlx.WithDialect("postgresql"), gosqlx.WithPipesAsConcat()}, "=", sql},
		{"no_dialect", nil, "=", sql},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseTree(context.Background(), sql, tc.opts...)
			if err != nil {
				t.Fatalf("ParseTree: %v", err)
			}
			stmts := tree.Statements()
			if len(stmts) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(stmts))
			}
			sel, ok := stmts[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", stmts[0])
			}
			bin, ok := sel.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("WHERE is %T, want *ast.BinaryExpression", sel.Where)
			}
			if bin.Operator != tc.wantTop {
				t.Fatalf("top operator = %q, want %q", bin.Operator, tc.wantTop)
			}
			if got := sel.SQL(); got != tc.wantSQL {
				t.Fatalf("SQL() = %q, want %q", got, tc.wantSQL)
			}
		})
	}
}
