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

package formatter

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestNormalizeLimitForDialect checks that LIMIT / OFFSET values, integer or
// expression, become TOP / OFFSET ... FETCH for SQL Server and FETCH FIRST
// for Oracle when formatting for those dialects.
func TestNormalizeLimitForDialect(t *testing.T) {
	ph := func(v string) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "placeholder"} }
	intp := func(v int) *int { return &v }
	order := []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "a"}, Ascending: true}}
	cases := []struct {
		name    string
		dialect string
		mod     func(s *ast.SelectStatement)
		want    string
	}{
		{"sqlserver limit expr to top", "sqlserver", func(s *ast.SelectStatement) { s.LimitExpr = ph("@n") }, "SELECT TOP (@n) a FROM t"},
		{"sqlserver limit int to top", "sqlserver", func(s *ast.SelectStatement) { s.Limit = intp(5) }, "SELECT TOP 5 a FROM t"},
		{"sqlserver limit expr offset expr", "sqlserver", func(s *ast.SelectStatement) {
			s.OrderBy = order
			s.LimitExpr = ph("@n")
			s.OffsetExpr = ph("@s")
		}, "SELECT a FROM t ORDER BY a OFFSET @s ROWS FETCH NEXT @n ROWS ONLY"},
		{"sqlserver limit int offset int", "sqlserver", func(s *ast.SelectStatement) {
			s.OrderBy = order
			s.Limit = intp(10)
			s.Offset = intp(20)
		}, "SELECT a FROM t ORDER BY a OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY"},
		{"sqlserver limit all dropped", "sqlserver", func(s *ast.SelectStatement) { s.LimitAll = true }, "SELECT a FROM t"},
		{"oracle limit expr", "oracle", func(s *ast.SelectStatement) { s.LimitExpr = ph(":n") }, "SELECT a FROM t FETCH FIRST :n ROWS ONLY"},
		{"oracle limit with offset expr", "oracle", func(s *ast.SelectStatement) {
			s.LimitExpr = ph(":n")
			s.OffsetExpr = ph(":o")
		}, "SELECT a FROM t OFFSET :o ROWS FETCH FIRST :n ROWS ONLY"},
		{"postgres untouched", "postgresql", func(s *ast.SelectStatement) { s.LimitExpr = ph("$1") }, "SELECT a FROM t LIMIT $1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, From: []ast.TableReference{{Name: "t"}}}
			tc.mod(s)
			opts := ast.CompactStyle()
			opts.Dialect = tc.dialect
			got := FormatStatement(s, opts)
			if got != tc.want {
				t.Errorf("got:  %s\nwant: %s", got, tc.want)
			}
			if s.LimitExpr == nil && s.Limit == nil && !s.LimitAll && tc.dialect != "postgresql" {
				t.Errorf("FormatStatement mutated the input statement")
			}
		})
	}
}
