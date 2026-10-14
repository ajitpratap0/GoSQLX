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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// semicolonInsideParens reports whether s has a ';' inside parentheses.
func semicolonInsideParens(s string) bool {
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ';':
			if depth > 0 {
				return true
			}
		}
	}
	return false
}

// TestParenSetOp_FormatterRender_Issue612 checks that pkg/formatter keeps
// set-operation operand parentheses and renders set-operation derived tables
// (#612): compact output is exact, no ';' lands inside parentheses with
// AddSemicolon on, and compact and readable output re-parse to the same
// compact SQL.
func TestParenSetOp_FormatterRender_Issue612(t *testing.T) {
	cases := []struct{ in, wantCompact string }{
		{"SELECT * FROM (SELECT 1 UNION SELECT 2) t", "SELECT * FROM (SELECT 1 UNION SELECT 2) t"},
		{"SELECT * FROM t1 JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a",
			"SELECT * FROM t1 INNER JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a"},
		{"SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t", "SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t"},
		{"SELECT * FROM ((SELECT 1)) t", "SELECT * FROM (SELECT 1) t"},
		{"SELECT * FROM (WITH c AS (SELECT 1 AS a) SELECT a FROM c) t",
			"SELECT * FROM (WITH c AS (SELECT 1 AS a) SELECT a FROM c) t"},
		{"(SELECT 1) UNION (SELECT 2)", "(SELECT 1) UNION (SELECT 2)"},
		{"(SELECT 1)", "SELECT 1"},
		{"(SELECT 1) ORDER BY 1", "SELECT 1 ORDER BY 1"},
		{"SELECT 1 UNION (SELECT 2)", "SELECT 1 UNION (SELECT 2)"},
		{"((SELECT 1) UNION (SELECT 2)) UNION SELECT 3", "((SELECT 1) UNION (SELECT 2)) UNION SELECT 3"},
		{"SELECT a FROM t EXCEPT (SELECT a FROM u UNION SELECT a FROM v)",
			"SELECT a FROM t EXCEPT (SELECT a FROM u UNION SELECT a FROM v)"},
		{"SELECT 1 UNION ALL (SELECT 2) UNION (SELECT 3)", "SELECT 1 UNION ALL (SELECT 2) UNION (SELECT 3)"},
	}
	readableNoSemi := ast.ReadableStyle()
	readableNoSemi.AddSemicolon = false
	compactSemi := ast.CompactStyle()
	compactSemi.AddSemicolon = true

	for _, d := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		for _, tc := range cases {
			tree, err := parser.ParseWithDialect(tc.in, d)
			if err != nil {
				t.Errorf("%s: %q: parse: %v", d, tc.in, err)
				continue
			}
			compact := FormatAST(tree, ast.CompactStyle())
			if compact != tc.wantCompact {
				t.Errorf("%s: %q: compact = %q, want %q", d, tc.in, compact, tc.wantCompact)
			}
			for name, opts := range map[string]ast.FormatOptions{
				"readable": ast.ReadableStyle(), "compact+semicolon": compactSemi,
			} {
				if out := FormatAST(tree, opts); semicolonInsideParens(out) {
					t.Errorf("%s: %q: %s output has ';' inside parentheses: %q", d, tc.in, name, out)
				}
			}
			readable := FormatAST(tree, readableNoSemi)
			ast.ReleaseAST(tree)

			for name, out := range map[string]string{"compact": compact, "readable": readable} {
				tree2, err := parser.ParseWithDialect(out, d)
				if err != nil {
					t.Errorf("%s: %q: %s output %q does not re-parse: %v", d, tc.in, name, out, err)
					continue
				}
				if got := FormatAST(tree2, ast.CompactStyle()); got != tc.wantCompact {
					t.Errorf("%s: %q: %s output re-parses to %q, want %q", d, tc.in, name, got, tc.wantCompact)
				}
				ast.ReleaseAST(tree2)
			}
		}
	}
}
