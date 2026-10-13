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
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

var joinUsingRenderDialects = []keywords.SQLDialect{
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

// joinUsingNames returns the USING column names of each join in the first
// SELECT of tree.
func joinUsingNames(t *testing.T, tree *ast.AST) [][]string {
	t.Helper()
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	out := make([][]string, 0, len(sel.Joins))
	for i, j := range sel.Joins {
		if j.Condition != nil {
			t.Errorf("join %d: Condition = %T, want nil for USING", i, j.Condition)
		}
		names := make([]string, 0, len(j.Using))
		for k, u := range j.Using {
			id, ok := u.(*ast.Identifier)
			if !ok || id == nil {
				t.Fatalf("join %d Using[%d]: got %T, want *ast.Identifier", i, k, u)
			}
			names = append(names, id.Name)
		}
		out = append(out, names)
	}
	return out
}

// TestJoinUsing_FormatterRender_Issue603 checks that pkg/formatter renders
// JOIN ... USING (cols) instead of "ON cols" (#603) in compact and readable
// styles for every dialect, and that the output re-parses to the same USING
// columns.
func TestJoinUsing_FormatterRender_Issue603(t *testing.T) {
	cases := []struct {
		in          string
		wantCompact string
		wantLine    string // line expected in readable output
	}{
		{"SELECT * FROM a JOIN b USING (id)", "SELECT * FROM a INNER JOIN b USING (id)", "INNER JOIN b USING (id)"},
		{"SELECT * FROM a LEFT JOIN b USING (id, k)", "SELECT * FROM a LEFT JOIN b USING (id, k)", "LEFT JOIN b USING (id, k)"},
	}

	for _, d := range joinUsingRenderDialects {
		for _, tc := range cases {
			t.Run(string(d)+"/"+tc.in, func(t *testing.T) {
				tree, err := parser.ParseWithDialect(tc.in, d)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.in, err)
				}
				defer ast.ReleaseAST(tree)
				want := joinUsingNames(t, tree)

				compactStyle := ast.CompactStyle()
				compactStyle.Dialect = string(d)
				compact := FormatAST(tree, compactStyle)
				if compact != tc.wantCompact {
					t.Fatalf("compact mismatch\n got: %q\nwant: %q", compact, tc.wantCompact)
				}

				readableStyle := ast.ReadableStyle()
				readableStyle.Dialect = string(d)
				readable := FormatAST(tree, readableStyle)
				if !containsLine(readable, tc.wantLine) {
					t.Fatalf("readable output lacks line %q:\n%s", tc.wantLine, readable)
				}
				if strings.Contains(readable, " ON ") {
					t.Fatalf("readable output still renders ON:\n%s", readable)
				}

				for _, out := range []string{compact, readable} {
					again, err := parser.ParseWithDialect(out, d)
					if err != nil {
						t.Fatalf("re-parse of %q failed: %v", out, err)
					}
					got := joinUsingNames(t, again)
					ast.ReleaseAST(again)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("USING columns changed across round trip of %q: %v -> %v", out, want, got)
					}
				}
			})
		}
	}
}

// TestJoinUsing_FormatString_Issue603 covers the string-level API and the
// lowercase keyword option.
func TestJoinUsing_FormatString_Issue603(t *testing.T) {
	out, err := FormatString("SELECT * FROM a LEFT JOIN b USING (id, k)")
	if err != nil {
		t.Fatalf("FormatString: %v", err)
	}
	if !containsLine(out, "LEFT JOIN b USING (id, k)") || strings.Contains(out, " ON ") {
		t.Fatalf("FormatString output wrong:\n%s", out)
	}

	compact, err := New(Options{Compact: true}).Format("SELECT * FROM a JOIN b USING (id)")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.TrimSpace(compact) != "SELECT * FROM a INNER JOIN b USING (id)" {
		t.Fatalf("compact Format = %q", compact)
	}

	tree, err := parser.ParseWithDialect("SELECT * FROM a JOIN b USING (id)", keywords.DialectGeneric)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	if got, want := FormatAST(tree, lower), "select * from a inner join b using (id)"; got != want {
		t.Fatalf("lowercase compact = %q, want %q", got, want)
	}
}

// containsLine reports whether s has a line equal to want after trimming
// surrounding whitespace and a trailing semicolon.
func containsLine(s, want string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSuffix(strings.TrimSpace(line), ";") == want {
			return true
		}
	}
	return false
}
