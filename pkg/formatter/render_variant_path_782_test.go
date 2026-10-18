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

func variantSQL(t *testing.T, input string) string {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(input, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse %q: %v", input, err)
	}
	defer ast.ReleaseAST(tree)
	return tree.SQL()
}

// TestVariantPath_SQLRoundTrip_782 checks that every variant path form the
// parser produces renders as a path (never a bare ':') and that
// parse -> SQL() -> parse -> SQL() is stable.
func TestVariantPath_SQLRoundTrip_782(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // expected first rendering; empty means only check stability
	}{
		{"simple_where", `SELECT * FROM t WHERE src:a = 1`, `SELECT * FROM t WHERE src:a = 1`},
		{"nested", `SELECT src:a.b FROM t`, `SELECT src:a.b FROM t`},
		{"index", `SELECT src:a[0] FROM t`, `SELECT src:a[0] FROM t`},
		{"nested_index_field", `SELECT src:a.b[0].c FROM t`, `SELECT src:a.b[0].c FROM t`},
		{"index_expr", `SELECT src:a[i + 1] FROM t`, ``},
		{"qualified_root", `SELECT t.src:a.b FROM t`, `SELECT t.src:a.b FROM t`},
		{"function_root", `SELECT PARSE_JSON(raw):a.b FROM t`, `SELECT PARSE_JSON(raw):a.b FROM t`},
		{"bracket_key", `SELECT src['key'] FROM t`, `SELECT src['key'] FROM t`},
		{"cast_select", `SELECT src:a.b::int FROM t`, ``},
		{"cast_rhs", `SELECT * FROM t WHERE a = src:b::int`, ``},
		{"cast_both_sides", `SELECT * FROM t WHERE src:a::int = src:b::int`, ``},
		{"rhs_plain", `SELECT * FROM t WHERE a = src:b`, `SELECT * FROM t WHERE a = src:b`},
		{"both_sides", `SELECT * FROM t WHERE src:a = src:b`, `SELECT * FROM t WHERE src:a = src:b`},
		{"order_by", `SELECT id FROM t ORDER BY src:a.b DESC`, `SELECT id FROM t ORDER BY src:a.b DESC`},
		{"group_by", `SELECT src:a, COUNT(*) FROM t GROUP BY src:a`, `SELECT src:a, COUNT(*) FROM t GROUP BY src:a`},
		{"quoted_field", `SELECT src:"my key" FROM t`, `SELECT src:"my key" FROM t`},
		{"keyword_field", `SELECT src:value.type FROM t`, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := variantSQL(t, tc.input)
			if strings.Contains(first, ": ") || strings.Contains(first, "(:") || strings.HasSuffix(first, ":") {
				t.Fatalf("bare ':' in output: %s", first)
			}
			if tc.want != "" && first != tc.want {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", first, tc.want)
			}
			second := variantSQL(t, first)
			if second != first {
				t.Errorf("round-trip not stable\n first: %s\nsecond: %s", first, second)
			}
		})
	}
}

// TestVariantPath_FormatAST_Reparses_782 checks that formatter output for
// variant paths parses again and is stable under both styles.
func TestVariantPath_FormatAST_Reparses_782(t *testing.T) {
	inputs := []string{
		`SELECT src:a, src:a.b[0].c::int FROM t WHERE src:a = 1 AND b = src:c::int GROUP BY src:a ORDER BY src:a.b`,
		`SELECT src['key'], src:"a b" FROM t WHERE src:x[1] > src:y`,
	}
	for _, input := range inputs {
		tree, err := gosqlx.ParseWithDialect(input, keywords.DialectSnowflake)
		if err != nil {
			t.Fatalf("parse %q: %v", input, err)
		}
		for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
			got := formatter.FormatAST(tree, opts)
			tree2, err := gosqlx.ParseWithDialect(got, keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("re-parse of %q: %v", got, err)
			}
			got2 := formatter.FormatAST(tree2, opts)
			ast.ReleaseAST(tree2)
			if got2 != got {
				t.Errorf("format not stable\n first: %s\nsecond: %s", got, got2)
			}
		}
		ast.ReleaseAST(tree)
	}
}

// TestVariantPath_HostileKey_782 checks that a hostile field name cannot
// break out of the path: it is double-quoted with embedded quotes doubled and
// the output re-parses as one statement with one path.
func TestVariantPath_HostileKey_782(t *testing.T) {
	hostile := []string{
		`a" ; DROP TABLE y; --`,
		`a b`,
		`a.b`,
		`a:b`,
		`1abc`,
		``,
		`x"y`,
		`a[0]`,
	}
	for _, key := range hostile {
		vp := &ast.VariantPath{
			Root:     &ast.Identifier{Name: "src"},
			Segments: []ast.VariantPathSegment{{Name: "ok"}, {Name: key}},
		}
		sel := &ast.SelectStatement{
			Columns: []ast.Expression{vp},
			From:    []ast.TableReference{{Name: "t"}},
		}
		tree := &ast.AST{Statements: []ast.Statement{sel}}
		want := `SELECT src:ok."` + strings.ReplaceAll(key, `"`, `""`) + `" FROM t`
		for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
			got := formatter.FormatAST(tree, opts)
			if opts == ast.CompactStyle() && got != want {
				t.Errorf("key %q\n got: %s\nwant: %s", key, got, want)
			}
			tree2, err := gosqlx.ParseWithDialect(got, keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("key %q: re-parse of %q: %v", key, got, err)
			}
			if n := len(tree2.Statements); n != 1 {
				t.Fatalf("key %q: output re-parses to %d statements: %s", key, n, got)
			}
			ast.ReleaseAST(tree2)
		}
		if got := vp.SQL(); got != `src:ok."`+strings.ReplaceAll(key, `"`, `""`)+`"` {
			t.Errorf("key %q: SQL() = %s", key, got)
		}
	}
}
