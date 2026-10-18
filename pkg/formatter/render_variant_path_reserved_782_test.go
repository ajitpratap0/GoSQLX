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

// TestVariantPath_ReservedWordFields_782 checks that JSON keys which are
// reserved words render quoted and re-parse, in both the ':' and '.'
// positions, via SQL() and FormatAST.
func TestVariantPath_ReservedWordFields_782(t *testing.T) {
	words := []string{
		"null", "true", "false", "and", "or", "not", "is", "in", "select", "from",
		"where", "as", "case", "when", "then", "else", "end", "between", "like",
		"ilike", "union", "except", "intersect", "order", "group", "by", "having",
		"limit", "offset", "fetch", "join", "on", "using", "inner", "outer", "left",
		"right", "full", "cross", "natural", "lateral", "interval", "exists",
		"distinct", "all", "any", "some", "with", "recursive", "over", "partition",
		"asc", "desc", "nulls", "first", "last", "default", "values", "set", "into",
		"key", "row", "array", "cast", "collate", "autoincrement", "materialized",
	}
	for _, w := range words {
		for _, word := range []string{w, strings.ToUpper(w)} {
			for _, tc := range []struct{ name, in string }{
				{"colon", `SELECT src:"` + word + `" FROM t`},
				{"dot", `SELECT src:a."` + word + `" FROM t`},
			} {
				t.Run(tc.name+"/"+word, func(t *testing.T) {
					first := variantSQL(t, tc.in)
					if first != tc.in {
						t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", first, tc.in)
					}
					tree, err := gosqlx.ParseWithDialect(first, keywords.DialectSnowflake)
					if err != nil {
						t.Fatalf("re-parse %q: %v", first, err)
					}
					defer ast.ReleaseAST(tree)
					for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
						out := formatter.FormatAST(tree, opts)
						tree2, err := gosqlx.ParseWithDialect(out, keywords.DialectSnowflake)
						if err != nil {
							t.Fatalf("re-parse of formatted %q: %v", out, err)
						}
						ast.ReleaseAST(tree2)
					}
				})
			}
		}
	}
}

// TestVariantPath_HandBuilt_782 covers hand-built paths the parser never
// produces: a leading index segment and an operator-like root.
func TestVariantPath_HandBuilt_782(t *testing.T) {
	cases := []struct {
		name string
		vp   *ast.VariantPath
		want string
	}{
		{"index_first", &ast.VariantPath{
			Root: &ast.Identifier{Name: "src"},
			Segments: []ast.VariantPathSegment{
				{Index: &ast.LiteralValue{Value: "0", Type: "INTEGER"}},
				{Name: "a"}, {Name: "b"},
			},
		}, `src[0]:a.b`},
		{"binary_root", &ast.VariantPath{
			Root: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "a"},
				Operator: "+",
				Right:    &ast.Identifier{Name: "b"},
			},
			Segments: []ast.VariantPathSegment{{Name: "c"}},
		}, `(a + b):c`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.vp.SQL(); got != tc.want {
				t.Fatalf("SQL() = %q, want %q", got, tc.want)
			}
			tree, err := gosqlx.ParseWithDialect("SELECT "+tc.want+" FROM t", keywords.DialectSnowflake)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			ast.ReleaseAST(tree)
		})
	}
}
