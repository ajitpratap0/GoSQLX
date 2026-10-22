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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestSetOpWithHoist checks that a WITH clause scoping over a whole set
// operation stays in front of it when the left operand needs parentheses in
// the target dialect: the clause is hoisted out of the parentheses, so the
// other operands still see its CTEs and the grouping is kept.
func TestSetOpWithHoist(t *testing.T) {
	const with = "WITH c AS (SELECT 1 AS a) "
	tests := []struct {
		name    string
		parse   keywords.SQLDialect
		in      string
		render  string // target dialect
		want    string
		reparse bool // the output parses back with the target dialect to the same text
	}{
		{
			name:  "equal precedence tree written for standard precedence",
			parse: keywords.DialectSQLite, render: "postgresql",
			in:      with + "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			want:    with + "(SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c",
			reparse: true,
		},
		{
			name:  "equal precedence tree written for its own dialect",
			parse: keywords.DialectSQLite, render: "sqlite",
			in:      with + "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			want:    with + "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			reparse: true,
		},
		{
			name:  "no WITH keeps plain parentheses",
			parse: keywords.DialectSQLite, render: "postgresql",
			in:      "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			want:    "(SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c",
			reparse: true,
		},
		{
			name:  "WITH written before a parenthesized operand",
			parse: keywords.DialectPostgreSQL, render: "postgresql",
			in:      with + "(SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c",
			want:    with + "(SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c",
			reparse: true,
		},
		{
			name:  "WITH before a single parenthesized operand",
			parse: keywords.DialectPostgreSQL, render: "postgresql",
			in:      with + "(SELECT a FROM c) UNION SELECT a FROM c",
			want:    with + "(SELECT a FROM c) UNION SELECT a FROM c",
			reparse: true,
		},
		{
			name:  "WITH before a parenthesized query without set operation",
			parse: keywords.DialectPostgreSQL, render: "postgresql",
			in:   with + "(SELECT a FROM c)",
			want: with + "SELECT a FROM c",
		},
		{
			name:  "WITH inside the parentheses stays inside",
			parse: keywords.DialectPostgreSQL, render: "postgresql",
			in:      "(" + with + "SELECT a FROM c UNION SELECT 2) INTERSECT SELECT 3",
			want:    "(" + with + "SELECT a FROM c UNION SELECT 2) INTERSECT SELECT 3",
			reparse: true,
		},
		{
			name:  "chain with standard precedence keeps its WITH in place",
			parse: keywords.DialectPostgreSQL, render: "postgresql",
			in:      with + "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			want:    with + "SELECT a FROM c UNION SELECT a FROM c INTERSECT SELECT a FROM c",
			reparse: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tc.in, tc.parse)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			opts := ast.CompactStyle()
			opts.Dialect = tc.render
			if got := FormatAST(tree, opts); got != tc.want {
				t.Errorf("FormatAST(%q)\n got: %s\nwant: %s", tc.in, got, tc.want)
			}
			if tc.render == "postgresql" {
				// SQL() writes with standard precedence.
				if got := tree.SQL(); got != tc.want {
					t.Errorf("tree.SQL(%q)\n got: %s\nwant: %s", tc.in, got, tc.want)
				}
			}
			if !tc.reparse {
				return
			}
			out := FormatAST(tree, opts)
			tree2, err := parser.ParseWithDialect(out, keywords.SQLDialect(tc.render))
			if err != nil {
				t.Fatalf("output %q does not re-parse: %v", out, err)
			}
			defer ast.ReleaseAST(tree2)
			if got := FormatAST(tree2, opts); got != out {
				t.Errorf("output %q re-renders as %q", out, got)
			}
		})
	}
}

// TestParseWithParenthesizedQuery_Rejects checks the forms the parser refuses
// instead of misplacing a WITH clause.
func TestParseWithParenthesizedQuery_Rejects(t *testing.T) {
	for _, in := range []string{
		"WITH c AS (SELECT 1) (WITH d AS (SELECT 2) SELECT 3) UNION SELECT 4",
		"WITH c AS (SELECT 1) (VALUES (1)) UNION SELECT 4",
	} {
		tree, err := parser.ParseWithDialect(in, keywords.DialectPostgreSQL)
		if err == nil {
			ast.ReleaseAST(tree)
			t.Errorf("parse %q: expected an error", in)
		}
	}
}

// TestSetOperationTailRender checks that the ORDER BY / LIMIT after a set
// operation whose last operand has its own clauses is written after the whole
// operation in every layout, and that the output parses back to the same text.
func TestSetOperationTailRender(t *testing.T) {
	const in = "SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT 3 OFFSET 2"
	tree, err := parser.ParseWithDialect(in, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)

	compact := ast.CompactStyle()
	compact.Dialect = "postgresql"
	if got := FormatAST(tree, compact); got != in {
		t.Errorf("compact = %q, want %q", got, in)
	}
	for name, opts := range map[string]ast.FormatOptions{"readable": ast.ReadableStyle(), "compact+semicolon": func() ast.FormatOptions {
		o := ast.CompactStyle()
		o.AddSemicolon = true
		return o
	}()} {
		opts.Dialect = "postgresql"
		out := FormatAST(tree, opts)
		if !strings.Contains(out, "ORDER BY 1") || strings.Index(out, "ORDER BY 1") < strings.Index(out, ")") {
			t.Errorf("%s: tail is not after the parenthesized operand: %s", name, out)
		}
		tree2, err := parser.ParseWithDialect(out, keywords.DialectPostgreSQL)
		if err != nil {
			t.Errorf("%s: output %q does not re-parse: %v", name, out, err)
			continue
		}
		if got := FormatAST(tree2, compact); got != in {
			t.Errorf("%s: output re-parses to %q, want %q", name, got, in)
		}
		ast.ReleaseAST(tree2)
	}
}
