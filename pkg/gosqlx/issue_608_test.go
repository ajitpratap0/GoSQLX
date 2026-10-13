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

// Package gosqlx - issue_608_test.go
// End-to-end regression tests for GitHub issue #608: a bare named-window
// reference (OVER w) must render as OVER w, a WINDOW definition must not repeat
// its own name inside AS (...), and the SQL:2003 existing-window refinement
// OVER (w ORDER BY z) must parse. Before the fix the output was
// "OVER (w) ... WINDOW w AS (w PARTITION BY ...)", which does not re-parse.

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestIssue608_NamedWindowRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{
			name: "bare reference",
			sql:  "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "refinement with ORDER BY",
			sql:  "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "parenthesized reference",
			sql:  "SELECT sum(x) OVER (w) FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER (w) FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "definition with frame",
			sql:  "SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)",
			want: "SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)",
		},
		{
			name: "refinement with frame",
			sql:  "SELECT sum(x) OVER (w ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t WINDOW w AS (PARTITION BY y ORDER BY z)",
			want: "SELECT sum(x) OVER (w ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t WINDOW w AS (PARTITION BY y ORDER BY z)",
		},
		{
			name: "window chain",
			sql:  "SELECT sum(x) OVER w2, avg(x) OVER w1 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b)",
			want: "SELECT sum(x) OVER w2, avg(x) OVER w1 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b)",
		},
		{
			name: "legacy bare definition keeps base window",
			sql:  "SELECT sum(x) OVER w FROM t WINDOW w AS w2",
			want: "SELECT sum(x) OVER w FROM t WINDOW w AS (w2)",
		},
	}

	dialects := []keywords.SQLDialect{"", keywords.DialectPostgreSQL, keywords.DialectMySQL}

	parse := func(t *testing.T, d keywords.SQLDialect, sql string) *ast.AST {
		t.Helper()
		var (
			tree *ast.AST
			err  error
		)
		if d == "" {
			tree, err = Parse(sql)
		} else {
			tree, err = ParseWithDialect(sql, d)
		}
		if err != nil {
			t.Fatalf("parse(%q, dialect %q) error: %v", sql, d, err)
		}
		return tree
	}

	for _, d := range dialects {
		for _, tc := range cases {
			name := string(d)
			if name == "" {
				name = "default"
			}
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				tree := parse(t, d, tc.sql)
				defer ast.ReleaseAST(tree)

				got := tree.SQL()
				if got != tc.want {
					t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
				}
				if strings.Contains(got, "AS (w PARTITION") || strings.Contains(got, "AS (w1 PARTITION") {
					t.Errorf("definition name repeated inside AS (...): %s", got)
				}

				again := parse(t, d, got)
				defer ast.ReleaseAST(again)
				if s := again.SQL(); s != tc.want {
					t.Errorf("round-trip mismatch\n got: %s\nwant: %s", s, tc.want)
				}

				compact := formatter.FormatAST(tree, ast.CompactStyle())
				fmtTree := parse(t, d, compact)
				defer ast.ReleaseAST(fmtTree)
				if s := fmtTree.SQL(); s != tc.want {
					t.Errorf("FormatAST(CompactStyle) re-parse mismatch\nformatted: %s\n      got: %s\n     want: %s", compact, s, tc.want)
				}
			})
		}
	}
}

func TestIssue608_FormatBareNamedWindow(t *testing.T) {
	const sql = "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)"
	out, err := Format(sql, FormatOptions{})
	if err != nil {
		t.Fatalf("Format(%q) error: %v", sql, err)
	}
	if !strings.Contains(out, "OVER w") || strings.Contains(out, "OVER (w)") {
		t.Errorf("Format() = %q, want it to contain bare %q", out, "OVER w")
	}
	if strings.Contains(out, "AS (w ") {
		t.Errorf("Format() = %q repeats the definition name inside AS (...)", out)
	}
	tree, err := Parse(out)
	if err != nil {
		t.Fatalf("re-Parse(Format() = %q) error: %v", out, err)
	}
	ast.ReleaseAST(tree)
}
