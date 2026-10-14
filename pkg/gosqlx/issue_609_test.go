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

// Package gosqlx - issue_609_test.go
// End-to-end regression tests for GitHub issue #609: window frames must accept
// the SQL:2011 GROUPS unit and the EXCLUDE clause, and an ANSI-qualified
// INTERVAL literal (INTERVAL '1' DAY, INTERVAL '1-2' YEAR TO MONTH) must parse
// as one expression - both as a frame offset and in a select list, where the
// unit used to be taken as an implicit column alias (INTERVAL '1' AS DAY).

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestIssue609_WindowFrameRoundTrip(t *testing.T) {
	// want defaults to sql when empty.
	cases := []struct {
		name string
		sql  string
		want string
	}{
		{name: "groups between", sql: "SELECT sum(x) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t"},
		{name: "groups single bound", sql: "SELECT sum(x) OVER (ORDER BY y GROUPS UNBOUNDED PRECEDING) FROM t"},
		{name: "exclude current row", sql: "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE CURRENT ROW) FROM t"},
		{name: "exclude ties", sql: "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM t"},
		{name: "exclude group", sql: "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE GROUP) FROM t"},
		{name: "exclude no others", sql: "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE NO OTHERS) FROM t"},
		{name: "range single bound exclude", sql: "SELECT sum(x) OVER (ORDER BY y RANGE UNBOUNDED PRECEDING EXCLUDE TIES) FROM t"},
		{name: "partition groups exclude group", sql: "SELECT sum(x) OVER (PARTITION BY p ORDER BY y GROUPS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE GROUP) FROM t"},
		{name: "window definition", sql: "SELECT sum(x) OVER w FROM t WINDOW w AS (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES)"},
		{name: "base window refinement", sql: "SELECT sum(x) OVER (w ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE NO OTHERS) FROM t WINDOW w AS (ORDER BY y)"},
		{name: "range interval day", sql: "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW) FROM t"},
		{name: "range interval year to month", sql: "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1-2' YEAR TO MONTH PRECEDING AND INTERVAL '1' DAY FOLLOWING) FROM t"},
		{name: "interval qualifier in arithmetic", sql: "SELECT d + INTERVAL '1' DAY FROM t"},
		{name: "lowercase qualifier", sql: "SELECT INTERVAL '1' day FROM t", want: "SELECT INTERVAL '1' DAY FROM t"},
		{name: "explicit alias unaffected", sql: "SELECT INTERVAL '1 day' AS day FROM t"},
		{name: "control interval string frame", sql: "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1 day' PRECEDING AND CURRENT ROW) FROM t"},
		{name: "control rows frame", sql: "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM t"},
	}

	dialects := []keywords.SQLDialect{"", keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite}

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
			want := tc.want
			if want == "" {
				want = tc.sql
			}
			name := string(d)
			if name == "" {
				name = "default"
			}
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				tree := parse(t, d, tc.sql)
				defer ast.ReleaseAST(tree)

				got := tree.SQL()
				if got != want {
					t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, want)
				}
				if strings.Contains(got, " AS DAY") {
					t.Errorf("interval unit rendered as an alias: %s", got)
				}

				again := parse(t, d, got)
				defer ast.ReleaseAST(again)
				if s := again.SQL(); s != want {
					t.Errorf("round-trip mismatch\n got: %s\nwant: %s", s, want)
				}

				compact := formatter.FormatAST(tree, ast.CompactStyle())
				fmtTree := parse(t, d, compact)
				defer ast.ReleaseAST(fmtTree)
				if s := fmtTree.SQL(); s != want {
					t.Errorf("FormatAST(CompactStyle) re-parse mismatch\nformatted: %s\n      got: %s\n     want: %s", compact, s, want)
				}
			})
		}
	}
}

func TestIssue609_Format(t *testing.T) {
	cases := []struct {
		sql     string
		want    string
		notWant string
	}{
		{
			sql:  "SELECT sum(x) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM t",
			want: "GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES",
		},
		{
			sql:     "SELECT d + INTERVAL '1' DAY FROM t",
			want:    "INTERVAL '1' DAY",
			notWant: "AS DAY",
		},
	}
	for _, tc := range cases {
		out, err := Format(tc.sql, FormatOptions{})
		if err != nil {
			t.Fatalf("Format(%q) error: %v", tc.sql, err)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("Format(%q) = %q, want it to contain %q", tc.sql, out, tc.want)
		}
		if tc.notWant != "" && strings.Contains(out, tc.notWant) {
			t.Errorf("Format(%q) = %q, must not contain %q", tc.sql, out, tc.notWant)
		}
		tree, err := Parse(out)
		if err != nil {
			t.Fatalf("re-Parse(Format() = %q) error: %v", out, err)
		}
		ast.ReleaseAST(tree)
	}
}
