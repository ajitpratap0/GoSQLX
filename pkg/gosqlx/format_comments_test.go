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

package gosqlx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormat_PreservesCommentsAndHints(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.UppercaseKeywords = true
	compact := opts
	compact.IndentSize = 0

	tests := []struct {
		name string
		sql  string
		opts FormatOptions
		want string
	}{
		{"hint and trailing comment", "select /*+ hint */ a from t -- note", compact, "SELECT /*+ hint */ a FROM t -- note"},
		{"oracle full hint", "select /*+ FULL(t) */ a from t", compact, "SELECT /*+ FULL(t) */ a FROM t"},
		{"leading comment", "-- report\nselect a from t", compact, "-- report\nSELECT a FROM t"},
		{"comment between statements", "select 1; -- one\n-- two\nselect 2", compact, "SELECT 1; -- one\n-- two\nSELECT 2"},
		{"inner comment moves up", "select a, /* new */ b from t", compact, "/* new */\nSELECT a, b FROM t"},
		{"no comments unchanged path", "select a from t", compact, "SELECT a FROM t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Format(tt.sql, tt.opts)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormat_RefusesToDropAnOptimizerHint(t *testing.T) {
	_, err := Format("select a from /*+ FULL(t) */ t", DefaultFormatOptions())
	if !errors.Is(err, formatter.ErrUnplaceableComment) {
		t.Fatalf("err = %v, want it to wrap formatter.ErrUnplaceableComment", err)
	}
}

func TestFormat_KeepsHintInSubquery(t *testing.T) {
	got, err := Format("select * from (select /*+ FULL(t) */ a from t) s", DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(got, "SELECT /*+ FULL(t) */ a") {
		t.Fatalf("got %q, lost the hint after the inner SELECT", got)
	}
}

func TestFormat_AddSemicolonWithComments(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.AddSemicolon = true
	opts.IndentSize = 0
	got, err := Format("select 1 -- a\n; select 2 -- b", opts)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Count(got, ";") != 2 {
		t.Fatalf("got %q, want exactly two semicolons", got)
	}
	for _, c := range []string{"-- a", "-- b"} {
		if !strings.Contains(got, c) {
			t.Fatalf("got %q, lost %q", got, c)
		}
	}
}

func TestParseTree_WithCommentsKeepsThemForFormatTree(t *testing.T) {
	const sql = "-- header\nSELECT a FROM t -- trailing"
	plain, err := ParseTree(context.Background(), sql)
	if err != nil {
		t.Fatal(err)
	}
	if out := FormatTree(plain); strings.Contains(out, "--") {
		t.Fatalf("comments kept without WithComments: %q", out)
	}
	withC, err := ParseTree(context.Background(), sql, WithComments())
	if err != nil {
		t.Fatal(err)
	}
	out := FormatTree(withC)
	for _, c := range []string{"-- header", "-- trailing"} {
		if !strings.Contains(out, c) {
			t.Fatalf("FormatTree output %q lost %q", out, c)
		}
	}
}

func TestFormatWithDialect(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.IndentSize = 0
	opts.UppercaseKeywords = true

	got, err := FormatWithDialect("select /*+ MAX_EXECUTION_TIME(1000) */ a from t -- why", opts, "mysql")
	if err != nil {
		t.Fatalf("FormatWithDialect: %v", err)
	}
	if want := "SELECT /*+ MAX_EXECUTION_TIME(1000) */ a FROM t -- why"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// An empty dialect is Format.
	a, errA := FormatWithDialect("select 1 -- x", opts, "")
	b, errB := Format("select 1 -- x", opts)
	if errA != nil || errB != nil || a != b {
		t.Fatalf("empty dialect: %q (%v) vs Format %q (%v)", a, errA, b, errB)
	}

	if _, err := FormatWithDialect("select 1", opts, "nosuchsql"); !errors.Is(err, ErrUnsupportedDialect) {
		t.Fatalf("unknown dialect: err = %v, want ErrUnsupportedDialect", err)
	}
	if _, err := FormatWithDialect("selec 1", opts, "mysql"); !errors.Is(err, ErrSyntax) {
		t.Fatalf("invalid SQL: err = %v, want ErrSyntax", err)
	}
}

// TestFormat_NestedHintsFollowTheirSelect checks that a hint after a nested
// SELECT stays with that SELECT when the renderer writes the clauses holding
// the subqueries in a different order (Oracle START WITH before CONNECT BY),
// (see formatter.TestOccMatcher for the cases that are refused).
func TestFormat_NestedHintsFollowTheirSelect(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.IndentSize = 0
	tests := []struct {
		name string
		sql  string
		want []string // fragments of the output
	}{
		{
			name: "distinct subqueries swap places",
			sql:  "SELECT a FROM t CONNECT BY PRIOR id = pid AND x IN (SELECT /*+ H1 */ 1 FROM u) START WITH id IN (SELECT /*+ H2 */ 2 FROM v)",
			want: []string{"x IN (SELECT /*+ H1 */ 1 FROM u)", "id IN (SELECT /*+ H2 */ 2 FROM v)"},
		},
		{
			name: "one hinted subquery moves",
			sql:  "SELECT a FROM t CONNECT BY PRIOR id = pid AND x IN (SELECT /*+ H1 */ 1 FROM u) START WITH id IN (SELECT 1 FROM u)",
			want: []string{"x IN (SELECT /*+ H1 */ 1 FROM u)", "id IN (SELECT 1 FROM u)"},
		},
		{
			name: "clauses already in rendered order",
			sql:  "SELECT a FROM t START WITH id IN (SELECT /*+ H2 */ 2 FROM v) CONNECT BY PRIOR id = pid AND x IN (SELECT /*+ H1 */ 1 FROM u)",
			want: []string{"x IN (SELECT /*+ H1 */ 1 FROM u)", "id IN (SELECT /*+ H2 */ 2 FROM v)"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatWithDialect(tc.sql, opts, "oracle")
			if err != nil {
				t.Fatalf("FormatWithDialect: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("output lacks %q:\n%s", w, got)
				}
			}
		})
	}
}

// TestFormatWithDialect_CommentsFollowStatementStarts checks that comments
// stay with their statements when a procedure or trigger body holds ';' or
// T-SQL statements have no ';' between them, and that the result is stable.
func TestFormatWithDialect_CommentsFollowStatementStarts(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.IndentSize = 0
	opts.UppercaseKeywords = true
	tests := []struct {
		dialect string
		sql     string
		want    string
	}{
		{"sqlserver",
			"-- A\nSELECT 1\nSELECT 2;\n-- B: the proc\nCREATE PROC p AS BEGIN SELECT 1; END;\n",
			"-- A\nSELECT 1;\nSELECT 2;\n-- B: the proc\nCREATE PROC p AS BEGIN SELECT 1; END"},
		{"mysql",
			"-- Section one\nSELECT 1 FROM users;\n-- Section two: trigger\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\n-- Section three\nSELECT 3 FROM orders;\n",
			"-- Section one\nSELECT 1 FROM users;\n-- Section two: trigger\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\n-- Section three\nSELECT 3 FROM orders"},
	}
	for _, tc := range tests {
		t.Run(tc.dialect, func(t *testing.T) {
			got, err := FormatWithDialect(tc.sql, opts, keywords.SQLDialect(tc.dialect))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
			again, err := FormatWithDialect(got, opts, keywords.SQLDialect(tc.dialect))
			if err != nil || again != got {
				t.Fatalf("not idempotent: %v\n%q\n%q", err, got, again)
			}
		})
	}
}

// TestFormat_CommentsScaleLinearly guards against quadratic optimizer-hint
// placement and comment lookup (seconds and gigabytes before the fix). The
// bounds are generous so that -race and slow CI machines pass.
func TestFormat_CommentsScaleLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	tests := []struct {
		name string
		sql  string
	}{
		{"hints", strings.Repeat("SELECT /*+ H */ 1 UNION ALL ", 3000) + "SELECT /*+ H */ 1"},
		{"comments", strings.Repeat("SELECT 1; -- c\n", 40000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			out, err := Format(tc.sql, DefaultFormatOptions())
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(out, "/*+ H */") != strings.Count(tc.sql, "/*+ H */") ||
				strings.Count(out, "-- c") != strings.Count(tc.sql, "-- c") {
				t.Fatal("comments lost")
			}
			if limit := 3 * time.Second; elapsed > limit {
				t.Fatalf("took %v, want under %v", elapsed, limit)
			}
		})
	}
}
