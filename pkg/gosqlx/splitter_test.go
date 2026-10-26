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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// nonEmpty returns the number of segments that are not whitespace-only.
// ParseReaderMultiple trims and skips these before parsing, so the splitter
// is free to emit them (and the simple cases in this file assert the trimmed
// count to mirror end-user behaviour).
func nonEmpty(segs []string) int {
	n := 0
	for _, s := range segs {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

func TestSplitStatements_Table(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		dialect string
		want    int
	}{
		// ─── ANSI baseline ───────────────────────────────────────────────
		{"ansi/simple-two", "SELECT 1; SELECT 2", "", 2},
		{"ansi/single-quote-escape", "SELECT 'a;b'; SELECT 1", "", 2},
		{"ansi/escaped-single-quote", "SELECT 'it''s;fine'; SELECT 1", "", 2},
		{"ansi/line-comment", "-- comment ; still comment\nSELECT 1", "", 1},
		{"ansi/block-comment", "/* ; in comment */ SELECT 1; SELECT 2", "", 2},
		{"ansi/double-quoted-ident", `SELECT "col;name" FROM t; SELECT 1`, "", 2},
		{"ansi/trailing-semi", "SELECT 1;", "", 1},
		{"ansi/empty-between", "SELECT 1;;;SELECT 2", "", 2},

		// ─── PostgreSQL nested block comments ───────────────────────────
		{"pg/nested-block-comment",
			"/* /* nested ; */ */ SELECT 1; SELECT 2", "postgresql", 2},
		// Same input under ANSI closes at the first */ and the trailing
		// "*/ SELECT 1" becomes part of the first segment — so we still see
		// two statements, but through a different code path. Check both
		// worlds remain deterministic.
		{"ansi/nested-flat", "/* /* x */ */ SELECT 1; SELECT 2", "", 2},

		// ─── PostgreSQL dollar-quoting ──────────────────────────────────
		{"pg/dollar-bare",
			"CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END; $$ LANGUAGE plpgsql; SELECT 1",
			"postgresql", 2},
		{"pg/dollar-tag",
			"SELECT $outer$ foo $inner$ bar $inner$ baz $outer$; SELECT 1",
			"postgresql", 2},
		{"pg/dollar-containing-semi-and-quotes",
			"DO $body$ BEGIN PERFORM 'a;b'; END $body$; SELECT 1",
			"postgresql", 2},
		// Same dollar-quote input with no dialect should split naively and
		// produce MORE segments — confirming the feature is gated.
		// Input has three top-level semicolons under ANSI rules (after
		// `SELECT 1`, `SELECT 2`, and `sql`), yielding 4 segments. (The body
		// deliberately avoids BEGIN … END, which the splitter now keeps whole.)
		{"ansi/dollar-not-recognised",
			"CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; SELECT 2; $$ LANGUAGE sql; SELECT 1",
			"", 4},

		// ─── PostgreSQL E-strings ───────────────────────────────────────
		{"pg/e-string-escaped-quote",
			`SELECT E'\''; SELECT 1`, "postgresql", 2},
		{"pg/e-string-escaped-semicolon",
			`SELECT E'a\;b'; SELECT 1`, "postgresql", 2},

		// ─── MySQL / MariaDB / ClickHouse backticks ─────────────────────
		{"mysql/backtick-ident",
			"SELECT `col;name` FROM t; SELECT 1", "mysql", 2},
		{"mariadb/backtick-ident",
			"SELECT `col;name` FROM t; SELECT 1", "mariadb", 2},
		{"clickhouse/backtick-ident",
			"SELECT `col;name` FROM t; SELECT 1", "clickhouse", 2},
		// Under ANSI, backticks are plain characters; the `;` inside splits.
		{"ansi/backtick-not-recognised",
			"SELECT `col;name` FROM t; SELECT 1", "", 3},

		// ─── SQL Server bracketed identifiers ───────────────────────────
		{"sqlserver/bracketed-ident",
			"SELECT [col;name] FROM t; SELECT 1", "sqlserver", 2},
		{"mssql/bracketed-ident",
			"SELECT [col;name] FROM t; SELECT 1", "mssql", 2},
		// Under ANSI, [] is not special; the `;` inside splits.
		{"ansi/brackets-not-recognised",
			"SELECT [col;name] FROM t; SELECT 1", "", 3},

		// ─── Dialect aliases ────────────────────────────────────────────
		{"pg/alias-postgres", "SELECT $$a;b$$; SELECT 1", "postgres", 2},
		{"pg/alias-pg", "SELECT $$a;b$$; SELECT 1", "pg", 2},
		{"pg/case-insensitive", "SELECT $$a;b$$; SELECT 1", "PostgreSQL", 2},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := nonEmpty(SplitStatements(tc.sql, tc.dialect))
			if got != tc.want {
				t.Errorf("SplitStatements(%q, %q) non-empty = %d, want %d",
					tc.sql, tc.dialect, got, tc.want)
			}
		})
	}
}

func TestSplitStatements_PreservesContent(t *testing.T) {
	// The splitter must not mangle statement bodies. Re-joining the
	// non-empty segments with "; " should reproduce the substantive SQL.
	sql := "SELECT 1; SELECT 2; SELECT 3"
	segs := SplitStatements(sql, "")
	var parts []string
	for _, s := range segs {
		if t := strings.TrimSpace(s); t != "" {
			parts = append(parts, t)
		}
	}
	joined := strings.Join(parts, "; ")
	if joined != sql {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", joined, sql)
	}
}

func TestSplitStatements_DollarTagMustMatch(t *testing.T) {
	// `$outer$...$inner$` must stay open until the matching $outer$, even
	// though `$inner$` looks like a closer. Semi inside must not split.
	sql := "SELECT $outer$ x; $inner$ y; $outer$; SELECT 1"
	got := nonEmpty(SplitStatements(sql, "postgresql"))
	if got != 2 {
		t.Errorf("got %d, want 2 — inner tag should not close outer", got)
	}
}

func TestSplitStatements_DollarNotATag(t *testing.T) {
	// `$1`, `$2`, ... are PG positional params, NOT dollar-quote openers.
	// The splitter must treat them as plain text so normal string/comment
	// rules still apply to the rest of the statement.
	sql := "SELECT $1; SELECT $2"
	got := nonEmpty(SplitStatements(sql, "postgresql"))
	if got != 2 {
		t.Errorf("got %d, want 2 — $1/$2 are params, not dollar-quotes", got)
	}
}

func TestSplitStatements_NestedBlockCommentDepth(t *testing.T) {
	// Two levels of nesting, semicolons at each level.
	sql := "/* a; /* b; /* c; */ */ */ SELECT 1; SELECT 2"
	got := nonEmpty(SplitStatements(sql, "postgresql"))
	if got != 2 {
		t.Errorf("got %d, want 2 — block comment depth tracking", got)
	}
}

func TestSplitStatements_EStringGatedByDialect(t *testing.T) {
	// Under ANSI, `E'` is not an E-string — the `E` is a plain identifier
	// byte and the `'` opens a normal string. The backslash escape then
	// does NOT apply, so `\';` DOES split.
	ansi := nonEmpty(SplitStatements(`SELECT E'\''; SELECT 1`, ""))
	pg := nonEmpty(SplitStatements(`SELECT E'\''; SELECT 1`, "postgresql"))
	if ansi == pg {
		t.Errorf("expected E-string handling to differ by dialect: ansi=%d pg=%d", ansi, pg)
	}
}

func TestSplitStatements_EmptyInput(t *testing.T) {
	segs := SplitStatements("", "")
	if len(segs) != 0 {
		t.Errorf("empty input produced %d segments", len(segs))
	}
}

func TestSplitStatements_OnlyWhitespace(t *testing.T) {
	segs := SplitStatements("   \n\t  ", "")
	if nonEmpty(segs) != 0 {
		t.Errorf("whitespace-only input produced %d non-empty segments", nonEmpty(segs))
	}
}

// splitterDialects lists every dialect string the splitter resolves to a
// distinct profile, plus aliases and an unknown value that falls back to ANSI.
var splitterDialects = []string{
	"", "postgresql", "postgres", "pg", "mysql", "mariadb",
	"clickhouse", "sqlserver", "mssql", "tsql", "oracle", "unknown",
}

// checkTilingFor asserts that segments exactly tile the source between
// top-level semicolons, allowing a consumed trailing semicolon. Dialects with
// client directives (GO, DELIMITER, a lone "/") consume those lines, so their
// segments must instead be ordered substrings of src.
func checkTilingFor(src string, segs []string, dialect string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(dialect)) {
	case "sqlserver", "mssql", "tsql", "mysql", "mariadb", "oracle":
		pos := 0
		for _, seg := range segs {
			at := strings.Index(src[pos:], seg)
			if at < 0 {
				return "segment is not an in-order substring of the source", false
			}
			pos += at + len(seg)
		}
		return "", true
	}
	joined := strings.Join(segs, ";")
	if joined != src && !(strings.HasSuffix(src, ";") && joined == src[:len(src)-1]) {
		return "segments do not tile the source", false
	}
	if len(segs) > strings.Count(src, ";")+1 {
		return "more segments than semicolons+1", false
	}
	return "", true
}

func TestSplitStatements_ExactSegments(t *testing.T) {
	cases := []struct {
		name    string
		sql     string
		dialect string
		want    []string
	}{
		{"empty", "", "", nil},
		{"lone semicolon", ";", "", []string{""}},
		{"three semicolons", ";;;", "", []string{"", "", ""}},
		{"trailing semicolon", "SELECT 1;", "", []string{"SELECT 1"}},
		{"trailing whitespace segment", "SELECT 1;  \n", "", []string{"SELECT 1", "  \n"}},
		{"no trailing semicolon", "SELECT 1; SELECT 2", "", []string{"SELECT 1", " SELECT 2"}},
		{"no semicolon at all", "SELECT 1", "", []string{"SELECT 1"}},
		{"quoted semicolon", "SELECT 'a;b'; SELECT 1", "", []string{"SELECT 'a;b'", " SELECT 1"}},
		{"doubled quote escape", "SELECT 'it''s;x'; SELECT 1", "", []string{"SELECT 'it''s;x'", " SELECT 1"}},
		{"double-quoted semicolon", `SELECT "a;b"; SELECT 1`, "", []string{`SELECT "a;b"`, " SELECT 1"}},
		{"line comment", "-- c ; c\nSELECT 1", "", []string{"-- c ; c\nSELECT 1"}},
		{"block comment", "/* ; */ SELECT 1; SELECT 2", "", []string{"/* ; */ SELECT 1", " SELECT 2"}},
		{"ansi block comment not nested", "/* /* a; */ b; */ SELECT 1", "", []string{"/* /* a; */ b", " */ SELECT 1"}},
		{"pg nested block comment", "/* /* a; */ ; */ SELECT 1; SELECT 2", "postgresql", []string{"/* /* a; */ ; */ SELECT 1", " SELECT 2"}},
		{"pg dollar body", "DO $body$ BEGIN PERFORM 'a;b'; END $body$; SELECT 1", "postgresql",
			[]string{"DO $body$ BEGIN PERFORM 'a;b'; END $body$", " SELECT 1"}},
		{"pg anonymous dollar body", "SELECT $$a;b$$; SELECT 2", "pg", []string{"SELECT $$a;b$$", " SELECT 2"}},
		{"pg E-string escape", `SELECT E'\''; SELECT 1`, "postgresql", []string{`SELECT E'\''`, " SELECT 1"}},
		{"pg E-string escaped quote then semicolon", `SELECT E'\'a;b'; SELECT 1`, "postgresql", []string{`SELECT E'\'a;b'`, " SELECT 1"}},
		{"mysql backtick", "SELECT `c;n` FROM t; SELECT 1", "mysql", []string{"SELECT `c;n` FROM t", " SELECT 1"}},
		{"sqlserver bracket", "SELECT [c;n] FROM t; SELECT 1", "sqlserver", []string{"SELECT [c;n] FROM t", " SELECT 1"}},
		{"unterminated string", "SELECT 'open ; SELECT 2", "", []string{"SELECT 'open ; SELECT 2"}},
		{"unterminated block comment", "/* open ; SELECT 2", "", []string{"/* open ; SELECT 2"}},
		{"unterminated dollar", "SELECT $$open ; SELECT 2", "postgresql", []string{"SELECT $$open ; SELECT 2"}},
		{"unterminated backtick", "SELECT `open ; x", "mysql", []string{"SELECT `open ; x"}},
		{"unterminated bracket", "SELECT [open ; x", "mssql", []string{"SELECT [open ; x"}},
		{"bare dollar", "SELECT $", "postgresql", []string{"SELECT $"}},
		{"bare E quote", "E'", "postgresql", []string{"E'"}},
		{"bare quote", "'", "", []string{"'"}},
		{"bare line comment opener", "--", "", []string{"--"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitStatements(tc.sql, tc.dialect)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SplitStatements(%q, %q) = %q, want %q", tc.sql, tc.dialect, got, tc.want)
			}
		})
	}
}

func TestSplitStatements_NilOnEmpty(t *testing.T) {
	for _, d := range splitterDialects {
		if got := SplitStatements("", d); got != nil {
			t.Errorf("SplitStatements(\"\", %q) = %#v, want nil", d, got)
		}
	}
}

func TestSplitStatements_TilesSource(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		src := string(data)
		for _, dialect := range splitterDialects {
			segs := SplitStatements(src, dialect)
			if msg, ok := checkTilingFor(src, segs, dialect); !ok {
				t.Errorf("%s (dialect %q): %s", path, dialect, msg)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if files == 0 {
		t.Fatalf("no files found under %s", root)
	}
}
