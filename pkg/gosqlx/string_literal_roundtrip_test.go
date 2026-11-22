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

package gosqlx_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// roundTripDialects are the dialects whose string rules differ (see
// dialect.StringEscape); "" is the unconfigured default.
var roundTripDialects = []keywords.SQLDialect{
	"", keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
	keywords.DialectMariaDB, keywords.DialectSQLServer, keywords.DialectOracle,
	keywords.DialectSQLite, keywords.DialectSnowflake, keywords.DialectClickHouse,
}

func parseDialect(sql string, d keywords.SQLDialect) (*ast.AST, error) {
	if d == "" {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, d)
}

// selectedLiteral returns the literal of "SELECT <literal>".
func selectedLiteral(t *testing.T, tree *ast.AST) *ast.LiteralValue {
	t.Helper()
	if len(tree.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("got %T, want *ast.SelectStatement", tree.Statements[0])
	}
	if len(sel.Columns) != 1 {
		t.Fatalf("got %d columns, want 1", len(sel.Columns))
	}
	lit, ok := sel.Columns[0].(*ast.LiteralValue)
	if !ok {
		t.Fatalf("got %T, want *ast.LiteralValue", sel.Columns[0])
	}
	return lit
}

// TestStringBackslashFormatIsIdempotent is the property behind the formatter
// corruption bug: format(parse(format(x))) == format(x) for strings containing
// backslashes, in every dialect, and the literal's value survives the round
// trip. Doubling backslashes on every pass used to corrupt regexes and paths.
func TestStringBackslashFormatIsIdempotent(t *testing.T) {
	bodies := []string{
		`C:\dir\file`,
		`x\.y`,
		`\d+\s*`,
		`50\%`,
		`a\\b`,
		`tab\there`,
		`^[a-z]+\.[a-z]{2,}$`,
		`a\\\\b`,
		`mixed 'quote'' and \ backslash`,
		`plain`,
	}
	for _, d := range roundTripDialects {
		for _, body := range bodies {
			sql := "SELECT '" + strings.ReplaceAll(body, "'", "''") + "'"
			t.Run(fmt.Sprintf("%s/%s", d, body), func(t *testing.T) {
				tree, err := parseDialect(sql, d)
				if d == "" && strictRejects(body) {
					// Without a dialect an escape whose meaning depends on
					// the dialect is refused rather than guessed.
					if err == nil {
						t.Fatalf("parse %q without a dialect succeeded, want an escape error", sql)
					}
					return
				}
				if err != nil {
					t.Fatalf("parse %q: %v", sql, err)
				}
				first := selectedLiteral(t, tree).Value
				f1 := gosqlx.FormatAST(tree)

				tree2, err := parseDialect(f1, d)
				if err != nil {
					t.Fatalf("reparse %q: %v", f1, err)
				}
				if got := selectedLiteral(t, tree2).Value; got != first {
					t.Errorf("value changed by formatting: %q -> %q (formatted %q)", first, got, f1)
				}
				if f2 := gosqlx.FormatAST(tree2); f2 != f1 {
					t.Errorf("not idempotent:\n first  %q\n second %q", f1, f2)
				}
			})
		}
	}
}

// strictRejects reports whether body has a backslash escape the unconfigured
// tokenizer refuses (anything but \\ \' \" \` \n \r \t).
func strictRejects(body string) bool {
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			continue
		}
		if i+1 >= len(body) || !strings.ContainsRune(`\'"`+"`nrt", rune(body[i+1])) {
			return true
		}
		i++
	}
	return false
}

// TestStringBackslashRendering pins what the formatter writes for backslashes
// in the dialects where it is a plain character (written back untouched) and
// where it escapes (written as an escape).
func TestStringBackslashRendering(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{keywords.DialectPostgreSQL, `SELECT a ~ 'x\.y' FROM t`, `x\.y`},
		{keywords.DialectOracle, `SELECT 'a\b' FROM dual`, `'a\b'`},
		{keywords.DialectSQLite, `SELECT 'C:\dir'`, `'C:\dir'`},
		{keywords.DialectGeneric, `SELECT 'a\b'`, `'a\b'`},
		{keywords.DialectPostgreSQL, "SELECT 'line1\nline2'", "'line1\nline2'"},
		{keywords.DialectMySQL, `SELECT * FROM t WHERE a LIKE '50\%'`, `'50\\%'`},
		{keywords.DialectMySQL, `SELECT 'it\'s'`, `'it''s'`},
		{keywords.DialectClickHouse, `SELECT 'a\'b'`, `'a''b'`},
		{keywords.DialectClickHouse, `SELECT 'x\.y'`, `'x\\.y'`},
		{keywords.DialectSnowflake, `SELECT 'a\tb'`, "'a\tb'"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := parseDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatal(err)
			}
			if out := gosqlx.FormatAST(tree); !strings.Contains(out, tt.want) {
				t.Errorf("formatted %q does not contain %q", out, tt.want)
			}
		})
	}
}

func TestStringEscapeOnlyBackslashDialects(t *testing.T) {
	// A trailing backslash is a complete string in the dialects without
	// backslash escapes and an unterminated one in the others.
	for _, tt := range []struct {
		dialect keywords.SQLDialect
		ok      bool
	}{
		{keywords.DialectPostgreSQL, true},
		{keywords.DialectOracle, true},
		{keywords.DialectSQLite, true},
		{keywords.DialectSQLServer, true},
		{keywords.DialectGeneric, true},
		{keywords.DialectMySQL, false},
		{keywords.DialectClickHouse, false},
		{keywords.DialectSnowflake, false},
	} {
		_, err := parseDialect(`SELECT 'a\'`, tt.dialect)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want success %v", tt.dialect, err, tt.ok)
		}
	}
}

// TestPrefixedLiteralsRoundTrip covers the introducers that carry meaning of
// their own: they must survive formatting and reparse to the same value.
func TestPrefixedLiteralsRoundTrip(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		prefix  string
		value   string
		want    string // formatted literal
	}{
		{keywords.DialectMySQL, `SELECT X'4D'`, "X", "4D", `X'4D'`},
		{keywords.DialectMySQL, `SELECT x'4d'`, "X", "4d", `X'4d'`},
		{keywords.DialectMySQL, `SELECT b'101'`, "B", "101", `B'101'`},
		{keywords.DialectMariaDB, `SELECT X'4D'`, "X", "4D", `X'4D'`},
		{keywords.DialectSQLite, `SELECT x'CAFE'`, "X", "CAFE", `X'CAFE'`},
		{keywords.DialectPostgreSQL, `SELECT B'101'`, "B", "101", `B'101'`},
		{keywords.DialectSnowflake, `SELECT X'4D'`, "X", "4D", `X'4D'`},
		{keywords.DialectOracle, `SELECT N'x' FROM dual`, "N", "x", `N'x'`},
		{keywords.DialectMySQL, `SELECT N'it''s'`, "N", "it's", `N'it''s'`},
		{keywords.DialectSQLServer, `SELECT N'abc'`, "N", "abc", `N'abc'`},
		{keywords.DialectMySQL, `SELECT _utf8mb4'abc'`, "_utf8mb4", "abc", `_utf8mb4'abc'`},
		{keywords.DialectPostgreSQL, `SELECT E'tab\there'`, "E", "tab\there", `E'tab\there'`},
		{keywords.DialectPostgreSQL, `SELECT E'a\\b\'c'`, "E", `a\b'c`, `E'a\\b''c'`},
		{keywords.DialectOracle, `SELECT q'[It's quoted]' FROM dual`, "q", "It's quoted", `q'[It's quoted]'`},
		{keywords.DialectOracle, `SELECT q'!a]'b!' FROM dual`, "q", "a]'b", `q'{a]'b}'`},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := parseDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatal(err)
			}
			lit := selectedLiteral(t, tree)
			if lit.DialectExtras().Prefix != tt.prefix || lit.Value != tt.value {
				t.Fatalf("got prefix %q value %q, want %q %q", lit.DialectExtras().Prefix, lit.Value, tt.prefix, tt.value)
			}
			f1 := gosqlx.FormatAST(tree)
			if !strings.Contains(f1, tt.want) {
				t.Errorf("formatted %q does not contain %q", f1, tt.want)
			}
			tree2, err := parseDialect(f1, tt.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", f1, err)
			}
			lit2 := selectedLiteral(t, tree2)
			if !strings.EqualFold(lit2.DialectExtras().Prefix, lit.DialectExtras().Prefix) || lit2.Value != lit.Value {
				t.Errorf("reparse: prefix %q value %q, want %q %q", lit2.DialectExtras().Prefix, lit2.Value, lit.DialectExtras().Prefix, lit.Value)
			}
			if f2 := gosqlx.FormatAST(tree2); f2 != f1 {
				t.Errorf("not idempotent: %q then %q", f1, f2)
			}
		})
	}
}

func TestPrefixedLiteralInExpressions(t *testing.T) {
	// The introducer works anywhere an expression does.
	for _, sql := range []string{
		`SELECT * FROM t WHERE a = X'4D' AND b = N'x'`,
		`INSERT INTO t (a, b) VALUES (X'4D', _utf8mb4'abc')`,
		`SELECT * FROM t WHERE a IN (X'01', X'02')`,
		`SELECT CASE WHEN a = b'1' THEN N'y' END FROM t`,
	} {
		tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMySQL)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		out := gosqlx.FormatAST(tree)
		for _, intro := range []string{"X'", "N'", "_utf8mb4'", "B'"} {
			if strings.Contains(sql, intro) && !strings.Contains(out, intro) {
				t.Errorf("%q: formatted %q lost the introducer %q", sql, out, intro)
			}
		}
		tree2, err := gosqlx.ParseWithDialect(out, keywords.DialectMySQL)
		if err != nil {
			t.Errorf("%q: reparse of %q: %v", sql, out, err)
			continue
		}
		if out2 := gosqlx.FormatAST(tree2); out2 != out {
			t.Errorf("%q: not idempotent: %q then %q", sql, out, out2)
		}
	}
}

func TestLexicalLiteralsFormat(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{keywords.DialectMySQL, `SELECT 0x1F`, "0x1F"},
		{keywords.DialectMySQL, `SELECT 0XAB, 1`, "0XAB"},
		{keywords.DialectClickHouse, `SELECT 0x1F`, "0x1F"},
		{keywords.DialectMySQL, `SELECT .5`, ".5"},
		{keywords.DialectPostgreSQL, `SELECT .5 + 1`, ".5 + 1"},
		{keywords.DialectOracle, `SELECT 5. FROM dual`, "5."},
		{keywords.DialectSQLite, `SELECT 5.`, "5."},
		{keywords.DialectOracle, `SELECT * FROM v$session`, "v$session"},
		{keywords.DialectOracle, `SELECT x FROM sys.gv$sql`, "sys.gv$sql"},
		{keywords.DialectSnowflake, `SELECT SYSTEM$TYPEOF(1)`, "SYSTEM$TYPEOF(1)"},
		{keywords.DialectSnowflake, `SELECT METADATA$FILENAME FROM t`, "METADATA$FILENAME"},
		{keywords.DialectPostgreSQL, `SELECT a$b FROM t`, "a$b"},
		{keywords.DialectSQLite, `SELECT a FROM t WHERE a = :name`, ":name"},
		{keywords.DialectSQLite, `SELECT ?1, ?2`, "?1, ?2"},
		{keywords.DialectSQLite, `SELECT [col] FROM [my table]`, `[my table]`},
		{keywords.DialectClickHouse, `SELECT a FROM t WHERE x = {p:UInt64}`, "{p:UInt64}"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := parseDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatal(err)
			}
			f1 := gosqlx.FormatAST(tree)
			if !strings.Contains(f1, tt.want) {
				t.Errorf("formatted %q does not contain %q", f1, tt.want)
			}
			tree2, err := parseDialect(f1, tt.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", f1, err)
			}
			if f2 := gosqlx.FormatAST(tree2); f2 != f1 {
				t.Errorf("not idempotent: %q then %q", f1, f2)
			}
		})
	}
}

func TestLeadingBOMParses(t *testing.T) {
	for _, d := range []keywords.SQLDialect{"", keywords.DialectGeneric, keywords.DialectMySQL, keywords.DialectSQLServer} {
		if _, err := parseDialect("\xEF\xBB\xBFSELECT 1", d); err != nil {
			t.Errorf("%q: %v", d, err)
		}
	}
}
