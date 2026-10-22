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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatWithoutDialectRefusesAmbiguousEscapes checks that the library
// entry points without a dialect refuse a literal whose backslash meaning
// depends on the dialect, instead of rewriting it ('C:\dir' used to come back
// as 'C:\\dir', a different value in PostgreSQL).
func TestFormatWithoutDialectRefusesAmbiguousEscapes(t *testing.T) {
	for _, sql := range []string{
		`SELECT 'C:\dir' FROM t`,
		`SELECT 'x\.y' FROM t`,
		`SELECT * FROM t WHERE a LIKE '50\%'`,
		`SELECT 'a\0b'`,
	} {
		if _, err := gosqlx.Parse(sql); err == nil {
			t.Errorf("Parse(%q) succeeded, want an escape error", sql)
		}
		if out, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions()); err == nil {
			t.Errorf("Format(%q) = %q, want an error", sql, out)
		}
	}
	// The escapes all backslash dialects agree on still format.
	out, err := gosqlx.Format(`SELECT 'a\nb', 'c\\d', 'it\'s'`, gosqlx.DefaultFormatOptions())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if want := `SELECT 'a\nb', 'c\\d', 'it''s'`; out != want {
		t.Errorf("Format = %q, want %q", out, want)
	}
}

// TestFormatStringLiteralFollowups pins the formatter output, its value
// round trip and idempotence for the literal fixes: NUL written as \0 instead
// of dropped, Snowflake dropping the backslash of an unknown escape, strings
// that start with a doubled quote, and '$' names that were delimited.
func TestFormatStringLiteralFollowups(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{keywords.DialectMySQL, `SELECT 'a\0b'`, `SELECT 'a\0b'`},
		{keywords.DialectMariaDB, `SELECT 'a\0' 'b'`, `SELECT 'a\0b'`},
		{keywords.DialectClickHouse, `SELECT 'a\0b'`, `SELECT 'a\0b'`},
		{keywords.DialectClickHouse, `SELECT 'a\Zb'`, `SELECT 'a\\Zb'`},
		{keywords.DialectSnowflake, `SELECT 'x\.y'`, `SELECT 'x.y'`},
		{keywords.DialectSnowflake, `SELECT '\\d+\x41'`, `SELECT '\\d+A'`},
		{keywords.DialectPostgreSQL, `SELECT '''a'`, `SELECT '''a'`},
		{keywords.DialectPostgreSQL, `SELECT '''a'''`, `SELECT '''a'''`},
		{keywords.DialectMySQL, `SELECT '''a'`, `SELECT '''a'`},
		{keywords.DialectGeneric, `SELECT "a$b" FROM t`, "SELECT \"a$b\"\nFROM t"},
		{keywords.DialectBigQuery, "SELECT `a$b` FROM t", "SELECT `a$b`\nFROM t"},
		{keywords.DialectOracle, `SELECT v$x FROM t`, "SELECT v$x\nFROM t"},
		{keywords.DialectMySQL, `SELECT 0x1E`, `SELECT 0x1E`},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			out := gosqlx.FormatAST(tree)
			if out != tt.want {
				t.Errorf("FormatAST = %q, want %q", out, tt.want)
			}
			tree2, err := gosqlx.ParseWithDialect(out, tt.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", out, err)
			}
			if again := gosqlx.FormatAST(tree2); again != out {
				t.Errorf("not idempotent: %q then %q", out, again)
			}
		})
	}
}
