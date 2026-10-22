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

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// escapeCase is one string literal read under one dialect: want is the
// decoded value, or wantErr reports that the literal must be rejected.
type escapeCase struct {
	name    string
	dialect keywords.SQLDialect // "" = unconfigured
	sql     string
	want    string
	wantErr bool
}

// tokenizerFor returns a fresh tokenizer configured for d.
func tokenizerFor(d keywords.SQLDialect) *Tokenizer {
	tkz, _ := NewWithDialect(d)
	return tkz
}

// runEscapeCases checks each case. An unconfigured case runs on every way of
// getting an unconfigured tokenizer: pooled, New and SetDialect("").
func runEscapeCases(t *testing.T, cases []escapeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tkzs []*Tokenizer
			if tc.dialect == "" {
				pooled := GetTokenizer()
				defer PutTokenizer(pooled)
				fresh, _ := New()
				reset, _ := NewWithDialect(keywords.DialectMySQL)
				reset.SetDialect("")
				tkzs = []*Tokenizer{pooled, fresh, reset}
			} else {
				tkzs = []*Tokenizer{tokenizerFor(tc.dialect)}
			}
			for i, tkz := range tkzs {
				tok, err := firstString(t, tkz, tc.sql)
				if tc.wantErr {
					if err == nil {
						t.Fatalf("tokenizer %d: %q decoded to %q, want an error", i, tc.sql, tok.Value)
					}
					continue
				}
				if err != nil {
					t.Fatalf("tokenizer %d: %q: %v", i, tc.sql, err)
				}
				if tok.Value != tc.want {
					t.Errorf("tokenizer %d: %q value = %q, want %q", i, tc.sql, tok.Value, tc.want)
				}
			}
		})
	}
}

// TestStringEscapeStrictUnconfigured pins the unconfigured tokenizer: the
// escapes every backslash-escaping dialect agrees on are decoded, and any
// other sequence is an error, because its meaning depends on the dialect
// ('C:\dir' is five characters in PostgreSQL and four in MySQL). Formatting
// such a literal without a dialect used to rewrite it silently.
func TestStringEscapeStrictUnconfigured(t *testing.T) {
	runEscapeCases(t, []escapeCase{
		{name: "newline", sql: `SELECT 'a\nb'`, want: "a\nb"},
		{name: "carriage return", sql: `SELECT 'a\rb'`, want: "a\rb"},
		{name: "tab", sql: `SELECT 'a\tb'`, want: "a\tb"},
		{name: "backslash", sql: `SELECT 'a\\b'`, want: `a\b`},
		{name: "quote", sql: `SELECT 'it\'s'`, want: "it's"},
		{name: "double quote", sql: `SELECT 'a\"b'`, want: `a"b`},
		{name: "backtick", sql: "SELECT 'a\\`b'", want: "a`b"},
		{name: "no backslash", sql: `SELECT 'plain'`, want: "plain"},

		{name: "windows path", sql: `SELECT 'C:\dir'`, wantErr: true},
		{name: "regex dot", sql: `SELECT 'x\.y'`, wantErr: true},
		{name: "regex digit", sql: `SELECT '\d+'`, wantErr: true},
		{name: "like percent", sql: `SELECT '50\%'`, wantErr: true},
		{name: "like underscore", sql: `SELECT '\_x'`, wantErr: true},
		{name: "NUL escape", sql: `SELECT 'a\0b'`, wantErr: true},
		{name: "ctrl-z escape", sql: `SELECT 'a\Zb'`, wantErr: true},
		{name: "backspace escape", sql: `SELECT 'a\bb'`, wantErr: true},
		{name: "raw NUL byte", sql: "SELECT 'a\x00b'", wantErr: true},
		{name: "raw ctrl-z byte", sql: "SELECT 'a\x1ab'", wantErr: true},
	})
}

// TestStringEscapeDropUnknown pins Snowflake and Redshift, where a backslash
// before a character that is not a recognised escape is ignored ('x\.y' is
// x.y; Snowflake documents "the backslash is ignored"). Octal, hex and
// Unicode escapes must be complete; the forms the two dialects read
// differently, and values the formatter cannot write back (NUL, Ctrl-Z,
// non-ASCII bytes), are rejected.
func TestStringEscapeDropUnknown(t *testing.T) {
	var cases []escapeCase
	for _, d := range []keywords.SQLDialect{keywords.DialectSnowflake, keywords.DialectRedshift} {
		for _, c := range []escapeCase{
			{name: "regex dot", sql: `SELECT 'x\.y'`, want: "x.y"},
			{name: "regex digit", sql: `SELECT '\d+'`, want: "d+"},
			{name: "like percent", sql: `SELECT '50\%'`, want: "50%"},
			{name: "like underscore", sql: `SELECT '\_x'`, want: "_x"},
			{name: "escaped backslash", sql: `SELECT 'a\\b'`, want: `a\b`},
			{name: "escaped quote", sql: `SELECT 'it\'s'`, want: "it's"},
			{name: "ctrl-z letter is Z", sql: `SELECT 'a\Zb'`, want: "aZb"},
			{name: "backspace", sql: `SELECT 'a\bb'`, want: "a\bb"},
			{name: "form feed", sql: `SELECT 'a\fb'`, want: "a\fb"},
			{name: "newline", sql: `SELECT 'a\nb'`, want: "a\nb"},
			{name: "octal", sql: `SELECT '\101\102'`, want: "AB"},
			{name: "hex", sql: `SELECT '\x41z'`, want: "Az"},
			{name: "unicode", sql: `SELECT '\u00e9'`, want: "é"},

			{name: "NUL", sql: `SELECT 'a\0b'`, wantErr: true},
			{name: "octal NUL", sql: `SELECT '\000'`, wantErr: true},
			{name: "hex NUL", sql: `SELECT '\x00'`, wantErr: true},
			{name: "unicode NUL", sql: `SELECT '\u0000'`, wantErr: true},
			{name: "octal ctrl-z", sql: `SELECT '\032'`, wantErr: true},
			{name: "short octal", sql: `SELECT '\12'`, wantErr: true},
			{name: "octal above ASCII", sql: `SELECT '\200'`, wantErr: true},
			{name: "short hex", sql: `SELECT '\x4'`, wantErr: true},
			{name: "hex above ASCII", sql: `SELECT '\xe9'`, wantErr: true},
			{name: "short unicode", sql: `SELECT '\u12'`, wantErr: true},
			{name: "long unicode", sql: `SELECT '\U0001F600'`, wantErr: true},
			{name: "raw NUL byte", sql: "SELECT 'a\x00b'", wantErr: true},
			{name: "raw ctrl-z byte", sql: "SELECT 'a\x1ab'", wantErr: true},
		} {
			c.name = string(d) + "/" + c.name
			c.dialect = d
			cases = append(cases, c)
		}
	}
	runEscapeCases(t, cases)
}

// TestStringEscapeLenientClickHouse pins ClickHouse: its C escapes are
// decoded, and any other sequence keeps its backslash (ClickHouse does this
// so LIKE patterns and regular expressions survive). \Z is not a ClickHouse
// escape, so it keeps its backslash instead of becoming Ctrl-Z.
func TestStringEscapeLenientClickHouse(t *testing.T) {
	ch := keywords.DialectClickHouse
	runEscapeCases(t, []escapeCase{
		{name: "regex dot", dialect: ch, sql: `SELECT 'x\.y'`, want: `x\.y`},
		{name: "ctrl-z letter kept", dialect: ch, sql: `SELECT 'a\Zb'`, want: `a\Zb`},
		{name: "like percent kept", dialect: ch, sql: `SELECT '50\%'`, want: `50\%`},
		{name: "bell", dialect: ch, sql: `SELECT 'a\ab'`, want: "a\ab"},
		{name: "vertical tab", dialect: ch, sql: `SELECT 'a\vb'`, want: "a\vb"},
		{name: "form feed", dialect: ch, sql: `SELECT 'a\fb'`, want: "a\fb"},
		{name: "NUL", dialect: ch, sql: `SELECT 'a\0b'`, want: "a\x00b"},
		{name: "hex", dialect: ch, sql: `SELECT '\x41'`, want: "A"},
		{name: "not hex keeps backslash", dialect: ch, sql: `SELECT '\xzz'`, want: `\xzz`},
		{name: "raw NUL byte", dialect: ch, sql: "SELECT 'a\x00b'", want: "a\x00b"},

		{name: "hex ctrl-z", dialect: ch, sql: `SELECT '\x1a'`, wantErr: true},
		{name: "hex above ASCII", dialect: ch, sql: `SELECT '\xff'`, wantErr: true},
		{name: "raw ctrl-z byte", dialect: ch, sql: "SELECT 'a\x1ab'", wantErr: true},
	})
}

// TestStringRawControlBytes checks which dialects accept a NUL or Ctrl-Z
// byte written directly inside a string literal. Where the formatter could
// not write the byte back (no backslash escapes means no spelling for NUL),
// the literal is rejected instead of being formatted with the byte dropped.
func TestStringRawControlBytes(t *testing.T) {
	runEscapeCases(t, []escapeCase{
		{name: "postgresql NUL", dialect: keywords.DialectPostgreSQL, sql: "SELECT 'a\x00b'", wantErr: true},
		{name: "oracle NUL", dialect: keywords.DialectOracle, sql: "SELECT 'a\x00b'", wantErr: true},
		{name: "sqlserver national NUL", dialect: keywords.DialectSQLServer, sql: "SELECT N'a\x00b'", wantErr: true},
		{name: "generic NUL", dialect: keywords.DialectGeneric, sql: "SELECT 'a\x00b'", wantErr: true},
		{name: "postgresql ctrl-z", dialect: keywords.DialectPostgreSQL, sql: "SELECT 'a\x1ab'", want: "a\x1ab"},
		{name: "mysql NUL", dialect: keywords.DialectMySQL, sql: "SELECT 'a\x00b'", want: "a\x00b"},
		{name: "mysql ctrl-z", dialect: keywords.DialectMySQL, sql: "SELECT 'a\x1ab'", want: "a\x1ab"},
	})

	// A NUL in a double-quoted identifier is not a string literal and is
	// left to the identifier rules.
	tkz := tokenizerFor(keywords.DialectPostgreSQL)
	if _, err := tkz.TokenizeString("SELECT \"a\x00b\""); err != nil {
		t.Errorf("NUL in a quoted identifier: %v", err)
	}
}

// TestTripleQuotedOnlyBigQuery checks that ”' opens a triple-quoted string
// only in BigQuery. Elsewhere it is a string whose text starts with a quote,
// so ”'a' (the value 'a) tokenizes and ”'abc”' means 'abc', not abc.
func TestTripleQuotedOnlyBigQuery(t *testing.T) {
	type tc struct {
		dialect keywords.SQLDialect
		sql     string
		typ     models.TokenType
		want    string
	}
	str := models.TokenTypeSingleQuotedString
	tests := []tc{
		{keywords.DialectBigQuery, `SELECT '''abc'''`, models.TokenTypeTripleSingleQuotedString, "abc"},
		{keywords.DialectBigQuery, `SELECT '''a'b'''`, models.TokenTypeTripleSingleQuotedString, "a'b"},
	}
	for _, d := range []keywords.SQLDialect{"", keywords.DialectPostgreSQL, keywords.DialectMySQL,
		keywords.DialectClickHouse, keywords.DialectSnowflake, keywords.DialectSQLServer, keywords.DialectOracle} {
		tests = append(tests,
			tc{d, `SELECT '''a'`, str, "'a"},
			tc{d, `SELECT '''abc'''`, str, "'abc'"},
			tc{d, `SELECT ''''''`, str, "''"},
			tc{d, `SELECT 'a'''`, str, "a'"},
		)
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			var tkz *Tokenizer
			if tt.dialect == "" {
				tkz, _ = New()
			} else {
				tkz = tokenizerFor(tt.dialect)
			}
			tokens, err := tkz.TokenizeString(tt.sql)
			if err != nil {
				t.Fatalf("%q: %v", tt.sql, err)
			}
			if len(tokens) < 2 {
				t.Fatalf("%q: got %d tokens", tt.sql, len(tokens))
			}
			got := tokens[1].Token
			if got.Type != tt.typ || got.Value != tt.want {
				t.Errorf("%q: got %v %q, want %v %q", tt.sql, got.Type, got.Value, tt.typ, tt.want)
			}
		})
	}
}
