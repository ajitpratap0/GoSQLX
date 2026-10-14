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

var strictQuoteDialects = []keywords.SQLDialect{
	"", keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB,
	keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite,
	keywords.DialectSnowflake, keywords.DialectClickHouse,
}

// TestASCIIQuotedTokenIgnoresUnicodeQuotes pins #632: a token opened with an
// ASCII quote is closed only by that ASCII quote, so a Unicode quote inside a
// rendered identifier or string literal cannot end it early and smuggle a
// second statement in.
func TestASCIIQuotedTokenIgnoresUnicodeQuotes(t *testing.T) {
	cases := []struct {
		sql   string
		typ   models.TokenType
		value string
	}{
		{"SELECT 1 AS \"x”; DROP TABLE pwn; --“\"", models.TokenTypeDoubleQuotedString, "x”; DROP TABLE pwn; --“"},
		{"SELECT 1 AS \"x“; DROP TABLE pwn; --\"", models.TokenTypeDoubleQuotedString, "x“; DROP TABLE pwn; --"},
		{"SELECT 1 AS \"x’; DROP TABLE pwn; --\"", models.TokenTypeDoubleQuotedString, "x’; DROP TABLE pwn; --"},
		{"PRAGMA journal_mode = 'x’; DROP TABLE pwn; --'", models.TokenTypeSingleQuotedString, "x’; DROP TABLE pwn; --"},
		{"SELECT 'a‘; DROP TABLE pwn; --'", models.TokenTypeSingleQuotedString, "a‘; DROP TABLE pwn; --"},
		{"SELECT 'a»; DROP TABLE pwn; --«'", models.TokenTypeSingleQuotedString, "a»; DROP TABLE pwn; --«"},
		{"SELECT 'a”; DROP TABLE pwn; --'", models.TokenTypeSingleQuotedString, "a”; DROP TABLE pwn; --"},
	}
	for _, d := range strictQuoteDialects {
		for _, tc := range cases {
			tkz := newDialectTokenizer(t, d)
			toks, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Errorf("[%s] %q: %v", d, tc.sql, err)
				continue
			}
			var semis int
			var got *models.Token
			for i := range toks {
				tok := &toks[i].Token
				if tok.Type == models.TokenTypeSemicolon {
					semis++
				}
				if tok.Type == tc.typ && got == nil {
					got = tok
				}
			}
			if semis != 0 {
				t.Errorf("[%s] %q: got %d semicolon tokens, want 0", d, tc.sql, semis)
			}
			if got == nil || got.Value != tc.value {
				t.Errorf("[%s] %q: quoted token %+v, want value %q", d, tc.sql, got, tc.value)
			}
		}
	}
}

// TestUnicodeOpenedTokenKeepsNormalizing pins the behaviour left unchanged by
// #632: a token opened with a Unicode quote is still closed by any quote of
// the same kind, Unicode or ASCII.
func TestUnicodeOpenedTokenKeepsNormalizing(t *testing.T) {
	cases := []struct {
		sql, value string
	}{
		{"SELECT “Smart”", "Smart"},
		{"SELECT “Smart\"", "Smart"},
		{"SELECT ‘abc’", "abc"},
		{"SELECT ‘abc'", "abc"},
		{"SELECT «abc»", "abc"},
		{"SELECT ‘it’’s’", "it's"},
	}
	for _, tc := range cases {
		tkz := newDialectTokenizer(t, keywords.DialectPostgreSQL)
		toks, err := tkz.Tokenize([]byte(tc.sql))
		if err != nil {
			t.Fatalf("%q: %v", tc.sql, err)
		}
		if len(toks) != 3 || toks[1].Token.Value != tc.value {
			t.Errorf("%q: tokens %+v, want SELECT, %q, EOF", tc.sql, toks, tc.value)
		}
	}
}

// TestStringLiteralReaderStrictASCII covers the exported StringLiteralReader:
// a literal opened with an ASCII quote keeps Unicode quotes as content.
func TestStringLiteralReaderStrictASCII(t *testing.T) {
	in := []byte("'a’b'")
	pos := NewPosition(1, 0)
	tok, err := NewStringLiteralReader(in, &pos, '\'').ReadStringLiteral()
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "a’b" || pos.Index != len(in) {
		t.Fatalf("got %q at %d, want %q at %d", tok.Value, pos.Index, "a’b", len(in))
	}
}
