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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"

	gerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Tests for the substring fast path of the quoted readers (#548).

type aliasWant int

const (
	aliasSkip aliasWant = iota // empty values: aliasing is not observable
	aliasYes                   // clean literal: Value is a substring of the input
	aliasNo                    // rewritten literal: Value is a fresh string
)

const noWord rune = -1

type quotedCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string

	// Expected first token, when errCode is empty.
	typ        models.TokenType
	value      string
	quote      rune
	quoteStyle rune            // Word.QuoteStyle, or noWord when Word must be nil
	end        models.Location // checked when non-zero
	alias      aliasWant

	errCode gerrors.ErrorCode
	errLoc  models.Location
}

var (
	backslashDialects   = []keywords.SQLDialect{"", keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSnowflake, keywords.DialectClickHouse}
	noBackslashDialects = []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite}
)

func quotedCases() []quotedCase {
	pg := keywords.DialectPostgreSQL
	bq := keywords.DialectBigQuery
	str := models.TokenTypeSingleQuotedString
	ident := models.TokenTypeDoubleQuotedString
	bt := models.TokenTypeIdentifier
	triple := models.TokenTypeTripleSingleQuotedString
	nat := models.TokenTypeNationalStringLiteral
	loc := func(l, c int) models.Location { return models.Location{Line: l, Column: c} }

	cases := []quotedCase{
		// Single-quoted strings.
		{name: "clean", dialect: pg, sql: `'abc'`, typ: str, value: "abc", quote: '\'', quoteStyle: noWord, end: loc(1, 6), alias: aliasYes},
		{name: "empty", dialect: pg, sql: `''`, typ: str, value: "", quote: '\'', quoteStyle: noWord, end: loc(1, 3)},
		{name: "doubled quote", dialect: pg, sql: `'it''s'`, typ: str, value: "it's", quote: '\'', quoteStyle: noWord, end: loc(1, 8), alias: aliasNo},
		{name: "trailing doubled quote", dialect: pg, sql: `'a'''`, typ: str, value: "a'", quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "escaped backslash", dialect: keywords.DialectMySQL, sql: `'a\\'`, typ: str, value: `a\`, quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "unknown escape mysql drops the backslash", dialect: keywords.DialectMySQL, sql: `'a\q'`, typ: str, value: `aq`, quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "unknown escape keeps the backslash", dialect: keywords.DialectClickHouse, sql: `'a\q'`, typ: str, value: `a\q`, quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "like escapes keep the backslash", dialect: keywords.DialectMySQL, sql: `'50\%\_'`, typ: str, value: `50\%\_`, quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "backslash quote does not close", dialect: keywords.DialectClickHouse, sql: `'a\'b'`, typ: str, value: `a'b`, quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "standard string ends at backslash quote", dialect: pg, sql: `'a\' x`, typ: str, value: `a\`, quote: '\'', quoteStyle: noWord, end: loc(1, 5), alias: aliasYes},
		{name: "multi-line", dialect: pg, sql: "'a\nb' x", typ: str, value: "a\nb", quote: '\'', quoteStyle: noWord, end: loc(2, 3), alias: aliasYes},
		{name: "unterminated at EOF", dialect: pg, sql: "'abc", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 1)},
		{name: "unterminated after newline", dialect: pg, sql: "x 'abc\n", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 3)},
		{name: "unicode content", dialect: pg, sql: "'héllo 世界'", typ: str, value: "héllo 世界", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "smart single quotes", dialect: pg, sql: "‘abc’", typ: str, value: "abc", quote: '‘', quoteStyle: noWord, alias: aliasYes},
		{name: "guillemets", dialect: pg, sql: "«abc»", typ: str, value: "abc", quote: '«', quoteStyle: noWord, alias: aliasYes},
		// A literal opened with an ASCII quote is closed only by that ASCII
		// quote: Unicode quotes inside it are kept as content (#632).
		{name: "smart double quote inside is content", dialect: pg, sql: "'a“b'", typ: str, value: "a“b", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "smart single quote does not close", dialect: pg, sql: "'a’; DROP TABLE pwn; --'", typ: str, value: "a’; DROP TABLE pwn; --", quote: '\'', quoteStyle: noWord, end: loc(1, 27), alias: aliasYes},
		{name: "guillemet does not close", dialect: pg, sql: "'a»b«c'", typ: str, value: "a»b«c", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "doubled smart quote is content", dialect: pg, sql: "'x’’y'", typ: str, value: "x’’y", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "ascii then smart quote is no escape", dialect: pg, sql: "'x'’y'", typ: str, value: "x", quote: '\'', quoteStyle: noWord, end: loc(1, 4), alias: aliasYes},
		{name: "smart quote only is unterminated", dialect: pg, sql: "'abc’", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 1)},
		{name: "smart quote content with doubled quote", dialect: pg, sql: "'a’b''c'", typ: str, value: "a’b'c", quote: '\'', quoteStyle: noWord, alias: aliasNo},
		{name: "smart quote content with invalid UTF-8", dialect: pg, sql: "'a’\xffb'", typ: str, value: "a’�b", quote: '\'', quoteStyle: noWord, alias: aliasNo},
		// A literal opened with a Unicode quote keeps normalizing: any rune
		// that normalizes to its quote closes or escapes it.
		{name: "smart opened doubled ascii quote", dialect: pg, sql: "‘a''b’", typ: str, value: "a'b", quote: '‘', quoteStyle: noWord, alias: aliasNo},
		{name: "smart opened closed by ascii", dialect: pg, sql: "‘abc' x", typ: str, value: "abc", quote: '‘', quoteStyle: noWord, end: loc(1, 8), alias: aliasYes},
		{name: "smart opened normalizes double quote", dialect: pg, sql: "‘a“b’", typ: str, value: `a"b`, quote: '‘', quoteStyle: noWord, alias: aliasNo},
		{name: "invalid UTF-8", dialect: pg, sql: "'a\xffb'", typ: str, value: "a�b", quote: '\'', quoteStyle: noWord, end: loc(1, 6), alias: aliasNo},
		{name: "valid U+FFFD", dialect: pg, sql: "'a�b'", typ: str, value: "a�b", quote: '\'', quoteStyle: noWord, alias: aliasYes},

		// Double-quoted identifiers.
		{name: "ident clean", dialect: pg, sql: `"Col"`, typ: ident, value: "Col", quote: '"', quoteStyle: '"', end: loc(1, 6), alias: aliasYes},
		{name: "ident empty", dialect: pg, sql: `""`, typ: ident, value: "", quote: '"', quoteStyle: '"'},
		{name: "ident doubled quote", dialect: pg, sql: `"a""b"`, typ: ident, value: `a"b`, quote: '"', quoteStyle: '"', alias: aliasNo},
		{name: "ident smart quotes", dialect: pg, sql: "“Smart”", typ: ident, value: "Smart", quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident smart single quote inside is content", dialect: pg, sql: "\"a‘b\"", typ: ident, value: "a‘b", quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident smart double quote does not close", dialect: pg, sql: "\"x”; DROP TABLE pwn; --“\"", typ: ident, value: "x”; DROP TABLE pwn; --“", quote: '"', quoteStyle: '"', end: loc(1, 30), alias: aliasYes},
		{name: "ident doubled smart quote is content", dialect: pg, sql: "\"a””b\"", typ: ident, value: "a””b", quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident smart quote only is unterminated", dialect: pg, sql: "x \"Smart”", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 3)},
		{name: "ident smart quote content with doubled quote", dialect: pg, sql: "\"a”b\"\"c\"", typ: ident, value: "a”b\"c", quote: '"', quoteStyle: '"', alias: aliasNo},
		{name: "ident smart opened closed by ascii", dialect: pg, sql: "“Smart\"", typ: ident, value: "Smart", quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident smart opened normalizes single quote", dialect: pg, sql: "“a’b”", typ: ident, value: "a'b", quote: '"', quoteStyle: '"', alias: aliasNo},
		{name: "ident smart opened doubled smart quote", dialect: pg, sql: "“a””b”", typ: ident, value: `a"b`, quote: '"', quoteStyle: '"', alias: aliasNo},
		{name: "ident backslash is content", dialect: pg, sql: `"a\b"`, typ: ident, value: `a\b`, quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident newline", dialect: pg, sql: "\"a\nb\"", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 1)},
		{name: "ident unterminated", dialect: pg, sql: "x \"abc", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 3)},
		{name: "ident unicode", dialect: pg, sql: "\"héllo 世界\"", typ: ident, value: "héllo 世界", quote: '"', quoteStyle: '"', alias: aliasYes},
		{name: "ident invalid UTF-8", dialect: pg, sql: "\"a\xffb\"", typ: ident, value: "a�b", quote: '"', quoteStyle: '"', alias: aliasNo},

		// Backtick identifiers.
		{name: "backtick clean", dialect: keywords.DialectMySQL, sql: "`col`", typ: bt, value: "col", quoteStyle: noWord, end: loc(1, 6), alias: aliasYes},
		{name: "backtick empty", dialect: keywords.DialectMySQL, sql: "``", typ: bt, value: "", quoteStyle: noWord},
		{name: "backtick doubled", dialect: keywords.DialectMySQL, sql: "`a``b`", typ: bt, value: "a`b", quoteStyle: noWord, alias: aliasNo},
		// parser.renderCurrentIdent uses this byte-wide span to recover backtick quoting.
		{name: "backtick unicode byte span", dialect: keywords.DialectBigQuery, sql: "`日本`", typ: bt, value: "日本", quoteStyle: noWord, end: loc(1, 9), alias: aliasYes},
		{name: "backtick doubled byte span", dialect: keywords.DialectBigQuery, sql: "`a``b`", typ: bt, value: "a`b", quoteStyle: noWord, end: loc(1, 7), alias: aliasNo},
		{name: "bare unicode byte span", dialect: keywords.DialectBigQuery, sql: "日本", typ: bt, value: "日本", quoteStyle: 0, end: loc(1, 7), alias: aliasYes},
		{name: "backtick multi-line", dialect: keywords.DialectMySQL, sql: "`a\nb` x", typ: bt, value: "a\nb", quoteStyle: noWord, end: loc(2, 3), alias: aliasYes},
		{name: "backtick invalid UTF-8 kept raw", dialect: keywords.DialectMySQL, sql: "`a\xffb`", typ: bt, value: "a\xffb", quoteStyle: noWord, alias: aliasYes},
		{name: "backtick unterminated", dialect: keywords.DialectMySQL, sql: "`abc", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 1)},

		// Triple-quoted strings.
		{name: "triple clean", dialect: bq, sql: "'''abc'''", typ: triple, value: "abc", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "triple with quote inside", dialect: bq, sql: "'''a'b'''", typ: triple, value: "a'b", quote: '\'', quoteStyle: noWord, alias: aliasYes},
		{name: "triple multi-line", dialect: bq, sql: "'''a\nb''' x", typ: triple, value: "a\nb", quote: '\'', quoteStyle: noWord, end: loc(2, 5), alias: aliasYes},
		{name: "triple unterminated", dialect: bq, sql: "'''abc", errCode: gerrors.ErrCodeUnterminatedString, errLoc: loc(1, 1)},
		{name: "triple invalid UTF-8", dialect: bq, sql: "'''a\xffb'''", typ: triple, value: "a�b", quote: '\'', quoteStyle: noWord, alias: aliasNo},

		// SQL Server national strings.
		{name: "national clean", dialect: keywords.DialectSQLServer, sql: "N'abc'", typ: nat, value: "abc", quote: 'N', quoteStyle: noWord, end: loc(1, 7), alias: aliasYes},
		{name: "national doubled quote", dialect: keywords.DialectSQLServer, sql: "N'it''s'", typ: nat, value: "it's", quote: 'N', quoteStyle: noWord, end: loc(1, 9), alias: aliasNo},
		{name: "national empty", dialect: keywords.DialectSQLServer, sql: "N''", typ: nat, value: "", quote: 'N', quoteStyle: noWord},
		{name: "national smart quote is content", dialect: keywords.DialectSQLServer, sql: "N'a’; DROP TABLE pwn; --'", typ: nat, value: "a’; DROP TABLE pwn; --", quote: 'N', quoteStyle: noWord, alias: aliasYes},
	}
	// A backslash escapes only in backslash-escaping dialects; elsewhere it
	// is plain content and the value aliases the input.
	for _, d := range backslashDialects {
		cases = append(cases, quotedCase{name: "backslash escape " + string(d), dialect: d, sql: `'a\nb'`,
			typ: str, value: "a\nb", quote: '\'', quoteStyle: noWord, end: loc(1, 7), alias: aliasNo})
	}
	for _, d := range noBackslashDialects {
		cases = append(cases, quotedCase{name: "literal backslash " + string(d), dialect: d, sql: `'a\nb'`,
			typ: str, value: `a\nb`, quote: '\'', quoteStyle: noWord, end: loc(1, 7), alias: aliasYes})
	}
	return cases
}

// newDialectTokenizer returns a tokenizer for d; the empty dialect is the
// zero value, reachable only in-package.
func newDialectTokenizer(t testing.TB, d keywords.SQLDialect) *Tokenizer {
	t.Helper()
	tkz, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d == "" {
		tkz.dialect = ""
	} else {
		tkz.SetDialect(d)
	}
	return tkz
}

// aliasesString reports whether v's bytes lie inside s's.
func aliasesString(s, v string) bool {
	if len(s) == 0 || len(v) == 0 {
		return false
	}
	sp := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	vp := uintptr(unsafe.Pointer(unsafe.StringData(v)))
	return vp >= sp && vp+uintptr(len(v)) <= sp+uintptr(len(s))
}

func checkQuotedCase(t *testing.T, tc quotedCase, tokens []models.TokenWithSpan, err error) {
	t.Helper()
	if tc.errCode != "" {
		var se *gerrors.Error
		if !errors.As(err, &se) {
			t.Fatalf("got err %v, want structured error %s", err, tc.errCode)
		}
		if se.Code != tc.errCode || se.Location != tc.errLoc {
			t.Fatalf("got error %s at %+v, want %s at %+v", se.Code, se.Location, tc.errCode, tc.errLoc)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("no tokens")
	}
	tw := tokens[0]
	tok := tw.Token
	if tok.Type != tc.typ || tok.Value != tc.value || tok.Quote != tc.quote {
		t.Fatalf("got {Type:%d Value:%q Quote:%q}, want {Type:%d Value:%q Quote:%q}",
			tok.Type, tok.Value, tok.Quote, tc.typ, tc.value, tc.quote)
	}
	if tc.quoteStyle == noWord {
		if tok.Word != nil {
			t.Fatalf("got Word %+v, want nil", *tok.Word)
		}
	} else {
		if tok.Word == nil {
			t.Fatal("got nil Word")
		}
		if tok.Word.Value != tc.value || tok.Word.QuoteStyle != tc.quoteStyle || tok.Word.Keyword != nil {
			t.Fatalf("got Word %+v, want {Value:%q QuoteStyle:%q}", *tok.Word, tc.value, tc.quoteStyle)
		}
	}
	if tw.Start != (models.Location{Line: 1, Column: 1}) {
		t.Fatalf("got Start %+v, want 1:1", tw.Start)
	}
	if tc.end != (models.Location{}) && tw.End != tc.end {
		t.Fatalf("got End %+v, want %+v", tw.End, tc.end)
	}
}

func TestQuotedLiterals_Table(t *testing.T) {
	for _, tc := range quotedCases() {
		t.Run(tc.name, func(t *testing.T) {
			tkz := newDialectTokenizer(t, tc.dialect)
			tokens, err := tkz.Tokenize([]byte(tc.sql))
			checkQuotedCase(t, tc, tokens, err)
			tokens, err = tkz.TokenizeString(tc.sql)
			checkQuotedCase(t, tc, tokens, err)
		})
	}
}

// TestQuotedLiterals_AliasInput checks which values are substrings of the
// TokenizeString input, and that Tokenize([]byte) values never observe later
// writes to the caller's buffer.
func TestQuotedLiterals_AliasInput(t *testing.T) {
	for _, tc := range quotedCases() {
		if tc.errCode != "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			tkz := newDialectTokenizer(t, tc.dialect)
			s := strings.Clone(tc.sql)
			tokens, err := tkz.TokenizeString(s)
			if err != nil {
				t.Fatal(err)
			}
			tok := tokens[0].Token
			switch tc.alias {
			case aliasYes:
				if !aliasesString(s, tok.Value) {
					t.Fatalf("Value %q does not alias the input", tok.Value)
				}
				if tok.Word != nil && !aliasesString(s, tok.Word.Value) {
					t.Fatalf("Word.Value %q does not alias the input", tok.Word.Value)
				}
			case aliasNo:
				if aliasesString(s, tok.Value) {
					t.Fatalf("rewritten Value %q aliases the input", tok.Value)
				}
			}

			input := []byte(tc.sql)
			tokens, err = tkz.Tokenize(input)
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotTokens(tokens, nil)
			for i := range input {
				input[i] = 'X'
			}
			if after := snapshotTokens(tokens, nil); !reflect.DeepEqual(before, after) {
				t.Fatalf("tokens alias the input buffer:\n before %+v\n after  %+v", before, after)
			}
		})
	}
}

// TestQuotedLiterals_PooledReuse checks that values built in litBuf are
// independent copies: later calls on the same pooled tokenizer, which reuse
// litBuf, must not change them.
func TestQuotedLiterals_PooledReuse(t *testing.T) {
	tkz := GetTokenizer()
	first := "SELECT 'it''s', 'clean', \"Quo\"\"ted\", \"Plain\", 'a\\tb' FROM t"
	a, err := tkz.TokenizeString(first)
	if err != nil {
		t.Fatal(err)
	}
	want := snapshotTokens(a, nil)
	var styles []rune
	for _, tw := range a {
		if tw.Token.Word != nil {
			styles = append(styles, tw.Token.Word.QuoteStyle)
		}
	}
	PutTokenizer(tkz)

	tkz2 := GetTokenizer()
	defer PutTokenizer(tkz2)
	big := "SELECT '" + strings.Repeat("zz''", 2000) + "', \"" + strings.Repeat(`yy""`, 2000) + "\" FROM t"
	if _, err := tkz2.TokenizeString(big); err != nil {
		t.Fatal(err)
	}
	if _, err := tkz2.Tokenize([]byte("SELECT 'q''q', \"w\"\"w\"")); err != nil {
		t.Fatal(err)
	}

	if got := snapshotTokens(a, nil); !reflect.DeepEqual(want, got) {
		t.Fatalf("earlier tokens changed:\n want %+v\n got  %+v", want, got)
	}
	var gotStyles []rune
	for _, tw := range a {
		if tw.Token.Word != nil {
			gotStyles = append(gotStyles, tw.Token.Word.QuoteStyle)
		}
	}
	if !reflect.DeepEqual(styles, gotStyles) {
		t.Fatalf("QuoteStyles changed: want %q, got %q", styles, gotStyles)
	}
}

// TestReset_DropsLargeLitBuf checks that Reset keeps a small litBuf for reuse
// and drops one that grew past maxRetainedLitBuf.
func TestReset_DropsLargeLitBuf(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tkz.TokenizeString("SELECT 'it''s'"); err != nil {
		t.Fatal(err)
	}
	tkz.Reset()
	if tkz.litBuf.Cap() == 0 || tkz.litBuf.Len() != 0 {
		t.Fatalf("small litBuf: cap %d len %d after Reset, want kept and empty", tkz.litBuf.Cap(), tkz.litBuf.Len())
	}

	huge := "SELECT '" + strings.Repeat("a''", 40<<10) + "'"
	if _, err := tkz.TokenizeString(huge); err != nil {
		t.Fatal(err)
	}
	if tkz.litBuf.Cap() <= maxRetainedLitBuf {
		t.Fatalf("litBuf cap %d, expected it to exceed %d", tkz.litBuf.Cap(), maxRetainedLitBuf)
	}
	tkz.Reset()
	if tkz.litBuf.Cap() != 0 {
		t.Fatalf("large litBuf kept after Reset: cap %d", tkz.litBuf.Cap())
	}
}

// TestReset_ZeroesLitBuf checks that no decoded literal text survives in a
// reset or pooled tokenizer's litBuf, including bytes past its length: the
// first literal is longer than the second, so its tail lies beyond the
// buffer's final length.
func TestReset_ZeroesLitBuf(t *testing.T) {
	const sentinel = "SENTINEL_SECRET_9f3a"
	sql := "SELECT '" + sentinel + "''" + sentinel + "', 'a''b' FROM t"
	hasSentinel := func(tkz *Tokenizer) bool {
		b := tkz.litBuf.Bytes()
		return strings.Contains(string(b[:cap(b)]), sentinel[:8])
	}

	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tkz.TokenizeString(sql); err != nil {
		t.Fatal(err)
	}
	if !hasSentinel(tkz) {
		t.Fatal("test setup: sentinel did not go through litBuf")
	}
	tkz.Reset()
	if tkz.litBuf.Cap() == 0 {
		t.Fatal("small litBuf dropped; expected it kept for reuse")
	}
	if hasSentinel(tkz) {
		t.Fatal("litBuf backing array still holds literal text after Reset")
	}

	pooled := GetTokenizer()
	if _, err := pooled.TokenizeString(sql); err != nil {
		t.Fatal(err)
	}
	PutTokenizer(pooled)
	next := GetTokenizer()
	defer PutTokenizer(next)
	if hasSentinel(next) {
		t.Fatal("pooled tokenizer's litBuf holds a previous request's literal text")
	}
}

// quotedReaderKind classifies the reader that nextToken would dispatch to
// at t.pos, or "" for none of the quoted readers.
func quotedReaderKind(tkz *Tokenizer) string {
	in := tkz.input[tkz.pos.Index:]
	r, _ := utf8.DecodeRune(in)
	switch {
	case isIdentifierStart(r):
		if tkz.dialect == keywords.DialectSQLServer && (r == 'N' || r == 'n') && len(in) > 1 && in[1] == '\'' {
			return "national"
		}
		return ""
	case r == '"' || isUnicodeQuote(r):
		return "ident"
	case r == '`':
		return "backtick"
	case r == '\'' || r == '‘' || r == '’' || r == '«' || r == '»':
		return "string"
	}
	return ""
}

// readQuotedSlowRef runs the quoted reader for kind with the fast path
// disabled: it repeats the reader's opening-quote handling and then calls the
// *Slow reference loop.
func readQuotedSlowRef(tkz *Tokenizer, kind string) (models.Token, error) {
	switch kind {
	case "ident":
		r, size := utf8.DecodeRune(tkz.input[tkz.pos.Index:])
		startPos := tkz.pos.Clone()
		tkz.pos.AdvanceRune(r, size)
		return tkz.readQuotedIdentifierSlow(startPos, r)
	case "backtick":
		startPos := tkz.pos.Clone()
		tkz.pos.Index++
		tkz.pos.Column++
		return tkz.readBacktickIdentifierSlow(startPos)
	case "national":
		r, size := utf8.DecodeRune(tkz.input[tkz.pos.Index:])
		tkz.pos.AdvanceRune(r, size)
		tok, err := readQuotedSlowRef(tkz, "string")
		if err != nil {
			return models.Token{}, err
		}
		return models.Token{Type: models.TokenTypeNationalStringLiteral, Value: tok.Value, Quote: 'N'}, nil
	default: // "string"
		quote, _ := utf8.DecodeRune(tkz.input[tkz.pos.Index:])
		startPos := tkz.pos
		if tkz.dialect == keywords.DialectBigQuery && tkz.pos.Index+2 < len(tkz.input) {
			next1, _ := utf8.DecodeRune(tkz.input[tkz.pos.Index+1:])
			next2, _ := utf8.DecodeRune(tkz.input[tkz.pos.Index+2:])
			if next1 == quote && next2 == quote {
				for i := 0; i < 3; i++ {
					r, size := utf8.DecodeRune(tkz.input[tkz.pos.Index:])
					tkz.pos.AdvanceRune(r, size)
				}
				return tkz.readTripleQuotedStringSlow(startPos, quote)
			}
		}
		r, size := utf8.DecodeRune(tkz.input[tkz.pos.Index:])
		tkz.pos.AdvanceRune(r, size)
		return tkz.readQuotedStringSlow(startPos, r, normalizeQuote(r))
	}
}

// assertQuotedFastMatchesSlow drives two tokenizers over s in lockstep. One
// uses the normal readers; the other forces every quoted literal through the
// slow reference. Tokens, errors and the full scanner Position (including
// LastNL) must match after every token.
func assertQuotedFastMatchesSlow(t testing.TB, d keywords.SQLDialect, s string) {
	t.Helper()
	fast, slow := newDialectTokenizer(t, d), newDialectTokenizer(t, d)
	for _, tkz := range []*Tokenizer{fast, slow} {
		tkz.load(stringBytes(s), s)
		tkz.prescan()
	}
	for steps := 0; fast.pos.Index < len(fast.input); steps++ {
		if steps > len(s)+1 {
			t.Fatalf("dialect %q input %q: no progress", d, s)
		}
		fast.skipWhitespace()
		slow.skipWhitespace()
		if fast.pos != slow.pos {
			t.Fatalf("dialect %q input %q: positions diverged before token: fast %+v slow %+v", d, s, fast.pos, slow.pos)
		}
		if fast.pos.Index >= len(fast.input) {
			break
		}
		kind := quotedReaderKind(slow)
		ft, ferr := fast.nextToken()
		var st models.Token
		var serr error
		if kind == "" {
			st, serr = slow.nextToken()
		} else {
			st, serr = readQuotedSlowRef(slow, kind)
		}
		if (ferr == nil) != (serr == nil) || (ferr != nil && ferr.Error() != serr.Error()) {
			t.Fatalf("dialect %q input %q (%s): errors differ:\n fast %v\n slow %v", d, s, kind, ferr, serr)
		}
		if ferr != nil {
			return
		}
		if !reflect.DeepEqual(ft, st) {
			t.Fatalf("dialect %q input %q (%s): tokens differ:\n fast %+v\n slow %+v", d, s, kind, ft, st)
		}
		if fast.pos != slow.pos {
			t.Fatalf("dialect %q input %q (%s): positions differ after token: fast %+v slow %+v", d, s, kind, fast.pos, slow.pos)
		}
	}
	if !reflect.DeepEqual(fast.Comments, slow.Comments) {
		t.Fatalf("dialect %q input %q: comments differ", d, s)
	}
}

// quotedDifferentialInputs are the edge inputs plus variants that put each
// literal mid-statement and after a newline, so the scanners start from
// non-trivial positions.
func quotedDifferentialInputs() []string {
	var out []string
	for _, s := range quotedLiteralEdgeInputs {
		out = append(out, s, "SELECT "+s+", z\nFROM t", "x\n  "+s+" y "+s)
	}
	for _, tc := range quotedCases() {
		out = append(out, tc.sql)
	}
	return out
}

func TestQuotedFastPath_MatchesSlow(t *testing.T) {
	for _, d := range literalGoldenDialects {
		for _, s := range quotedDifferentialInputs() {
			assertQuotedFastMatchesSlow(t, d, s)
		}
	}
}

func repeatList(n int, item func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = item(i)
	}
	return "SELECT " + strings.Join(parts, ", ") + " FROM t"
}

// TestTokenizeString_AllocsIndependentOfLiteralCount checks that clean
// literals and quoted identifiers no longer allocate per token (#548), and
// that an escaped literal costs exactly one string.
func TestTokenizeString_AllocsIndependentOfLiteralCount(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	allocs := func(s string) float64 {
		return testing.AllocsPerRun(50, func() {
			if _, err := tkz.TokenizeString(s); err != nil {
				t.Fatal(err)
			}
		})
	}

	lit := func(i int) string { return fmt.Sprintf("'value%03d'", i) }
	if small, large := allocs(repeatList(10, lit)), allocs(repeatList(200, lit)); small != large {
		t.Fatalf("string literal allocs grow with count: N=10 -> %v, N=200 -> %v", small, large)
	}

	// Quoted-identifier Words come from the slab, whose chunks grow
	// geometrically, so 200 identifiers cost a few chunk allocations at most.
	id := func(i int) string { return fmt.Sprintf(`"Col%03d"`, i) }
	if small, large := allocs(repeatList(10, id)), allocs(repeatList(200, id)); large > small+4 {
		t.Fatalf("quoted identifier allocs: N=10 -> %v, N=200 -> %v, want at most +4", small, large)
	}

	bt := func(i int) string { return fmt.Sprintf("`col%03d`", i) }
	tkz.SetDialect(keywords.DialectMySQL)
	if small, large := allocs(repeatList(10, bt)), allocs(repeatList(200, bt)); small != large {
		t.Fatalf("backtick allocs grow with count: N=10 -> %v, N=200 -> %v", small, large)
	}
	tkz.SetDialect(keywords.DialectPostgreSQL)

	const n = 50
	clean := allocs(repeatList(n, func(int) string { return "'abcd'" }))
	doubled := allocs(repeatList(n, func(int) string { return "'a''b'" }))
	if doubled != clean+n {
		t.Fatalf("doubled-quote literals: %v allocs, want clean %v + %d", doubled, clean, n)
	}
}
