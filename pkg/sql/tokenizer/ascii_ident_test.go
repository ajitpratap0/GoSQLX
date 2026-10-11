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
	"reflect"
	"testing"
	"unicode"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestASCIIIdentTables_MatchUnicodePredicates verifies the table-backed
// predicates agree with the full Unicode implementations for every rune,
// including negative values and values above unicode.MaxRune.
func TestASCIIIdentTables_MatchUnicodePredicates(t *testing.T) {
	for r := rune(-2); r <= unicode.MaxRune+1; r++ {
		if got, want := isUnicodeIdentifierStart(r), unicodeIdentifierStartSlow(r); got != want {
			t.Fatalf("isUnicodeIdentifierStart(%#U) = %v, want %v", r, got, want)
		}
		if got, want := isUnicodeIdentifierPart(r), unicodeIdentifierPartSlow(r); got != want {
			t.Fatalf("isUnicodeIdentifierPart(%#U) = %v, want %v", r, got, want)
		}
	}
}

// TestASCIIIdentTables_ExplicitContents pins the table contents by explicit
// rule so the tables and predicates cannot silently drift together.
func TestASCIIIdentTables_ExplicitContents(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := byte(i)
		isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		wantStart := i < 128 && (isLetter || c == '_')
		wantPart := i < 128 && (isLetter || isDigit || c == '_')
		if asciiIdentStart[i] != wantStart {
			t.Errorf("asciiIdentStart[%#x] = %v, want %v", i, asciiIdentStart[i], wantStart)
		}
		if asciiIdentPart[i] != wantPart {
			t.Errorf("asciiIdentPart[%#x] = %v, want %v", i, asciiIdentPart[i], wantPart)
		}
	}
}

type spanTok struct {
	typ    models.TokenType
	value  string
	sl, sc int
	el, ec int
}

func tokenizeSpans(t *testing.T, tkz *Tokenizer, input string) []spanTok {
	t.Helper()
	toks, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", input, err)
	}
	out := make([]spanTok, 0, len(toks))
	for _, tk := range toks {
		out = append(out, spanTok{
			typ: tk.Token.Type, value: tk.Token.Value,
			sl: tk.Start.Line, sc: tk.Start.Column,
			el: tk.End.Line, ec: tk.End.Column,
		})
	}
	return out
}

// TestTokenizer_MixedASCIIUnicodeIdentifiers exercises switching between the
// ASCII byte path and the multi-byte path inside one identifier, every ASCII
// terminator, and Line/Column tracking across newlines.
func TestTokenizer_MixedASCIIUnicodeIdentifiers(t *testing.T) {
	const (
		id  = models.TokenTypeIdentifier
		eof = models.TokenTypeEOF
	)
	tests := []struct {
		name  string
		input string
		want  []spanTok
	}{
		{"cjk in middle", "abc用户def", []spanTok{
			{id, "abc用户def", 1, 1, 1, 13}, {eof, "", 1, 13, 1, 13}}},
		{"latin1 after digit", "x_1é2 y", []spanTok{
			{id, "x_1é2", 1, 1, 1, 7}, {id, "y", 1, 8, 1, 9}, {eof, "", 1, 9, 1, 9}}},
		{"combining mark Mn", "café_tbl,", []spanTok{
			{id, "café_tbl", 1, 1, 1, 11},
			{models.TokenTypeComma, ",", 1, 11, 1, 12}, {eof, "", 1, 12, 1, 12}}},
		{"devanagari digit Nd", "_३.x", []spanTok{
			{id, "_३", 1, 1, 1, 5},
			{models.TokenTypePeriod, ".", 1, 5, 1, 6},
			{id, "x", 1, 6, 1, 7}, {eof, "", 1, 7, 1, 7}}},
		{"undertie Pc", "a‿b)", []spanTok{
			{id, "a‿b", 1, 1, 1, 6},
			{models.TokenTypeRParen, ")", 1, 6, 1, 7}, {eof, "", 1, 7, 1, 7}}},
		{"terminated by semicolon", "foo\nbar;", []spanTok{
			{id, "foo", 1, 1, 1, 4}, {id, "bar", 2, 1, 2, 4},
			{models.TokenTypeSemicolon, ";", 2, 4, 2, 5}, {eof, "", 2, 5, 2, 5}}},
		{"terminated by EOF", "tbl", []spanTok{
			{id, "tbl", 1, 1, 1, 4}, {eof, "", 1, 4, 1, 4}}},
		{"multi-line", "SELECT a\n  FROM t1\nWHERE b.c", []spanTok{
			{models.TokenTypeSelect, "SELECT", 1, 1, 1, 7},
			{id, "a", 1, 8, 1, 9},
			{models.TokenTypeFrom, "FROM", 2, 3, 2, 7},
			{id, "t1", 2, 8, 2, 10},
			{models.TokenTypeWhere, "WHERE", 3, 1, 3, 6},
			{id, "b", 3, 7, 3, 8},
			{models.TokenTypePeriod, ".", 3, 8, 3, 9},
			{id, "c", 3, 9, 3, 10}, {eof, "", 3, 10, 3, 10}}},
	}

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenizeSpans(t, tkz, tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Tokenize(%q)\n got  %+v\n want %+v", tt.input, got, tt.want)
			}
		})
	}
}

// TestTokenizer_CompoundKeywordAfterASCIIFastPath covers the compound-keyword
// lookahead, which scans the second word with scanIdentifierTail.
func TestTokenizer_CompoundKeywordAfterASCIIFastPath(t *testing.T) {
	const id = models.TokenTypeIdentifier
	tests := []struct {
		name  string
		input string
		want  []spanTok
	}{
		{"left join", "LEFT JOIN t", []spanTok{
			{models.TokenTypeLeftJoin, "LEFT JOIN", 1, 1, 1, 10},
			{id, "t", 1, 11, 1, 12}, {models.TokenTypeEOF, "", 1, 12, 1, 12}}},
		{"group by", "GROUP BY x", []spanTok{
			{models.TokenTypeGroupBy, "GROUP BY", 1, 1, 1, 9},
			{id, "x", 1, 10, 1, 11}, {models.TokenTypeEOF, "", 1, 11, 1, 11}}},
		{"order by across newline", "ORDER   BY\ny", []spanTok{
			{models.TokenTypeOrderBy, "ORDER BY", 1, 1, 1, 11},
			{id, "y", 2, 1, 2, 2}, {models.TokenTypeEOF, "", 2, 2, 2, 2}}},
		{"no match when second word extends", "INNER JOINx", []spanTok{
			{models.TokenTypeInner, "INNER", 1, 1, 1, 6},
			{id, "JOINx", 1, 7, 1, 12}, {models.TokenTypeEOF, "", 1, 12, 1, 12}}},
	}

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenizeSpans(t, tkz, tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Tokenize(%q)\n got  %+v\n want %+v", tt.input, got, tt.want)
			}
		})
	}
}

// TestTokenizer_ASCIIFastPath_PoolReuse pins that a pooled tokenizer produces
// the same output as a fresh one after alternating ASCII and Unicode inputs.
func TestTokenizer_ASCIIFastPath_PoolReuse(t *testing.T) {
	const (
		asciiSQL = "SELECT id, name FROM users WHERE age > 25"
		uniSQL   = "SELECT 用户.名前, café FROM пользователи"
		mixedSQL = "SELECT abc用户def,\nx_1é2 FROM t1\nLEFT JOIN café_tbl ON a = b"
	)

	fresh := func(input string) []spanTok {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		return tokenizeSpans(t, tkz, input)
	}
	wantASCII, wantUnicode, wantMixed := fresh(asciiSQL), fresh(uniSQL), fresh(mixedSQL)

	tkz := GetTokenizer()
	for i, c := range []struct {
		in   string
		want []spanTok
	}{{asciiSQL, wantASCII}, {uniSQL, wantUnicode}, {asciiSQL, wantASCII}} {
		if got := tokenizeSpans(t, tkz, c.in); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("reuse step %d: %q\n got  %+v\n want %+v", i, c.in, got, c.want)
		}
	}
	PutTokenizer(tkz)

	tkz = GetTokenizer()
	defer PutTokenizer(tkz)
	if got := tokenizeSpans(t, tkz, mixedSQL); !reflect.DeepEqual(got, wantMixed) {
		t.Fatalf("after Put/Get: %q\n got  %+v\n want %+v", mixedSQL, got, wantMixed)
	}
}
