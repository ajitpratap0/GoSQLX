// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	stderrors "errors"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestUnicodeEscapeTokens(t *testing.T) {
	tk, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`U&'d\0061t\+000061'`, `U&'d!0061t' UESCAPE '!'`, `u&'a''b'`, `U&'!+01F600' UESCAPE '!'`, `U&'\\'`, `U&'\D83D\DE00'`} {
		tokens, err := tk.TokenizeString(sql)
		if err != nil {
			t.Errorf("%s: %v", sql, err)
			continue
		}
		if len(tokens) != 2 || tokens[0].Token.Type != models.TokenTypeUnicodeStringLiteral || tokens[0].Token.Value != sql || tokens[0].Token.Quote != 'U' {
			t.Errorf("%s: %v", sql, tokens)
		}
	}
	for _, sql := range []string{`U&'\zzzz'`, `U&'\0000'`, `U&'\+110000'`, `U&'\D800'`, `U&'x' UESCAPE 'ab'`, `U&'x' UESCAPE '+'`, `U&'x' UESCAPE '0'`, `U&'x' UESCAPE ''`, `U&'unterminated`} {
		if _, err := tk.TokenizeString(sql); err == nil {
			t.Errorf("%s: expected error", sql)
		}
	}
}

func TestUnicodeEscapeNames(t *testing.T) {
	// U&"..." names decode into ordinary double-quoted identifier tokens.
	for _, tc := range []struct{ sql, name string }{
		{`U&"d\0061t"`, "dat"},
		{`u&"d!0061t" UESCAPE '!'`, "dat"},
		{`U&"A""b"`, `A"b`},
		{`U&"\D83D\DE00"`, "\U0001F600"},
		{`U&"x\\y"`, `x\y`},
		{`U&"d!0061t" /* c */ UESCAPE /* d */ '!'`, "dat"},
	} {
		got := lexAll(t, keywords.DialectPostgreSQL, tc.sql)
		if len(got) != 1 || got[0].typ != models.TokenTypeIdentifier || got[0].val != tc.name {
			t.Errorf("%s: %v", tc.sql, got)
		}
	}
}

func TestUnicodeIdentifierSpellingMetadata(t *testing.T) {
	tk := GetTokenizer()
	defer PutTokenizer(tk)
	tk.SetDialect(keywords.DialectPostgreSQL)
	for _, tc := range []struct{ source, decoded, spelling string }{
		{`U&"d\0061t\+000061"`, "data", `U&"d\0061t\+000061"`},
		{`u&"d!0061ta" UESCAPE '!'`, "data", `u&"d!0061ta" UESCAPE '!'`},
		{`U&"a\000Ab"`, "a\nb", `U&"a\000Ab"`},
		{`U&"d!0061ta" /* c */ UESCAPE '!'`, "data", `U&"d!0061ta" UESCAPE '!'`},
	} {
		for _, bytesAPI := range []bool{false, true} {
			var tokens []models.TokenWithSpan
			var err error
			if bytesAPI {
				tokens, err = tk.Tokenize([]byte(tc.source))
			} else {
				tokens, err = tk.TokenizeString(tc.source)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(tokens) != 2 {
				t.Fatalf("tokens: %#v", tokens)
			}
			tok := tokens[0].Token
			if tok.Value != tc.decoded || tok.Type != models.TokenTypeIdentifier || tok.Quote != '"' || tok.Word == nil || tok.Word.QuoteStyle != 'U' || tok.Word.Value != tc.spelling || tok.Word.Keyword != nil {
				t.Fatalf("bytes=%v source=%q token=%#v", bytesAPI, tc.source, tok)
			}
		}
	}
	// Reusing the tokenizer must not attach spelling metadata to ordinary names.
	tokens, err := tk.TokenizeString(`ordinary "ordinary"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tw := range tokens {
		if tw.Token.Word != nil && tw.Token.Word.QuoteStyle == 'U' {
			t.Fatalf("leaked Unicode metadata: %#v", tw.Token)
		}
	}
}

func TestUnicodeEscapeCommentsBeforeUESCAPE(t *testing.T) {
	// Comments between the literal and UESCAPE are whitespace: they are
	// recorded as comments and kept out of the literal's spelling.
	for _, sql := range []string{"U&'x' /* c */ UESCAPE '!'", "U&'x' -- c\n UESCAPE '!'", "U&'x'/**/UESCAPE/**/'!'"} {
		sql = strings.ReplaceAll(sql, `\n`, "\n")
		tk, err := NewWithDialect(keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tk.TokenizeString(sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if len(tokens) != 2 || tokens[0].Token.Value != "U&'x' UESCAPE '!'" || len(tk.Comments) == 0 {
			t.Errorf("%q: %v comments=%v", sql, tokens, tk.Comments)
		}
	}
	// Without UESCAPE the comment is recorded once and the literal ends at
	// its quote.
	tk, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tk.TokenizeString("U&'x' /* c */ , 1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 4 || tokens[0].Token.Value != "U&'x'" || len(tk.Comments) != 1 {
		t.Errorf("%v comments=%v", tokens, tk.Comments)
	}
}

// In dialects with an & operator, U&'x' is the expression U & 'x'.
func TestOtherDialectsKeepUnicodeAmpersandTokens(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer, keywords.DialectSQLite} {
		tokens := lexAll(t, dialect, `U&'x'`)
		if len(tokens) != 3 || tokens[0].val != "U" || tokens[1].val != "&" || tokens[2].val != "x" {
			t.Errorf("%s: %v", dialect, tokens)
		}
	}
}

// Oracle, Snowflake and ClickHouse have neither U& literals nor an &
// operator. Reading U&'x' as U & 'x' there let formatting turn it into
// BITAND(U, 'x') or bitAnd(U, 'x'), so it is rejected instead.
func TestUnicodeAmpersandRejectedWithoutAmpersandOperator(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectClickHouse} {
		for _, sql := range []string{`U&'x'`, `u&'x'`, `SELECT U&"col" FROM t`, `SELECT 1, U&'d\0061t' UESCAPE '\'`} {
			tk, err := NewWithDialect(dialect)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tk.TokenizeString(sql)
			var e *goerrors.Error
			if !stderrors.As(err, &e) || e.Code != goerrors.ErrCodeUnsupportedFeature || !strings.Contains(e.Message, "U& Unicode escape") {
				t.Errorf("%s %q: err = %v, want unsupported U& feature error", dialect, sql, err)
				continue
			}
			if want := strings.IndexAny(sql, "Uu") + 1; e.Location.Line != 1 || e.Location.Column != want {
				t.Errorf("%s %q: location = %+v, want line 1 column %d", dialect, sql, e.Location, want)
			}
		}
		// Only the adjacent U&' spelling is a Unicode literal: spaced or
		// longer names keep their tokens.
		for _, sql := range []string{`U & 'x'`, `menu&'x'`, `U&x`} {
			if tokens := lexAll(t, dialect, sql); len(tokens) != 3 {
				t.Errorf("%s %q: %v", dialect, sql, tokens)
			}
		}
	}
}
