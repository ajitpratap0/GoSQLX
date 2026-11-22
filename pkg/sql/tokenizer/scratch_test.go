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
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var scratchCases = []struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
}{
	{"simple", "", "SELECT id, name FROM users WHERE active = true"},
	{"multiline comments", "", "-- lead\nSELECT a /* mid */, \"Q\"\nFROM t\nORDER BY 1"},
	{"literals", "", "SELECT 'it''s', E'a\\nb', 1.5e3, $1 FROM t"},
	{"mysql", keywords.DialectMySQL, "SELECT `a`, 'x\\'y' FROM `db`.`t` LIMIT 5"},
	{"sqlserver", keywords.DialectSQLServer, "SELECT TOP 3 [a b] FROM dbo.t"},
	{"bom", "", "\xEF\xBB\xBFSELECT 1"},
	{"empty", "", ""},
}

// TestTokScratch_MatchesPublic checks that every scratch entry point returns
// exactly what the matching public method returns.
func TestTokScratch_MatchesPublic(t *testing.T) {
	for _, tc := range scratchCases {
		t.Run(tc.name, func(t *testing.T) {
			pub := GetTokenizer()
			defer PutTokenizer(pub)
			scr := GetTokenizer()
			defer PutTokenizer(scr)
			if tc.dialect != "" {
				pub.SetDialect(tc.dialect)
				scr.SetDialect(tc.dialect)
			}

			want, err := pub.TokenizeString(tc.sql)
			if err != nil {
				t.Fatalf("TokenizeString: %v", err)
			}

			calls := []struct {
				name string
				run  func() ([]models.TokenWithSpan, error)
			}{
				{"String", func() ([]models.TokenWithSpan, error) { return tokscratch.String(scr, tc.sql) }},
				{"Bytes", func() ([]models.TokenWithSpan, error) { return tokscratch.Bytes(scr, []byte(tc.sql)) }},
				{"StringContext", func() ([]models.TokenWithSpan, error) {
					return tokscratch.StringContext(context.Background(), scr, tc.sql)
				}},
			}
			for _, c := range calls {
				got, err := c.run()
				if err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s tokens differ from TokenizeString:\n got %v\nwant %v", c.name, got, want)
				}
				if (len(scr.Comments) != 0 || len(pub.Comments) != 0) && !reflect.DeepEqual(scr.Comments, pub.Comments) {
					t.Errorf("%s comments = %v, want %v", c.name, scr.Comments, pub.Comments)
				}
			}
		})
	}
}

// TestTokScratch_ReusesBuffer checks that the scratch path reuses the
// tokenizer's buffer while the public methods keep returning fresh,
// caller-owned slices that later calls never overwrite.
func TestTokScratch_ReusesBuffer(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	first, err := tokscratch.String(tkz, "SELECT a, b, c FROM t WHERE x = 1")
	if err != nil {
		t.Fatalf("scratch: %v", err)
	}
	second, err := tokscratch.String(tkz, "SELECT d FROM u")
	if err != nil {
		t.Fatalf("scratch: %v", err)
	}
	if &first[0] != &second[0] {
		t.Errorf("second scratch call did not reuse the buffer")
	}

	if first[1].Token.Word == nil || second[1].Token.Word == nil {
		t.Fatalf("precondition: identifier tokens carry no Word")
	}
	if first[1].Token.Word != second[1].Token.Word {
		t.Errorf("second scratch call did not reuse the Word slab")
	}

	pub, err := tkz.TokenizeString("SELECT p FROM q")
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	snapshot := projectWords(pub)
	if &pub[0] == &second[0] {
		t.Fatalf("public TokenizeString returned the scratch buffer")
	}
	if pub[1].Token.Word == second[1].Token.Word {
		t.Fatalf("public TokenizeString handed out a Word from the scratch slab")
	}
	if _, err := tokscratch.String(tkz, "UPDATE z SET y = 2 WHERE w = 3"); err != nil {
		t.Fatalf("scratch: %v", err)
	}
	if got := projectWords(pub); !reflect.DeepEqual(got, snapshot) {
		t.Errorf("scratch call changed an earlier public result:\n got %v\nwant %v", got, snapshot)
	}
}

// wordProjection is a token with its Word copied by value, so a snapshot does
// not share Words with the tokens it was taken from.
type wordProjection struct {
	Tok  models.TokenWithSpan
	Word models.Word
}

func projectWords(toks []models.TokenWithSpan) []wordProjection {
	out := make([]wordProjection, len(toks))
	for i, tk := range toks {
		out[i].Tok = tk
		out[i].Tok.Token.Word = nil
		if tk.Token.Word != nil {
			out[i].Word = *tk.Token.Word
		}
	}
	return out
}

// TestTokScratch_ResetClearsBuffer checks that Reset (and so PutTokenizer)
// drops every reference into the previous SQL, including after an error, and
// drops an oversized buffer.
func TestTokScratch_ResetClearsBuffer(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		wantErr bool
		dropped bool
	}{
		{"success", "SELECT a, b FROM t", false, false},
		{"tokenize error", "SELECT a, 'unterminated", true, false},
		{"oversized", "SELECT " + strings.Repeat("a, ", maxRetainedTokBuf) + "b", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tkz, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = tokscratch.String(tkz, tc.sql)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(tkz.tokBuf) == 0 {
				t.Fatalf("precondition: tokBuf is empty after the call")
			}
			buf := tkz.tokBuf[:cap(tkz.tokBuf)]
			slab := tkz.wordSlab[:cap(tkz.wordSlab)]
			// The oversized input has more words than the slab may hold,
			// so it never gets one.
			if !tc.dropped && tkz.wordSlabUsed == 0 {
				t.Fatalf("precondition: no Words handed out from the slab")
			}
			tkz.Reset()
			for i := range slab {
				if slab[i] != (models.Word{}) {
					t.Fatalf("wordSlab[%d] = %v after Reset, want zero", i, slab[i])
				}
			}
			if tkz.wordSlabUsed != 0 {
				t.Errorf("wordSlabUsed = %d after Reset, want 0", tkz.wordSlabUsed)
			}
			if tc.dropped {
				if tkz.tokBuf != nil {
					t.Errorf("oversized tokBuf (cap %d) kept after Reset", cap(buf))
				}
				return
			}
			if len(tkz.tokBuf) != 0 || cap(tkz.tokBuf) != cap(buf) {
				t.Errorf("tokBuf after Reset: len %d cap %d, want len 0 cap %d", len(tkz.tokBuf), cap(tkz.tokBuf), cap(buf))
			}
			for i := range buf {
				if buf[i] != (models.TokenWithSpan{}) {
					t.Fatalf("tokBuf[%d] = %v after Reset, want zero", i, buf[i])
				}
			}
		})
	}
}

// TestTokScratch_Errors checks error parity with the public methods and the
// guard against a wrong tokenizer argument.
func TestTokScratch_Errors(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	const bad = "SELECT 'oops"
	_, wantErr := tkz.TokenizeString(bad)
	_, gotErr := tokscratch.String(tkz, bad)
	if wantErr == nil || gotErr == nil || gotErr.Error() != wantErr.Error() {
		t.Errorf("scratch error = %v, want %v", gotErr, wantErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tokscratch.StringContext(ctx, tkz, "SELECT 1"); !errors.Is(err, context.Canceled) {
		t.Errorf("StringContext on cancelled ctx: err = %v, want context.Canceled", err)
	}

	for _, arg := range []any{nil, "not a tokenizer", (*Tokenizer)(nil)} {
		if _, err := tokscratch.String(arg, "SELECT 1"); err == nil {
			t.Errorf("tokscratch.String(%T) succeeded, want an error", arg)
		}
	}
}
