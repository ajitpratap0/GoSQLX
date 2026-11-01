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

// Differential tests for the preprocess type-gated fast path: the optimised
// preprocessTokensInto must be byte-for-byte identical to the straightforward
// reference (appendCompound, else normalizeToken) for every token type and for
// real tokenizer output.

package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// normalizeToken is the by-value reference for normalizeTokenInPlace. It maps a TokenWithSpan to a canonical form expected by the
// parser. Type mismatches that existed in the tokenizer are corrected here.
func normalizeToken(t models.TokenWithSpan) models.TokenWithSpan {
	// TokenTypeMul (*) is the same symbol as TokenTypeAsterisk for the
	// parser. The parser explicitly checks both types wherever '*' can appear
	// (SELECT list wildcard, table.* qualified wildcard, COUNT(*) argument).
	// No remap is performed here to preserve the distinction for binary multiply.

	// Aggregate-function tokens (COUNT, SUM, AVG, MIN, MAX) must be treated
	// as identifiers so they can be used as function-call names.
	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		t.Token.Type = models.TokenTypeIdentifier
		return t
	}

	// Identifier tokens whose *value* is a keyword that the parser dispatches
	// on by type need to be remapped.
	if t.Token.Type == models.TokenTypeIdentifier {
		// A delimited identifier (`key`, [Group]) is a name, never a
		// keyword. The tokenizer strips backticks without recording them,
		// so a single-line span wider than the value marks one; record
		// the backtick so later stages can tell it from a bare word.
		if t.Token.Quote != 0 {
			return t
		}
		if t.Start.Line != 0 && t.Start.Line == t.End.Line && t.End.Column-t.Start.Column > len(t.Token.Value) {
			t.Token.Quote = '`'
			return t
		}
		if remapped := identifierKeywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
		return t
	}

	// Generic TokenTypeKeyword tokens need a specific type for the parser.
	if t.Token.Type == models.TokenTypeKeyword {
		if remapped := keywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
		return t
	}

	return t
}

// preprocessReference is the pre-fast-path implementation, kept as the oracle.
func preprocessReference(tokens []models.TokenWithSpan) []models.TokenWithSpan {
	dst := make([]models.TokenWithSpan, 0, len(tokens)+4)
	for i := range tokens {
		var ok bool
		if dst, ok = appendCompound(dst, &tokens[i]); ok {
			continue
		}
		dst = append(dst, normalizeToken(tokens[i]))
	}
	return dst
}

func diffPreprocess(t *testing.T, name string, in []models.TokenWithSpan) {
	t.Helper()
	snapshot := append([]models.TokenWithSpan(nil), in...)
	want := preprocessReference(in)
	got := preprocessTokensInto(nil, in)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s: fast path diverges from reference\nwant %+v\n got %+v", name, want, got)
	}
	if !reflect.DeepEqual(snapshot, in) {
		t.Fatalf("%s: input tokens were mutated", name)
	}
}

// TestPreprocessFastPath_EveryTokenType feeds every token type (including
// unassigned values) with values/quotes/spans that exercise each normalisation
// rule, so a type missing from the fast-path gate is caught.
func TestPreprocessFastPath_EveryTokenType(t *testing.T) {
	values := []string{
		"", "x", "select", "INSERT", "insert", "Update", "DELETE", "count", "SUM",
		"INNER JOIN", "cross join", "LEFT OUTER JOIN", "ORDER BY", "group by",
		"Grouping Sets", "AUTO_INCREMENT", "a-very-long-identifier-name", "'str'",
	}
	spans := []struct{ s, e models.Location }{
		{models.Location{}, models.Location{}},
		{models.Location{Line: 1, Column: 1}, models.Location{Line: 1, Column: 7}},
		{models.Location{Line: 1, Column: 1}, models.Location{Line: 1, Column: 40}},
		{models.Location{Line: 1, Column: 1}, models.Location{Line: 2, Column: 3}},
	}
	for typ := models.TokenType(0); typ < 600; typ++ {
		for _, v := range values {
			for _, q := range []rune{0, '"', '`'} {
				for _, sp := range spans {
					in := []models.TokenWithSpan{{
						Token: models.Token{Type: typ, Value: v, Quote: q},
						Start: sp.s, End: sp.e,
					}}
					diffPreprocess(t, "single", in)
				}
			}
		}
	}
}

// TestPreprocessFastPath_Corpus compares the two implementations over the
// tokenizer output of the repository's SQL fixtures.
func TestPreprocessFastPath_Corpus(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata")
	var files []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Ext(p) == ".sql" {
			files = append(files, p)
		}
		return nil
	})
	inline := []string{
		"SELECT COUNT(*), sum(x), Max(y) FROM t INNER JOIN u ON t.a=u.a LEFT OUTER JOIN v ON 1=1 GROUP BY a ORDER BY b",
		"SELECT `my col`, \"q\" FROM `t` CROSS JOIN u GROUP BY GROUPING SETS ((a),(b))",
		"INSERT INTO t (a) VALUES (1); UPDATE t SET a=2; DELETE FROM t",
	}
	tokenize := func(sql []byte) []models.TokenWithSpan {
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		toks, err := tkz.Tokenize(sql)
		if err != nil {
			return nil
		}
		return append([]models.TokenWithSpan(nil), toks...)
	}
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if toks := tokenize(b); toks != nil {
			diffPreprocess(t, f, toks)
			n += len(toks)
		}
	}
	for _, s := range inline {
		toks := tokenize([]byte(s))
		if toks == nil {
			t.Fatalf("tokenize failed: %s", s)
		}
		diffPreprocess(t, s, toks)
		n += len(toks)
	}
	if n == 0 {
		t.Fatal("no tokens compared")
	}
	t.Logf("compared %d tokens from %d files", n, len(files))
}
