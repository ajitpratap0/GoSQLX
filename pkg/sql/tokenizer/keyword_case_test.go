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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// tokenizeForCase tokenizes input with a pooled tokenizer and returns the
// tokens without the trailing EOF token.
func tokenizeForCase(t *testing.T, input string) []models.TokenWithSpan {
	t.Helper()
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	toks, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize(%q) error: %v", input, err)
	}
	if n := len(toks); n > 0 && toks[n-1].Token.Type == models.TokenTypeEOF {
		toks = toks[:n-1]
	}
	// Copy so results stay valid after the tokenizer returns to the pool.
	out := make([]models.TokenWithSpan, len(toks))
	copy(out, toks)
	return out
}

// caseVariants returns lower, upper and alternating-case forms of s.
func caseVariants(s string) []string {
	alt := []byte(strings.ToLower(s))
	for i := range alt {
		if i%2 == 1 && alt[i] >= 'a' && alt[i] <= 'z' {
			alt[i] -= 'a' - 'A'
		}
	}
	return []string{strings.ToLower(s), strings.ToUpper(s), string(alt)}
}

func TestKeywordClassificationCaseInsensitive(t *testing.T) {
	for key, want := range keywordTokenTypes {
		for _, variant := range caseVariants(key) {
			toks := tokenizeForCase(t, variant)
			if len(toks) != 1 {
				// Some keywords may be handled specially by the main loop;
				// the classification must still be consistent across cases.
				t.Errorf("%q: expected 1 token, got %d", variant, len(toks))
				continue
			}
			tok := toks[0].Token
			if tok.Type != want {
				t.Errorf("%q: type = %v, want %v", variant, tok.Type, want)
			}
			if tok.Value != variant {
				t.Errorf("%q: Value = %q, want original case", variant, tok.Value)
			}
			if tok.Word == nil || tok.Word.Value != variant {
				t.Errorf("%q: Word = %+v, want Word.Value %q", variant, tok.Word, variant)
			}
		}
	}
}

func TestCompoundKeywordCaseInsensitive(t *testing.T) {
	for key, want := range compoundKeywordTypes {
		if strings.Count(key, " ") != 1 {
			continue // the tokenizer only joins two words in one step
		}
		for _, variant := range caseVariants(key) {
			toks := tokenizeForCase(t, variant)
			if len(toks) != 1 {
				t.Errorf("%q: expected 1 token, got %d", variant, len(toks))
				continue
			}
			if toks[0].Token.Type != want {
				t.Errorf("%q: type = %v, want %v", variant, toks[0].Token.Type, want)
			}
			if toks[0].Token.Value != variant {
				t.Errorf("%q: Value = %q, want %q", variant, toks[0].Token.Value, variant)
			}
		}
	}
}

func TestCompoundKeywordValueAndMiss(t *testing.T) {
	// Value is always the two words joined by exactly one space.
	for _, tc := range []struct {
		input, value string
		typ          models.TokenType
	}{
		{"group   by", "group by", models.TokenTypeGroupBy},
		{"group\tby", "group by", models.TokenTypeGroupBy},
		{"order\n by", "order by", models.TokenTypeOrderBy},
		{"Left  Join", "Left Join", models.TokenTypeLeftJoin},
	} {
		toks := tokenizeForCase(t, tc.input)
		if len(toks) != 1 {
			t.Fatalf("%q: expected 1 token, got %d", tc.input, len(toks))
		}
		if toks[0].Token.Type != tc.typ || toks[0].Token.Value != tc.value {
			t.Errorf("%q: got (%v, %q), want (%v, %q)", tc.input,
				toks[0].Token.Type, toks[0].Token.Value, tc.typ, tc.value)
		}
	}

	t.Run("miss restores position", func(t *testing.T) {
		toks := tokenizeForCase(t, "left tbl")
		if len(toks) != 2 {
			t.Fatalf("expected 2 tokens, got %d", len(toks))
		}
		if toks[0].Token.Type != models.TokenTypeLeft || toks[0].Token.Value != "left" {
			t.Errorf("first token = (%v, %q), want LEFT", toks[0].Token.Type, toks[0].Token.Value)
		}
		if toks[1].Token.Type != models.TokenTypeIdentifier || toks[1].Token.Value != "tbl" {
			t.Errorf("second token = (%v, %q), want identifier tbl", toks[1].Token.Type, toks[1].Token.Value)
		}
		if toks[0].End.Column != 5 || toks[1].Start.Column != 6 {
			t.Errorf("spans wrong: first end col %d, second start col %d", toks[0].End.Column, toks[1].Start.Column)
		}
	})

	t.Run("compound start at EOF", func(t *testing.T) {
		toks := tokenizeForCase(t, "group")
		if len(toks) != 1 || toks[0].Token.Type != models.TokenTypeGroup {
			t.Fatalf("got %+v, want single GROUP token", toks)
		}
	})
}

func TestCompoundKeywordStartsAreKeywords(t *testing.T) {
	for k := range compoundKeywordStarts {
		if _, ok := keywordTokenTypes[k]; !ok {
			t.Errorf("compoundKeywordStarts key %q is not in keywordTokenTypes", k)
		}
	}
	for k := range compoundKeywordTypes {
		first, _, _ := strings.Cut(k, " ")
		if !compoundKeywordStarts[first] {
			t.Errorf("first word %q of compound %q is not in compoundKeywordStarts", first, k)
		}
	}
}

func TestKeywordKeyBufferBounds(t *testing.T) {
	// The fast path is only correct if no key exceeds the stack buffer.
	for k := range keywordTokenTypes {
		if len(k) > keywordKeyBufLen {
			t.Errorf("keywordTokenTypes key %q longer than keywordKeyBufLen", k)
		}
	}
	for k := range compoundKeywordStarts {
		if len(k) > keywordKeyBufLen {
			t.Errorf("compoundKeywordStarts key %q longer than keywordKeyBufLen", k)
		}
	}
	for k := range compoundKeywordTypes {
		if len(k) > keywordKeyBufLen {
			t.Errorf("compoundKeywordTypes key %q longer than keywordKeyBufLen", k)
		}
		if !isASCII(k) {
			t.Errorf("compoundKeywordTypes key %q is not ASCII", k)
		}
	}
	for k := range keywordTokenTypes {
		if !isASCII(k) {
			t.Errorf("keywordTokenTypes key %q is not ASCII", k)
		}
	}
}

func TestKeywordBufferBoundary(t *testing.T) {
	for _, n := range []int{keywordKeyBufLen - 1, keywordKeyBufLen, keywordKeyBufLen + 1} {
		word := strings.Repeat("a", n)
		toks := tokenizeForCase(t, word)
		if len(toks) != 1 || toks[0].Token.Type != models.TokenTypeIdentifier || toks[0].Token.Value != word {
			t.Errorf("len %d: got %+v, want identifier %q", n, toks, word)
		}
	}

	if toks := tokenizeForCase(t, "materialized"); len(toks) != 1 || toks[0].Token.Type != keywordTokenTypes["MATERIALIZED"] {
		t.Errorf("materialized: got %+v, want keyword", toks)
	}
	if toks := tokenizeForCase(t, "materializedx"); len(toks) != 1 || toks[0].Token.Type != models.TokenTypeIdentifier {
		t.Errorf("materializedx: got %+v, want identifier", toks)
	}

	// Compound boundary: "group " + word, total key length n.
	for _, wordLen := range []int{keywordKeyBufLen - len("group "), keywordKeyBufLen - len("group ") + 1} {
		word := strings.Repeat("b", wordLen)
		toks := tokenizeForCase(t, "group "+word)
		if len(toks) != 2 {
			t.Fatalf("group + %d-char word: expected 2 tokens, got %d", wordLen, len(toks))
		}
		if toks[0].Token.Type != models.TokenTypeGroup {
			t.Errorf("group + %d-char word: first type = %v, want GROUP", wordLen, toks[0].Token.Type)
		}
		if toks[1].Token.Type != models.TokenTypeIdentifier || toks[1].Token.Value != word {
			t.Errorf("group + %d-char word: second = (%v, %q)", wordLen, toks[1].Token.Type, toks[1].Token.Value)
		}
	}
}

func TestNonASCIIIdentifierKeywordFolding(t *testing.T) {
	// Behaviour-preserving: Unicode upper-casing maps U+017F to S and U+0131 to I.
	if toks := tokenizeForCase(t, "ſelect"); len(toks) != 1 || toks[0].Token.Type != models.TokenTypeSelect {
		t.Errorf("long-s select: got %+v, want SELECT", toks)
	}
	if toks := tokenizeForCase(t, "rıght join"); len(toks) != 1 ||
		toks[0].Token.Type != models.TokenTypeRightJoin || toks[0].Token.Value != "rıght join" {
		t.Errorf("dotless-i right join: got %+v, want RIGHT JOIN", toks)
	}

	for _, word := range []string{"sélect", "naïve", "café_table", strings.Repeat("é", 20)} {
		toks := tokenizeForCase(t, word)
		if len(toks) != 1 || toks[0].Token.Type != models.TokenTypeIdentifier || toks[0].Token.Value != word {
			t.Errorf("%q: got %+v, want identifier", word, toks)
		}
	}

	toks := tokenizeForCase(t, "gröup by")
	if len(toks) != 2 || toks[0].Token.Type != models.TokenTypeIdentifier || toks[0].Token.Value != "gröup" ||
		toks[1].Token.Type != keywordTokenTypes["BY"] {
		t.Errorf("gröup by: got %+v, want identifier then BY", toks)
	}
}

func TestKeywordLookupCaseDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	lower := "select id, name from users u left join orders o on u.id = o.user_id " +
		"where u.active = true group by name order by id limit 10"
	upper := strings.ToUpper(lower)

	measure := func(sql string) float64 {
		in := []byte(sql)
		return testing.AllocsPerRun(200, func() {
			tkz := GetTokenizer()
			if _, err := tkz.Tokenize(in); err != nil {
				t.Fatalf("Tokenize error: %v", err)
			}
			PutTokenizer(tkz)
		})
	}
	lowerAllocs, upperAllocs := measure(lower), measure(upper)
	if lowerAllocs != upperAllocs {
		t.Errorf("case changes allocations: lower=%v upper=%v", lowerAllocs, upperAllocs)
	}
}

func TestTokenizerPoolReuseAfterKeywordLookup(t *testing.T) {
	first := GetTokenizer()
	if _, err := first.Tokenize([]byte("select ſelect SELECT")); err != nil {
		t.Fatalf("Tokenize error: %v", err)
	}
	PutTokenizer(first)

	toks := tokenizeForCase(t, "x")
	if len(toks) != 1 || toks[0].Token.Type != models.TokenTypeIdentifier || toks[0].Token.Value != "x" {
		t.Errorf("after reuse, x: got %+v", toks)
	}
	toks = tokenizeForCase(t, "order by")
	if len(toks) != 1 || toks[0].Token.Type != models.TokenTypeOrderBy || toks[0].Token.Value != "order by" {
		t.Errorf("after reuse, order by: got %+v", toks)
	}
}
