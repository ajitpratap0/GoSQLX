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

package tokclass

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestGateIsHoleFree(t *testing.T) {
	values := []string{"count", "x"}
	for word := range goldenKeywordTypes {
		values = append(values, word)
	}
	values = append(values, CompoundKeys()...)
	for typ := models.TokenType(0); typ < 600; typ++ {
		wantGate := typ == models.TokenTypeIdentifier || typ == models.TokenTypeKeyword ||
			(typ >= models.TokenTypeCount && typ <= models.TokenTypeMax) ||
			(typ >= models.TokenTypeGroupBy && typ <= models.TokenTypeCrossJoin) ||
			typ == models.TokenTypeGroupingSets
		if got := Gate(typ); got != wantGate {
			t.Errorf("Gate(%d) = %v, want %v", typ, got, wantGate)
		}
		if Gate(typ) {
			continue
		}
		for _, value := range values {
			for _, quote := range []rune{0, '`'} {
				for _, span := range []string{"none", "exact", "wide"} {
					in := models.TokenWithSpan{Token: models.Token{Type: typ, Value: value, Quote: quote}}
					if span != "none" {
						in.Start = models.Location{Line: 1, Column: 1}
						in.End = models.Location{Line: 1, Column: 1 + len(value)}
						if span == "wide" {
							in.End.Column += 2
						}
					}
					got, compound := AppendCompound(nil, &in)
					if !compound {
						normalized := in
						NormalizeInPlace(&normalized)
						got = append(got, normalized)
					}
					if !reflect.DeepEqual(got, []models.TokenWithSpan{in}) {
						t.Fatalf("ungated rules changed type=%d value=%q quote=%q span=%s: got %+v, want %+v", typ, value, quote, span, got, in)
					}
				}
			}
		}
	}
}

func TestIdentifierRemapKeysAreTheDomain(t *testing.T) {
	keys := IdentifierRemapKeys()
	if len(keys) != 62 {
		t.Fatalf("IdentifierRemapKeys has %d entries, want 62", len(keys))
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatal("IdentifierRemapKeys is not sorted")
	}
	domain := make(map[string]bool, len(keys))
	for _, key := range keys {
		if domain[key] {
			t.Fatalf("duplicate identifier remap key %q", key)
		}
		domain[key] = true
	}
	words := make(map[string]bool, len(goldenKeywordTypes)+len(keys))
	for word := range goldenKeywordTypes {
		words[word] = true
	}
	for _, key := range keys {
		words[key] = true
	}
	for word := range words {
		if got := IdentifierKeywordType(word) != models.TokenTypeUnknown; got != domain[word] {
			t.Errorf("IdentifierKeywordType(%q) known = %v, listed = %v", word, got, domain[word])
		}
	}
	original := append([]string(nil), keys...)
	keys[0] = "changed copy"
	if got := IdentifierRemapKeys(); !reflect.DeepEqual(got, original) {
		t.Fatal("IdentifierRemapKeys does not return a fresh copy")
	}
}

func TestParserTypeMatchesNormalize(t *testing.T) {
	words := map[string]bool{"": true, "x": true, "users": true, "valıd": true, "ſum": true, "KEY": true, "abcdefghijklmnopq": true}
	for word := range goldenKeywordTypes {
		words[word] = true
	}
	for _, word := range IdentifierRemapKeys() {
		words[word] = true
	}
	types := []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeKeyword,
		models.TokenTypeWord, models.TokenTypeString, models.TokenTypeNumber,
		models.TokenTypeGroupBy, models.TokenTypeEOF}
	for typ := models.TokenTypeCount; typ <= models.TokenTypeMax; typ++ {
		types = append(types, typ)
	}
	for word := range words {
		for _, value := range []string{strings.ToUpper(word), strings.ToLower(word), mixCase(word)} {
			for _, typ := range types {
				normalized := models.TokenWithSpan{
					Token: models.Token{Type: typ, Value: value},
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 1, Column: 1 + len(value)},
				}
				NormalizeInPlace(&normalized)
				if got := ParserType(typ, value); got != normalized.Token.Type {
					t.Errorf("ParserType(%d, %q) = %d, NormalizeInPlace gives %d", typ, value, got, normalized.Token.Type)
				}
			}
		}
	}
}

func TestCompoundPartsByKey(t *testing.T) {
	want := []string{"CROSS JOIN", "FULL JOIN", "FULL OUTER JOIN", "GROUP BY", "GROUPING SETS", "INNER JOIN", "LEFT JOIN", "LEFT OUTER JOIN", "ORDER BY", "OUTER JOIN", "RIGHT JOIN", "RIGHT OUTER JOIN"}
	keys := CompoundKeys()
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("CompoundKeys() = %q, want sorted twelve keys %q", keys, want)
	}
	for _, key := range keys {
		if got := CompoundPartsByKey(key); got == nil {
			t.Errorf("CompoundPartsByKey(%q) = nil", key)
		}
		for _, invalid := range []string{strings.ToLower(key), strings.ReplaceAll(key, " ", "  "), " " + key, key + " "} {
			if got := CompoundPartsByKey(invalid); got != nil {
				t.Errorf("CompoundPartsByKey(%q) = %+v, want nil", invalid, got)
			}
		}
	}
	if got := CompoundPartsByKey(""); got != nil {
		t.Errorf("CompoundPartsByKey(empty) = %+v, want nil", got)
	}
	genericOuterJoin := models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeKeyword, Value: "OUTER JOIN"}}
	if got := CompoundParts(&genericOuterJoin); got != nil {
		t.Errorf("CompoundParts(generic OUTER JOIN) = %+v, want nil", got)
	}
	keys[0] = "changed copy"
	if got := CompoundKeys(); !reflect.DeepEqual(got, want) {
		t.Fatal("CompoundKeys does not return a fresh copy")
	}
}
