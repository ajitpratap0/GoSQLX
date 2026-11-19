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
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/tokclass"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestCompoundKeysMatchTokenizer pins the tokenizer-joinable compound keys
// and the expansions a parser-ready tokenizer must emit for each one.
func TestCompoundKeysMatchTokenizer(t *testing.T) {
	keys := make([]string, 0, len(compoundKeywordTypes))
	for key := range compoundKeywordTypes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) != 12 {
		t.Errorf("tokenizer compound key count = %d, want 12", len(keys))
	}
	if got := tokclass.CompoundKeys(); !reflect.DeepEqual(got, keys) {
		t.Errorf("CompoundKeys() = %q, tokenizer keys = %q", got, keys)
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			got := tokclass.CompoundPartsByKey(key)
			if got == nil {
				t.Fatalf("CompoundPartsByKey(%q) = nil", key)
			}
			want := tokclass.CompoundParts(&models.TokenWithSpan{
				Token: models.Token{Type: compoundKeywordTypes[key], Value: key},
			})
			if !reflect.DeepEqual(got, want) {
				t.Errorf("CompoundPartsByKey(%q) = %+v, typed expansion = %+v", key, got, want)
			}
			first, _, _ := strings.Cut(key, " ")
			if !compoundKeywordStarts[first] {
				t.Errorf("compound first word %q is missing from compoundKeywordStarts", first)
			}
		})
	}
}

// TestRemapOnlyWordsPinned pins words that the parser remaps even though the
// tokenizer does not currently classify them through keywordTokenTypes.
func TestRemapOnlyWordsPinned(t *testing.T) {
	want := []string{
		"ANY", "AUTOINCREMENT", "AUTO_INCREMENT", "CONNECTOR", "DCPROPERTIES",
		"LATERAL", "MEMBER", "NOCREATEDB", "NOCREATEROLE", "NOLOGIN",
		"NOSUPERUSER", "OWNER", "POLICY", "RESET", "SOME", "UNTIL", "URL", "VALID",
	}
	var got []string
	for _, key := range tokclass.IdentifierRemapKeys() {
		if _, ok := keywordTokenTypes[key]; !ok {
			got = append(got, key)
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("remap-only words = %q, want %q", got, want)
	}
}

// TestParserTypeOfTokenizerKeywords pins the parser type precomputed from
// each lexical keyword against the existing normalization rule.
func TestParserTypeOfTokenizerKeywords(t *testing.T) {
	for key, typ := range keywordTokenTypes {
		t.Run(key, func(t *testing.T) {
			token := models.TokenWithSpan{
				Token: models.Token{Type: typ, Value: key},
				Start: models.Location{Line: 1, Column: 1},
				End:   models.Location{Line: 1, Column: 1 + len(key)},
			}
			tokclass.NormalizeInPlace(&token)
			if got := tokclass.ParserType(typ, key); got != token.Token.Type {
				t.Errorf("ParserType(%v, %q) = %v, NormalizeInPlace type = %v", typ, key, got, token.Token.Type)
			}
		})
	}
}
