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

package keywords

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// These reference bodies are frozen copies of the pre-optimization lookup methods.
func refIsKeyword(k *Keywords, s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	_, ok := k.keywordMap[s]
	return ok
}

func refGetKeywordType(k *Keywords, s string) models.TokenType {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	if kw, ok := k.keywordMap[s]; ok {
		return kw.Type
	}
	return models.TokenTypeWord
}

func refIsReserved(k *Keywords, s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	return k.reservedKeywords[s]
}

func refGetKeyword(k *Keywords, word string) (Keyword, bool) {
	keyword, ok := k.keywordMap[strings.ToUpper(word)]
	return keyword, ok
}

func refGetTokenType(k *Keywords, word string) models.TokenType {
	var key string
	if k.ignoreCase {
		key = strings.ToUpper(word)
	} else {
		key = word
	}

	if kw, ok := k.keywordMap[key]; ok {
		return kw.Type
	}
	return models.TokenTypeWord
}

func refContainsKeyword(k *Keywords, word string) bool {
	if k.ignoreCase {
		_, exists := k.keywordMap[strings.ToUpper(word)]
		return exists
	}
	_, exists := k.keywordMap[word]
	return exists
}

func refIsCompoundKeywordStart(k *Keywords, word string) bool {
	if k.ignoreCase {
		word = strings.ToUpper(word)
	}
	return k.compoundKeywordStarts[word]
}

type lookupFoldInstance struct {
	name     string
	keywords *Keywords
}

func lookupFoldAddedKeywords(tb testing.TB) *Keywords {
	tb.Helper()
	k := New(DialectPostgreSQL, true)
	for _, word := range []string{"ÉCOLE", strings.Repeat("A", keyBufLen), strings.Repeat("B", keyBufLen+1), "CUSTOM KEY", "A@B", "A[B", "A\x00"} {
		if err := k.AddKeyword(Keyword{Word: word, Type: models.TokenTypeKeyword, Reserved: true}); err != nil {
			tb.Fatalf("AddKeyword(%q): %v", word, err)
		}
	}
	return k
}

func lookupFoldInstances(tb testing.TB) []lookupFoldInstance {
	tb.Helper()
	instances := []lookupFoldInstance{{"default", NewKeywords()}}
	for _, d := range AllDialects() {
		instances = append(instances, lookupFoldInstance{string(d), New(d, true)})
	}
	instances = append(instances,
		lookupFoldInstance{"case_sensitive", &Keywords{
			keywordMap: map[string]Keyword{
				"SELECT": {Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true},
				"FROM":   {Word: "FROM", Type: models.TokenTypeFrom},
			}, reservedKeywords: map[string]bool{"SELECT": true},
		}},
		lookupFoldInstance{"raw_80", &Keywords{
			ignoreCase:       true,
			keywordMap:       map[string]Keyword{"\x80X": {Word: "\x80X", Type: models.TokenTypeKeyword}},
			reservedKeywords: map[string]bool{"\x80X": true},
		}},
		lookupFoldInstance{"added", lookupFoldAddedKeywords(tb)},
	)
	return instances
}

func lookupFoldInputs(k *Keywords) []string {
	inputs := []string{
		"users", "customer_id", "x", "", "ſelect", "dıstınct", "Sſelect",
		"\xff", "sel\xff" + "ect", "\x80x", "SELECT\x00", "a\xff",
		"sel`ect", "sel{ect", "sel@ect", "sel[ect", "a`b", "a{b",
		strings.Repeat("a", keyBufLen), strings.Repeat("b", keyBufLen+1),
	}
	for _, n := range []int{keyBufLen - 1, keyBufLen, keyBufLen + 1, 200} {
		inputs = append(inputs, strings.Repeat("x", n))
	}
	keys := make(map[string]bool)
	for key := range k.keywordMap {
		keys[key] = true
	}
	for key := range k.compoundKeywordStarts {
		keys[key] = true
	}
	for key := range keys {
		alternate := []rune(strings.ToLower(key))
		for i := range alternate {
			if i%2 == 0 {
				alternate[i] = unicode.ToUpper(alternate[i])
			}
		}
		title := []rune(strings.ToLower(key))
		if len(title) > 0 {
			title[0] = unicode.ToTitle(title[0])
		}
		inputs = append(inputs, strings.ToUpper(key), strings.ToLower(key), string(title), string(alternate))
	}
	sort.Strings(inputs)
	return inputs
}

func assertLookupFoldEquivalent(t *testing.T, k *Keywords, input string) {
	t.Helper()
	if got, want := k.IsKeyword(input), refIsKeyword(k, input); got != want {
		t.Errorf("IsKeyword(%q) = %v, want %v", input, got, want)
	}
	if got, want := k.GetKeywordType(input), refGetKeywordType(k, input); got != want {
		t.Errorf("GetKeywordType(%q) = %v, want %v", input, got, want)
	}
	if got, want := k.IsReserved(input), refIsReserved(k, input); got != want {
		t.Errorf("IsReserved(%q) = %v, want %v", input, got, want)
	}
	got, gotOK := k.GetKeyword(input)
	want, wantOK := refGetKeyword(k, input)
	if got != want || gotOK != wantOK {
		t.Errorf("GetKeyword(%q) = (%+v, %v), want (%+v, %v)", input, got, gotOK, want, wantOK)
	}
	if got, want := k.GetTokenType(input), refGetTokenType(k, input); got != want {
		t.Errorf("GetTokenType(%q) = %v, want %v", input, got, want)
	}
	if got, want := k.IsCompoundKeywordStart(input), refIsCompoundKeywordStart(k, input); got != want {
		t.Errorf("IsCompoundKeywordStart(%q) = %v, want %v", input, got, want)
	}
	if got, want := k.containsKeyword(input), refContainsKeyword(k, input); got != want {
		t.Errorf("containsKeyword(%q) = %v, want %v", input, got, want)
	}
}

func TestLookupFold_Equivalence(t *testing.T) {
	for _, instance := range lookupFoldInstances(t) {
		t.Run(instance.name, func(t *testing.T) {
			for _, input := range lookupFoldInputs(instance.keywords) {
				assertLookupFoldEquivalent(t, instance.keywords, input)
			}
		})
	}
}

func FuzzLookupFold_Equivalence(f *testing.F) {
	seen := make(map[string]bool)
	for _, instance := range lookupFoldInstances(f) {
		for _, input := range lookupFoldInputs(instance.keywords) {
			if !seen[input] {
				f.Add(input)
				seen[input] = true
			}
		}
	}
	base, added := New(DialectPostgreSQL, true), lookupFoldAddedKeywords(f)
	f.Fuzz(func(t *testing.T, input string) {
		t.Run("postgresql", func(t *testing.T) { assertLookupFoldEquivalent(t, base, input) })
		t.Run("added", func(t *testing.T) { assertLookupFoldEquivalent(t, added, input) })
	})
}

func TestLookupFold_BuiltinKeysFitFastPath(t *testing.T) {
	for _, dialect := range AllDialects() {
		t.Run(string(dialect), func(t *testing.T) {
			k := New(dialect, true)
			check := func(name, key string) {
				if len(key) > keyBufLen {
					t.Errorf("%s key %q has %d bytes, exceeds fast path", name, key, len(key))
				}
				for i := range key {
					if key[i] >= utf8.RuneSelf {
						t.Errorf("%s key %q is not ASCII", name, key)
						break
					}
				}
			}
			for key := range k.keywordMap {
				check("keywordMap", key)
			}
			for key := range k.reservedKeywords {
				check("reservedKeywords", key)
			}
			for key := range k.compoundKeywordStarts {
				check("compoundKeywordStarts", key)
			}
		})
	}
}

func TestLookupFold_NoAllocs(t *testing.T) {
	k := New(DialectPostgreSQL, true)
	methods := []struct {
		name string
		call func(string)
	}{
		{"IsKeyword", func(s string) { lookupBenchmarkBool = k.IsKeyword(s) }},
		{"GetKeywordType", func(s string) { lookupBenchmarkType = k.GetKeywordType(s) }},
		{"IsReserved", func(s string) { lookupBenchmarkBool = k.IsReserved(s) }},
		{"GetKeyword", func(s string) { lookupBenchmarkKeyword, lookupBenchmarkBool = k.GetKeyword(s) }},
		{"GetTokenType", func(s string) { lookupBenchmarkType = k.GetTokenType(s) }},
		{"IsCompoundKeywordStart", func(s string) { lookupBenchmarkBool = k.IsCompoundKeywordStart(s) }},
	}
	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			for _, input := range []string{"select", "Select", "row_number", "users", "x", strings.Repeat("x", keyBufLen), strings.Repeat("x", keyBufLen+1)} {
				t.Run(fmt.Sprintf("%s_%d", input[:min(10, len(input))], len(input)), func(t *testing.T) {
					allocs := testing.AllocsPerRun(100, func() { method.call(input) })
					if len(input) <= keyBufLen && allocs != 0 {
						t.Errorf("%q: got %g allocations, want 0", input, allocs)
					}
					if len(input) == keyBufLen+1 && allocs > 1 {
						t.Errorf("65-byte fallback: got %g allocations, want at most 1", allocs)
					}
				})
			}
		})
	}
}
