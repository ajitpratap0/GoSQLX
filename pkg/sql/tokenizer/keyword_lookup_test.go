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
)

func TestIsKeyword(t *testing.T) {
	tests := []struct {
		word string
		want bool
	}{
		{"select", true},
		{"SELECT", true},
		{"Table", true},
		{"order", true},
		{"users", false},
		{"", false},
		{"émoji", false},
		{strings.Repeat("a", keywordKeyBufLen+1), false},
	}
	for _, tc := range tests {
		if got := IsKeyword(tc.word); got != tc.want {
			t.Errorf("IsKeyword(%q) = %v, want %v", tc.word, got, tc.want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { IsKeyword("order") }); n != 0 {
		t.Errorf("IsKeyword allocates %v times per call, want 0", n)
	}
}

// TestKwTableMatchesMaps asserts the fused table resolves every key of both
// source maps exactly as the maps do, for the canonical and lower/mixed case.
func TestKwTableMatchesMaps(t *testing.T) {
	var buf [keywordKeyBufLen]byte
	lookup := func(word string) *kwEntry {
		h, ok := asciiUpperHash(buf[:len(word)], word)
		if !ok {
			t.Fatalf("%q unexpectedly non-ASCII", word)
		}
		return kwLookup(h, buf[:len(word)])
	}
	forms := func(k string) []string {
		mixed := []byte(strings.ToLower(k))
		for i := 0; i < len(mixed); i += 2 {
			mixed[i] = byte(strings.ToUpper(string(mixed[i]))[0])
		}
		return []string{k, strings.ToLower(k), string(mixed)}
	}
	for k, v := range keywordTokenTypes {
		for _, w := range forms(k) {
			e := lookup(w)
			if e == nil || !e.isKeyword || e.typ != v || e.compoundStart != compoundKeywordStarts[k] {
				t.Errorf("keyword %q: table=%+v want typ=%v compoundStart=%v", w, e, v, compoundKeywordStarts[k])
			}
		}
	}
	for k, v := range compoundKeywordStarts {
		for _, w := range forms(k) {
			e := lookup(w)
			if e == nil || e.compoundStart != v {
				t.Errorf("compound start %q: table=%+v want %v", w, e, v)
			}
			if _, isKw := keywordTokenTypes[k]; e != nil && e.isKeyword != isKw {
				t.Errorf("compound start %q: isKeyword=%v want %v", w, e.isKeyword, isKw)
			}
		}
	}
	for _, w := range []string{"foo", "selec", "SELECTT", "x", "_", "a1", "users"} {
		if e := lookup(w); e != nil && (e.isKeyword || e.compoundStart) {
			t.Errorf("%q should not be a keyword: %+v", w, e)
		}
	}
	// Table is read-only data: no key stored twice, load factor below 0.5.
	used := 0
	seen := map[string]bool{}
	for i := range kwTable {
		if kwTable[i].used {
			used++
			if seen[kwTable[i].key] {
				t.Errorf("duplicate key %q", kwTable[i].key)
			}
			seen[kwTable[i].key] = true
		}
	}
	if used*2 > kwTableSize {
		t.Errorf("load factor too high: %d/%d", used, kwTableSize)
	}
}

// TestIsKeywordMatchesMap checks IsKeyword (table backed) against the map,
// including non-ASCII and over-long words.
func TestIsKeywordMatchesMap(t *testing.T) {
	for k := range keywordTokenTypes {
		if !IsKeyword(k) || !IsKeyword(strings.ToLower(k)) {
			t.Errorf("IsKeyword(%q) = false", k)
		}
	}
	for k := range compoundKeywordStarts {
		_, want := keywordTokenTypes[k]
		if IsKeyword(k) != want {
			t.Errorf("IsKeyword(%q) = %v, want %v", k, !want, want)
		}
	}
	for _, w := range []string{"", "foo", "ſelect", "SELECTſ", strings.Repeat("a", 40), "ınsert"} {
		_, want := keywordTokenTypes[strings.ToUpper(w)]
		if IsKeyword(w) != want {
			t.Errorf("IsKeyword(%q) = %v, want %v", w, !want, want)
		}
	}
}
