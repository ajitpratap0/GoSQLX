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

package highlight

import (
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFoldUpperMatchesToUpper(t *testing.T) {
	values := []string{"", "select", "SELECT", "MiXeD_1", "0x1f", "ſelect", "ınt", "straße", "é", "名前", "😀a", "\xffa", strings.Repeat("a", 70)}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		b := make([]byte, r.Intn(50))
		for j := range b {
			b[j] = byte(r.Intn(256))
		}
		values = append(values, string(b))
	}
	ls := make([]lexeme, len(values))
	for i, v := range values {
		ls[i].up = v
	}
	foldUpper(ls)
	for i, v := range values {
		if want := strings.ToUpper(v); ls[i].up != want {
			t.Fatalf("%d: %q: got %q want %q", i, v, ls[i].up, want)
		}
	}
}

func TestUpperLemmaForRadixAndZero(t *testing.T) {
	for r := rune(utf8.RuneSelf); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for _, c := range []byte(strings.ToUpper(string(r))) {
			if c < utf8.RuneSelf && strings.ContainsRune("0123456789ABCDEFabcdefXxBb", rune(c)) {
				t.Fatalf("%U uppercases to %q", r, strings.ToUpper(string(r)))
			}
		}
	}
}

func TestPutScratchDropsReferences(t *testing.T) {
	sc := &scratch{lexemes: make([]lexeme, 2, 4), parens: make([]string, 1, 4)}
	sc.lexemes[0].up, sc.lexemes[1].up = "document", "other"
	sc.parens[:cap(sc.parens)][3] = "document"
	resetScratch(sc)
	if len(sc.lexemes) != 0 || len(sc.parens) != 0 {
		t.Fatal("buffers not reset")
	}
	for _, l := range sc.lexemes[:cap(sc.lexemes)] {
		if l != (lexeme{}) {
			t.Fatal("lexeme retained")
		}
	}
	for _, p := range sc.parens[:cap(sc.parens)] {
		if p != "" {
			t.Fatal("paren retained")
		}
	}
	large := &scratch{lexemes: make([]lexeme, 0, maxRetainedLexemes+1), lineStarts: make([]int, 0, maxRetainedLineStarts+1), comments: make([]Span, 0, maxRetainedComments+1), parens: make([]string, 0, maxRetainedParens+1)}
	resetScratch(large)
	if large.lexemes != nil || large.lineStarts != nil || large.comments != nil || large.parens != nil {
		t.Fatal("oversized buffers retained")
	}
}

// TestScratchClearedAfterRealRun drives the real classifier path and checks no
// lexeme (and so no `up` string pointing into the document) survives reset.
func TestScratchClearedAfterRealRun(t *testing.T) {
	src := "select a, b from t where a = 1 and b in (2, 3) order by a"
	sc := getScratch()
	h := classifier{src: src, kw: keywordsFor(""), sc: sc}
	h.indexLines()
	if _, err := h.run(len(src)); err != nil {
		t.Fatal(err)
	}
	if len(sc.lexemes) == 0 {
		t.Fatal("run produced no lexemes")
	}
	populated := len(sc.lexemes)
	resetScratch(sc)
	if len(sc.lexemes) != 0 {
		t.Fatal("lexemes not truncated")
	}
	full := sc.lexemes[:cap(sc.lexemes)]
	if len(full) < populated {
		t.Fatalf("capacity %d below populated %d", len(full), populated)
	}
	for i, l := range full {
		if l != (lexeme{}) {
			t.Fatalf("lexeme %d retained: %+v", i, l)
		}
	}
}
