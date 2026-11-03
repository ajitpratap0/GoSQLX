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
	"math/rand"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// spacedWords builds an input of identifier words separated by random
// whitespace (spaces, tabs, LF, CRLF) and returns it with the byte offset of
// each word. Every word is a plain identifier, so token i spans exactly
// [starts[i], starts[i]+len(words[i])).
func spacedWords(rng *rand.Rand, n int, bom bool) (input string, starts, ends []int) {
	words := []string{"a", "colx", "naïve", "日本語", "t1", "x_y", "select_me"}
	seps := []string{" ", "  ", "\t", "\n", "\r\n", "\n\n", " \n ", "\n\t\t"}
	var sb strings.Builder
	if bom {
		sb.WriteString("\xEF\xBB\xBF")
	}
	for i := 0; i < n; i++ {
		if i > 0 || rng.Intn(3) == 0 {
			sb.WriteString(seps[rng.Intn(len(seps))])
		}
		w := words[rng.Intn(len(words))]
		// Avoid keywords turning into different token types: all words
		// above are non-keywords, and only positions are asserted.
		starts = append(starts, sb.Len())
		sb.WriteString(w)
		ends = append(ends, sb.Len())
	}
	return sb.String(), starts, ends
}

// wantLoc is the independent oracle: the 1-based line and byte column of off,
// counting from the first byte after an optional BOM.
func wantLoc(input string, off int) models.Location {
	base := 0
	if strings.HasPrefix(input, "\xEF\xBB\xBF") {
		base = 3
	}
	if off < base {
		off = base
	}
	prefix := input[base:off]
	line := strings.Count(prefix, "\n")
	col := off - base - (strings.LastIndexByte(prefix, '\n') + 1)
	return models.Location{Line: line + 1, Column: col + 1}
}

func TestLineWindowPositionsMatchOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	for iter := 0; iter < 300; iter++ {
		bom := iter%3 == 0
		input, starts, ends := spacedWords(rng, 1+rng.Intn(60), bom)
		// A pooled tokenizer is reused across inputs on purpose: the cached
		// line window must not leak from one input into the next.
		toks, err := tkz.Tokenize([]byte(input))
		if err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		// Last token is EOF.
		if len(toks) != len(starts)+1 {
			t.Fatalf("iter %d: got %d tokens, want %d (input %q)", iter, len(toks), len(starts)+1, input)
		}
		for i := range starts {
			if got, want := toks[i].Start, wantLoc(input, starts[i]); got != want {
				t.Fatalf("iter %d token %d Start = %+v, want %+v (input %q)", iter, i, got, want, input)
			}
			if got, want := toks[i].End, wantLoc(input, ends[i]); got != want {
				t.Fatalf("iter %d token %d End = %+v, want %+v (input %q)", iter, i, got, want, input)
			}
		}
	}
}

func TestLineWindowBOMFirstLineColumns(t *testing.T) {
	// The BOM is not part of the SQL: the first token starts at column 1 and
	// the first line begins after the BOM.
	input := "\xEF\xBB\xBFSELECT a\nFROM t"
	toks, err := newTok(t).Tokenize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ sl, sc, el, ec int }{
		{1, 1, 1, 7}, // SELECT
		{1, 8, 1, 9}, // a
		{2, 1, 2, 5}, // FROM
		{2, 6, 2, 7}, // t
		{2, 7, 2, 7}, // EOF
	}
	if len(toks) != len(want) {
		t.Fatalf("got %d tokens, want %d: %+v", len(toks), len(want), toks)
	}
	for i, w := range want {
		s, e := toks[i].Start, toks[i].End
		if s.Line != w.sl || s.Column != w.sc || e.Line != w.el || e.Column != w.ec {
			t.Errorf("token %d: got %+v-%+v, want %d:%d-%d:%d", i, s, e, w.sl, w.sc, w.el, w.ec)
		}
	}
}

func TestLineWindowResetBetweenInputs(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	long := strings.Repeat("alpha beta\n", 50) + "gamma"
	if _, err := tkz.Tokenize([]byte(long)); err != nil {
		t.Fatal(err)
	}
	// A short single-line input after a long one: stale window state would
	// report line 51 or a wrong column.
	toks, err := tkz.Tokenize([]byte("x y"))
	if err != nil {
		t.Fatal(err)
	}
	if toks[0].Start != (models.Location{Line: 1, Column: 1}) || toks[1].Start != (models.Location{Line: 1, Column: 3}) {
		t.Fatalf("stale window after reuse: %+v %+v", toks[0].Start, toks[1].Start)
	}
}

func TestLineWindowCommentsAndEOF(t *testing.T) {
	cases := []string{
		"a -- c\nb",
		"a /* x\ny */ b\r\nc",
		"a\n",
		"a\r\n",
		"",
		"   ",
		"\n\n\na",
		"'str\nspanning' b",
	}
	for _, in := range cases {
		toks, err := newTok(t).Tokenize([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		for i, tk := range toks {
			if tk.Start.Line < 1 || tk.Start.Column < 1 || tk.End.Line < tk.Start.Line {
				t.Errorf("%q token %d: bad span %+v-%+v", in, i, tk.Start, tk.End)
			}
		}
	}
}

func newTok(t *testing.T) *Tokenizer {
	t.Helper()
	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return tkz
}
