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

	"github.com/ajitpratap0/GoSQLX/internal/scaletest"
)

// inlineReference is the straightforward definition of Comment.Inline: some
// byte other than space, tab or CR precedes start on its line.
func inlineReference(src string, start int) bool {
	lineStart := strings.LastIndexByte(src[:start], '\n') + 1
	for i := lineStart; i < start; i++ {
		if c := src[i]; c != ' ' && c != '\t' && c != '\r' {
			return true
		}
	}
	return false
}

// TestTokenizer_CommentInlineMatchesReference checks the Inline flag of every
// collected comment against inlineReference on generated ASCII inputs that mix
// several comments per line, leading whitespace, CR and code.
func TestTokenizer_CommentInlineMatchesReference(t *testing.T) {
	frags := []string{
		" ", "  ", "\t", "\r", "\n", "\r\n", "--x\n", "-- y", "/**/", "/* z */",
		"/*\n*/", "SELECT", "1", "a", ",", "(", ")", ";", "'s'", "x.y",
	}
	rng := rand.New(rand.NewSource(1))

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	for n := 0; n < 20000; n++ {
		var sb strings.Builder
		for k := rng.Intn(24); k >= 0; k-- {
			sb.WriteString(frags[rng.Intn(len(frags))])
		}
		src := sb.String()
		if _, err := tkz.TokenizeString(src); err != nil {
			continue
		}
		// The fragments never put comment text inside a token, so each
		// comment starts at the first occurrence of its text after the
		// previous comment.
		off := 0
		for i, c := range tkz.Comments {
			rel := strings.Index(src[off:], c.Text)
			if rel < 0 {
				t.Fatalf("input %q: comment %d %q not found after offset %d", src, i, c.Text, off)
			}
			start := off + rel
			off = start + len(c.Text)
			if want := inlineReference(src, start); c.Inline != want {
				t.Fatalf("input %q: comment %d %q Inline = %v, want %v", src, i, c.Text, c.Inline, want)
			}
		}
	}
}

// TestTokenizer_CommentRunLinearTime checks that many comments on one line
// after a long whitespace prefix are tokenized in time linear in the input:
// the inline check must not rescan the line prefix for every comment. The
// work of a rescan is comments x prefix length, so the test grows both by 4x:
// a linear tokenizer takes about 4x as long, a rescanning one about 16x. The
// comparison is between two sizes of the same input, so race and coverage
// instrumentation slow both alike (see scaletest).
func TestTokenizer_CommentRunLinearTime(t *testing.T) {
	const (
		spaces   = 1 << 20
		comments = 20000
	)
	build := func(div int) string {
		return strings.Repeat(" ", spaces/div) + strings.Repeat("/**/", comments/div) + "SELECT 1"
	}
	input := build(1)

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	tokens, err := tkz.TokenizeString(input)
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("got %d tokens, want 3", len(tokens))
	}
	if len(tkz.Comments) != comments {
		t.Fatalf("collected %d comments, want %d", len(tkz.Comments), comments)
	}
	if tkz.Comments[0].Inline {
		t.Error("first comment after only whitespace reported as inline")
	}
	for _, i := range []int{1, comments / 2, comments - 1} {
		if !tkz.Comments[i].Inline {
			t.Errorf("comment %d after another comment on the same line not reported as inline", i)
		}
	}

	if testing.Short() {
		t.Skip("scaling check skipped in short mode")
	}
	small := build(4)
	scaletest.AssertLinearGrowth(t, "comments after whitespace", 10,
		func() { _, _ = tkz.TokenizeString(small) },
		func() { _, _ = tkz.TokenizeString(input) })
}
