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
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// longCommentRun is the number of consecutive comments used by the tests
// below. It is large enough that skipping comments with one stack frame per
// comment would exceed the stack limit set by limitStack, and small enough
// that the comments plus the tokens after them stay within MaxTokens.
const longCommentRun = 900_000

// limitStack lowers the maximum goroutine stack size for the duration of the
// test so that per-comment stack growth fails quickly instead of first
// growing towards the 1 GB default.
func limitStack(t *testing.T) {
	t.Helper()
	prev := debug.SetMaxStack(64 << 20)
	t.Cleanup(func() { debug.SetMaxStack(prev) })
}

// TestTokenizer_LongCommentRun checks that a long run of consecutive comments
// is skipped iteratively: tokenizing succeeds with a small stack limit, every
// comment is collected, and the token after the run is reported normally.
func TestTokenizer_LongCommentRun(t *testing.T) {
	limitStack(t)

	cases := []struct {
		name  string
		unit  string
		style models.CommentStyle
		text  string
		width int // bytes per unit on one line (block) or 0 (one unit per line)
	}{
		{name: "line", unit: "--\n", style: models.LineComment, text: "--"},
		{name: "block", unit: "/**/", style: models.BlockComment, text: "/**/", width: 4},
		{name: "block_with_space", unit: "/**/ ", style: models.BlockComment, text: "/**/", width: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Repeat(tc.unit, longCommentRun) + "SELECT 1"

			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.TokenizeString(input)
			if err != nil {
				t.Fatalf("TokenizeString: %v", err)
			}
			if len(tokens) != 3 {
				t.Fatalf("got %d tokens, want 3 (SELECT, 1, EOF)", len(tokens))
			}
			if tokens[0].Token.Type != models.TokenTypeSelect || tokens[1].Token.Value != "1" ||
				tokens[2].Token.Type != models.TokenTypeEOF {
				t.Fatalf("unexpected tokens: %v %v %v", tokens[0].Token, tokens[1].Token, tokens[2].Token)
			}

			if len(tkz.Comments) != longCommentRun {
				t.Fatalf("collected %d comments, want %d", len(tkz.Comments), longCommentRun)
			}
			for _, i := range []int{0, longCommentRun / 2, longCommentRun - 1} {
				c := tkz.Comments[i]
				if c.Text != tc.text || c.Style != tc.style {
					t.Fatalf("comment %d = %q (style %v), want %q (style %v)", i, c.Text, c.Style, tc.text, tc.style)
				}
				wantLine, wantCol := i+1, 1
				if tc.width > 0 {
					wantLine, wantCol = 1, i*tc.width+1
				}
				if c.Start.Line != wantLine || c.Start.Column != wantCol {
					t.Fatalf("comment %d starts at %d:%d, want %d:%d", i, c.Start.Line, c.Start.Column, wantLine, wantCol)
				}
			}
		})
	}
}

// TestTokenizer_LongCommentRunUnterminated checks that an unterminated block
// comment after a long run of comments still reports the usual error.
func TestTokenizer_LongCommentRunUnterminated(t *testing.T) {
	limitStack(t)

	input := strings.Repeat("--\n/**/", longCommentRun/2) + "/* open"

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	if _, err := tkz.TokenizeString(input); err == nil {
		t.Fatal("expected an unterminated block comment error, got nil")
	} else if !strings.Contains(err.Error(), "comment") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestTokenizer_CommentsBetweenTokens pins token values, comment text and
// positions for short mixed comment runs, which are now skipped in a loop.
func TestTokenizer_CommentsBetweenTokens(t *testing.T) {
	input := "SELECT /* a */ /*b*/ -- c\n-- d\n  1 -- e\n/* f */"

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	tokens, err := tkz.TokenizeString(input)
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	var vals []string
	for _, tok := range tokens {
		vals = append(vals, tok.Token.Value)
	}
	// A trailing comment yields an empty EOF-typed token before the final EOF.
	if got, want := strings.Join(vals, "|"), "SELECT|1||"; got != want {
		t.Fatalf("token values = %q, want %q", got, want)
	}

	want := []struct {
		text      string
		line, col int
		inline    bool
	}{
		{"/* a */", 1, 8, true},
		{"/*b*/", 1, 16, true},
		{"-- c", 1, 22, true},
		{"-- d", 2, 1, false},
		{"-- e", 3, 5, true},
		{"/* f */", 4, 1, false},
	}
	if len(tkz.Comments) != len(want) {
		t.Fatalf("collected %d comments, want %d", len(tkz.Comments), len(want))
	}
	for i, w := range want {
		c := tkz.Comments[i]
		if c.Text != w.text || c.Start.Line != w.line || c.Start.Column != w.col || c.Inline != w.inline {
			t.Errorf("comment %d = {%q %d:%d inline=%v}, want {%q %d:%d inline=%v}",
				i, c.Text, c.Start.Line, c.Start.Column, c.Inline, w.text, w.line, w.col, w.inline)
		}
	}
}
