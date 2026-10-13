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
	stderrors "errors"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
)

// wantTokenLimit fails the test unless err is an E1007 token-limit error
// located on wantLine.
func wantTokenLimit(t *testing.T, err error, wantLine int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a token limit error, got nil")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Fatalf("expected *errors.Error, got %T: %v", err, err)
	}
	if e.Code != errors.ErrCodeTokenLimitReached {
		t.Fatalf("error code = %s, want %s (%v)", e.Code, errors.ErrCodeTokenLimitReached, err)
	}
	if wantLine > 0 && e.Location.Line != wantLine {
		t.Fatalf("error line = %d, want %d", e.Location.Line, wantLine)
	}
}

// TestTokenizer_CommentCountLimit checks that collected comments count toward
// MaxTokens together with tokens: the call fails with the token-limit error
// exactly when tokens plus comments exceed MaxTokens.
//
// Each case tokenizes about a million comments, which takes well over ten
// seconds per case under the race detector with coverage on CI. With race
// enabled only the exact-boundary error case and the reuse case run; the
// remaining cases run without -race. All cases are skipped with -short.
func TestTokenizer_CommentCountLimit(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	run := func(name string, underRace bool, f func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			if testing.Short() {
				t.Skip("million-comment input; skipped with -short")
			}
			if raceEnabled && !underRace {
				t.Skip("million-comment input is too slow under the race detector; runs without -race")
			}
			f(t)
		})
	}

	run("comments_only_at_limit", false, func(t *testing.T) {
		if _, err := tkz.TokenizeString(strings.Repeat("--\n", MaxTokens)); err != nil {
			t.Fatalf("%d comments: %v", MaxTokens, err)
		}
		if len(tkz.Comments) != MaxTokens {
			t.Fatalf("collected %d comments, want %d", len(tkz.Comments), MaxTokens)
		}
	})
	run("comments_only_over_limit", false, func(t *testing.T) {
		for _, unit := range []string{"--\n", "/**/\n"} {
			_, err := tkz.TokenizeString(strings.Repeat(unit, MaxTokens+1))
			wantTokenLimit(t, err, MaxTokens+1)
		}
	})
	run("comments_then_tokens_at_limit", false, func(t *testing.T) {
		// MaxTokens-2 comments + 2 tokens = MaxTokens.
		toks, err := tkz.TokenizeString(strings.Repeat("--\n", MaxTokens-2) + "SELECT 1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(toks) != 3 {
			t.Fatalf("got %d tokens, want 3", len(toks))
		}
	})
	run("comments_then_tokens_over_limit", true, func(t *testing.T) {
		_, err := tkz.TokenizeString(strings.Repeat("--\n", MaxTokens-1) + "SELECT 1")
		wantTokenLimit(t, err, MaxTokens)
	})
	run("interleaved_over_limit", false, func(t *testing.T) {
		// Each line is one token and one comment; tokens alone stay at
		// half the limit.
		lines := MaxTokens/2 + 1
		_, err := tkz.TokenizeString(strings.Repeat("a -- c\n", lines))
		wantTokenLimit(t, err, 0)
	})
	run("interleaved_at_limit", false, func(t *testing.T) {
		if _, err := tkz.TokenizeString(strings.Repeat("a -- c\n", MaxTokens/2)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	run("reusable_after_limit", true, func(t *testing.T) {
		_, err := tkz.TokenizeString(strings.Repeat("/**/", MaxTokens+1))
		wantTokenLimit(t, err, 1)
		toks, err := tkz.TokenizeString("SELECT /* c */ 1")
		if err != nil {
			t.Fatalf("unexpected error after limit: %v", err)
		}
		if len(toks) != 3 || len(tkz.Comments) != 1 {
			t.Fatalf("got %d tokens and %d comments, want 3 and 1", len(toks), len(tkz.Comments))
		}
	})
}

// TestTokenizer_ResetDropsLargeComments checks that Reset keeps a small
// Comments backing array for reuse but drops one grown past
// maxRetainedComments.
func TestTokenizer_ResetDropsLargeComments(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tkz.TokenizeString(strings.Repeat("-- c\n", 10) + "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	tkz.Reset()
	if len(tkz.Comments) != 0 || cap(tkz.Comments) == 0 {
		t.Fatalf("small Comments: len=%d cap=%d, want len 0 and capacity kept", len(tkz.Comments), cap(tkz.Comments))
	}

	if _, err := tkz.TokenizeString(strings.Repeat("-- c\n", 4*maxRetainedComments) + "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	tkz.Reset()
	if tkz.Comments != nil {
		t.Fatalf("large Comments kept after Reset: len=%d cap=%d", len(tkz.Comments), cap(tkz.Comments))
	}

	// The tokenizer still collects comments afterwards.
	if _, err := tkz.TokenizeString("SELECT 1 /* x */"); err != nil {
		t.Fatal(err)
	}
	if len(tkz.Comments) != 1 || tkz.Comments[0].Text != "/* x */" {
		t.Fatalf("unexpected comments after Reset: %+v", tkz.Comments)
	}
}
