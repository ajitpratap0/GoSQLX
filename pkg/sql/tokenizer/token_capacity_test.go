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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
)

// capacityCase is a named input for the token-capacity estimator tests.
type capacityCase struct {
	name  string
	input string
	dense bool // dense inputs must also satisfy the tightness bound
}

// inList builds "SELECT a,b,c FROM t WHERE id IN (1,2,...,n)" with no spaces
// after commas, the worst case for a len/4 guess.
func inList(n int) string {
	var sb strings.Builder
	sb.WriteString("SELECT a,b,c FROM t WHERE id IN (")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%d", i%10)
	}
	sb.WriteString(")")
	return sb.String()
}

func capacityCases(t *testing.T) []capacityCase {
	t.Helper()
	cases := []capacityCase{
		{"empty", "", false},
		{"single_word", "x", false},
		{"in_list_compact_small", "SELECT a,b FROM t WHERE x IN (1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7,8)", true},
		{"in_list_compact_mid", inList(30), true},
		{"in_list_1k", inList(1000), true},
		{"deeply_nested", string(deeplyNestedSQL), true},
		{"wide_joins", string(wideJoinSQL), false},
		{"large_in_clause", string(largeInClauseSQL), true},
		{"complex_analytics", string(complexAnalyticsSQL), false},
		{"generated_10kb", string(generateComplexSQL(10000)), true},
		{"unicode", "SELECT 用户.名前, café FROM пользователи WHERE 名前 = 'こんにちは'", false},
		{"multi_char_operators", "SELECT a>=b, a<>b, a||b, j->'k', j@>'{}', x::int FROM t WHERE a<=b AND c!=d", false},
		{"numeric_literals", "SELECT 1.5, 1e10, 2.5E-3, .5, 10 FROM t", false},
		{"quoted_strings_with_spaces", "SELECT 'hello world and more words', \"quoted ident\" FROM t", false},
		{"block_comment", "SELECT /* a long block comment with many words */ 1 FROM t", false},
		{"line_comment", "SELECT 1 -- trailing comment with words\nFROM t", false},
		{"crlf_lines", "SELECT a,\r\n b\r\nFROM t\r\n", false},
	}

	var files []string
	for _, pattern := range []string{
		"../../../testdata/*/*.sql",
		"../../../testdata/*/*/*.sql",
		"../parser/testdata/*.sql",
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %q: %v", pattern, err)
		}
		files = append(files, m...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		cases = append(cases, capacityCase{name: "file/" + filepath.ToSlash(f), input: string(data)})
	}
	return cases
}

// naiveLineStarts is the reference implementation of the line-start scan.
func naiveLineStarts(input []byte) []int {
	starts := []int{0}
	for i, b := range input {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func TestPrescan_LineStarts(t *testing.T) {
	inputs := []string{
		"",
		"a",
		"a\nb",
		"a\r\nb\n",
		"\n\n",
		"SELECT 1 -- c\nFROM t",
	}
	for _, in := range inputs {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			tkz, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tkz.input = []byte(in)
			tkz.lineStarts = append(tkz.lineStarts[:0], 0)
			tkz.prescan()
			if want := naiveLineStarts([]byte(in)); !reflect.DeepEqual(tkz.lineStarts, want) {
				t.Errorf("lineStarts = %v, want %v", tkz.lineStarts, want)
			}
		})
	}
}

// estimateFor returns prescan's estimate for input using a fresh tokenizer.
func estimateFor(t *testing.T, input string) int {
	t.Helper()
	tkz, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tkz.input = []byte(input)
	tkz.lineStarts = append(tkz.lineStarts[:0], 0)
	return tkz.prescan()
}

func TestTokenCapacityEstimate_UpperBoundAndTight(t *testing.T) {
	for _, tc := range capacityCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			tkz, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tokens, err := tkz.Tokenize([]byte(tc.input))
			if err != nil {
				t.Skipf("Tokenize rejects input: %v", err)
			}
			est := estimateFor(t, tc.input)
			if est < len(tokens) {
				t.Errorf("estimate %d < token count %d: slice would regrow", est, len(tokens))
			}
			if cap(tokens) != est {
				t.Errorf("cap(tokens) = %d, want estimate %d (slice was regrown or not sized by prescan)", cap(tokens), est)
			}
			if tc.dense {
				if limit := len(tokens) + len(tokens)/4 + minTokenCapacity; est > limit {
					t.Errorf("estimate %d too loose for %d tokens (limit %d)", est, len(tokens), limit)
				}
			}
		})
	}
}

func TestTokenCapacity_TokenizeContextMatchesTokenize(t *testing.T) {
	for _, tc := range capacityCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			b, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			want, wantErr := a.Tokenize([]byte(tc.input))
			got, gotErr := b.TokenizeContext(t.Context(), []byte(tc.input))
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("error mismatch: Tokenize=%v TokenizeContext=%v", wantErr, gotErr)
			}
			if wantErr != nil {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("token streams differ")
			}
			if cap(got) != cap(want) {
				t.Errorf("cap mismatch: TokenizeContext=%d Tokenize=%d", cap(got), cap(want))
			}
		})
	}
}

func TestTokenCapacity_PoolReuse(t *testing.T) {
	dense := inList(500)
	sparse := "SELECT   id   FROM   users   WHERE   name   =   'x'\n\n\n"
	seq := []string{dense, sparse, dense, "", dense}

	fresh := func(in string) []spanTok {
		tkz, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return tokenizeSpans(t, tkz, in)
	}

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	for i, in := range seq {
		toks, err := tkz.Tokenize([]byte(in))
		if err != nil {
			t.Fatalf("step %d: Tokenize: %v", i, err)
		}
		if want := naiveLineStarts([]byte(in)); !reflect.DeepEqual(tkz.lineStarts, want) {
			t.Errorf("step %d: lineStarts = %v, want %v", i, tkz.lineStarts, want)
		}
		got := make([]spanTok, 0, len(toks))
		for _, tk := range toks {
			got = append(got, spanTok{
				typ: tk.Token.Type, value: tk.Token.Value,
				sl: tk.Start.Line, sc: tk.Start.Column,
				el: tk.End.Line, ec: tk.End.Column,
			})
		}
		if want := fresh(in); !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d: pooled output differs from fresh tokenizer", i)
		}
		if len(toks) > 0 && i+1 < len(seq) {
			// The next call must not reuse this call's backing array.
			next, err := tkz.Tokenize([]byte(seq[i+1]))
			if err != nil {
				t.Fatalf("step %d: next Tokenize: %v", i, err)
			}
			if len(next) > 0 && &next[0] == &toks[0] {
				t.Errorf("step %d: consecutive results alias the same backing array", i)
			}
		}
	}

	// Correct after Put/Get as well.
	PutTokenizer(tkz)
	tkz = GetTokenizer()
	if got, want := tokenizeSpans(t, tkz, dense), fresh(dense); !reflect.DeepEqual(got, want) {
		t.Fatalf("after Put/Get: pooled output differs from fresh tokenizer")
	}
}

func TestTokenCapacity_Limits(t *testing.T) {
	t.Run("floor", func(t *testing.T) {
		in := "SELECT 1 FROM t"
		if len(in) >= 20 {
			t.Fatalf("test input too long: %d", len(in))
		}
		if est := estimateFor(t, in); est != minTokenCapacity {
			t.Errorf("estimate = %d, want floor %d", est, minTokenCapacity)
		}
	})

	t.Run("cap", func(t *testing.T) {
		if testing.Short() {
			t.Skip("allocates ~72MB")
		}
		in := strings.Repeat("(", MaxTokens+10)
		if est := estimateFor(t, in); est != MaxTokens+1 {
			t.Errorf("estimate = %d, want cap %d", est, MaxTokens+1)
		}
		tkz, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = tkz.Tokenize([]byte(in))
		if err == nil {
			t.Fatal("expected token limit error")
		}
		var e *errors.Error
		if !stderrors.As(err, &e) || e.Code != errors.ErrCodeTokenLimitReached {
			t.Errorf("error = %v, want code %s", err, errors.ErrCodeTokenLimitReached)
		}
	})
}
