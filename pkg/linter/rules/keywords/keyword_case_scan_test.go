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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestScanWordsNoAllocations(t *testing.T) {
	const line = "SELECT café, 日本語٢, abcdefghijklmnopqrstuvwxyz FROM users WHERE id = 1 -- select 'from'"
	words := 0
	allocs := testing.AllocsPerRun(100, func() {
		scanWords(line, func(_ string, _ int) { words++ })
	})
	if allocs != 0 {
		t.Fatalf("scanWords allocated %g times per run", allocs)
	}
	if words == 0 {
		t.Fatal("scanWords did not emit any words")
	}
}

func TestKeywordCaseCleanASCIIHasNoAllocations(t *testing.T) {
	for _, style := range []CaseStyle{CaseUpper, CaseLower} {
		t.Run(string(style), func(t *testing.T) {
			sql := "SELECT user_id FROM users WHERE active = TRUE"
			if style == CaseLower {
				sql = "select user_id from users where active = true"
			}
			rule := NewKeywordCaseRule(style)
			ctx := linter.NewContext(sql, "allocation.sql")
			allocs := testing.AllocsPerRun(100, func() {
				violations, err := rule.Check(ctx)
				if err != nil || len(violations) != 0 {
					t.Fatalf("Check: violations=%v err=%v", violations, err)
				}
			})
			if allocs != 0 {
				t.Fatalf("clean ASCII Check allocated %g times per run", allocs)
			}
		})
	}
}

func TestKeywordLengthBound(t *testing.T) {
	for keyword := range sqlKeywords {
		if len(keyword) > maxKeywordLen {
			t.Errorf("keyword %q exceeds stack buffer bound %d", keyword, maxKeywordLen)
		}
	}
}

// wordToken represents a word extracted from a line with its position.
type wordToken struct {
	text   string
	column int // 1-indexed column position in the line
}

// tokenizeLine extracts words from a line with their column positions.
//
// Parses the line character by character, extracting sequences of letters, digits,
// and underscores as words. Skips content inside string literals (both single and
// double quoted) to avoid extracting keywords from SQL string values.
//
// Returns a slice of wordTokens representing each word and its position.
func tokenizeLine(line string) []wordToken {
	words := []wordToken{}
	scanWords(line, func(text string, column int) {
		words = append(words, wordToken{text: text, column: column})
	})
	return words
}
