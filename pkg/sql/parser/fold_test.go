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

package parser

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestEqualsUpper_MatchesToUpper(t *testing.T) {
	tests := []struct {
		name, s, upper string
		want           bool
	}{
		{"upper", "LIKE", "LIKE", true},
		{"lower", "like", "LIKE", true},
		{"mixed", "LiKe", "LIKE", true},
		{"both empty", "", "", true},
		{"empty s", "", "LIKE", false},
		{"empty upper", "like", "", false},
		{"s longer", "LIKEX", "LIKE", false},
		{"s shorter", "LIK", "LIKE", false},
		{"different", "ILIKE", "LIKE", false},
		{"dotless i to I", "lıke", "LIKE", true},
		{"dotless i in IN", "ın", "IN", true},
		{"kelvin sign not folded by ToUpper", "liKe", "LIKE", false},
		{"long s to S", "ſample", "SAMPLE", true},
		{"invalid utf8", "li\xffe", "LIKE", false},
		{"truncated utf8", "like\xc4", "LIKE", false},
		{"non-ascii extra", "likeé", "LIKE", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalsUpper(tt.s, tt.upper); got != tt.want {
				t.Errorf("equalsUpper(%q, %q) = %v, want %v", tt.s, tt.upper, got, tt.want)
			}
			if want := strings.ToUpper(tt.s) == tt.upper; want != tt.want {
				t.Errorf("test table disagrees with ToUpper for %q: %v", tt.s, want)
			}
		})
	}

	t.Run("randomized", func(t *testing.T) {
		rng := rand.New(rand.NewSource(554))
		alphabet := []string{"l", "L", "i", "I", "k", "K", "e", "E", "s", "S", "n", "N",
			"ı", "K", "ſ", "İ", "é", "\xff", "x"}
		uppers := []string{"LIKE", "IN", "SAMPLE", "KS", "I", ""}
		for n := 0; n < 5000; n++ {
			var b strings.Builder
			for i, l := 0, rng.Intn(7); i < l; i++ {
				b.WriteString(alphabet[rng.Intn(len(alphabet))])
			}
			s := b.String()
			for _, up := range uppers {
				if got, want := equalsUpper(s, up), strings.ToUpper(s) == up; got != want {
					t.Fatalf("equalsUpper(%q, %q) = %v, ToUpper says %v", s, up, got, want)
				}
			}
		}
	})
}

func TestEqualsUpper_NoAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	inputs := []string{"like", "LIKE", "lıke", "liKe", "ſample", "li\xffe", "", "tablesample"}
	n := testing.AllocsPerRun(100, func() {
		for _, s := range inputs {
			_ = equalsUpper(s, "LIKE")
			_ = equalsUpper(s, "SAMPLE")
		}
	})
	if n != 0 {
		t.Errorf("equalsUpper allocated %v times per run, want 0", n)
	}
}

// TestParse_UnicodeCaseFoldKeywordsPreserved guards behaviour that predates
// the #554 allocation work: the tokenizer classifies keywords with
// strings.ToUpper, so a dotless i spells LIKE and IN.
func TestParse_UnicodeCaseFoldKeywordsPreserved(t *testing.T) {
	for _, sql := range []string{
		"SELECT a FROM t WHERE x NOT lıke 'a'",
		"SELECT a FROM t WHERE x NOT ın (1)",
	} {
		tkz := tokenizer.GetTokenizer()
		toks, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			tokenizer.PutTokenizer(tkz)
			t.Fatalf("tokenize %q: %v", sql, err)
		}
		tokens := append(toks[:0:0], toks...)
		tokenizer.PutTokenizer(tkz)

		p := NewParser()
		tree, err := p.ParseFromModelTokens(tokens)
		p.Release()
		if err != nil {
			t.Errorf("parse %q: %v", sql, err)
			continue
		}
		ast.ReleaseAST(tree)
	}
}
