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

package security

import (
	"bytes"
	"math/rand"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func naiveLiteralPresence(m *litMatcher, s string) litSet {
	folded := foldASCII(nil, s)
	var present litSet
	for i, l := range m.lits {
		if bytes.Contains(folded, []byte(l)) {
			present.add(i)
		}
	}
	return present
}

func checkLiteralPresence(t testing.TB, m *litMatcher, s string) {
	t.Helper()
	if got, want := m.scan(s), naiveLiteralPresence(m, s); got != want {
		t.Fatalf("scan(%q) = %x, want %x", s, got, want)
	}
}

func TestLitMatcher_PresenceExact(t *testing.T) {
	NewScanner()
	for _, s := range equivalenceCorpus(t) {
		checkLiteralPresence(t, literalMatcher, s)
	}
	for _, a := range literalMatcher.lits {
		checkLiteralPresence(t, literalMatcher, a)
		for _, b := range literalMatcher.lits {
			checkLiteralPresence(t, literalMatcher, a+b)
			if a[len(a)-1] == b[0] {
				checkLiteralPresence(t, literalMatcher, a+b[1:])
			}
		}
	}
	// Failure-chain outputs are tested independently of the production dictionary.
	overlap := newLitMatcher([]string{"he", "she", "hers", "his", "/", "/*", "*/", "pg_sleep", "sleep", "union", "null"})
	for _, s := range []string{"ushers", "/*/", "pg_sleep", "unionull"} {
		checkLiteralPresence(t, overlap, s)
	}
	fragments := append([]string{}, literalMatcher.lits...)
	for _, s := range literalMatcher.lits {
		fragments = append(fragments, strings.ToUpper(s))
	}
	fragments = append(fragments, "ſ", "K", "K", "\xc5", "\xbf", "\xe2\x84", "\xaa", " ", ";", "\x00")
	n := 200000
	if raceEnabled || testing.Short() {
		n = 20000
	}
	rng := rand.New(rand.NewSource(608))
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := rng.Intn(10); j > 0; j-- {
			b.WriteString(fragments[rng.Intn(len(fragments))])
		}
		checkLiteralPresence(t, literalMatcher, b.String())
	}
}

func TestLitMatcher_FoldOrbit(t *testing.T) {
	letters := strings.Split("abcdefghijklmnopqrstuvwxyz", "")
	m := newLitMatcher(letters)
	for i := 0; i < 26; i++ {
		c := rune('a' + i)
		for r := unicode.SimpleFold(c); r != c; r = unicode.SimpleFold(r) {
			if r < utf8.RuneSelf {
				continue
			}
			var want litSet
			want.add(i)
			if got := m.scan(string(r)); got != want {
				t.Errorf("scan(U+%04X)=%x, want %x", r, got, want)
			}
		}
	}
	for _, s := range []string{"\xc5", "\xe2", "\xe2\x84", "\xbf", "\x84\xaa", "\xff", "\xc5\x00", "\xe2\x84\x00"} {
		if got := m.scan(s); got != (litSet{}) {
			t.Errorf("scan(%q)=%x, want no letters", s, got)
		}
	}
}

// generatedRegexMatch uses a different representation from CNF derivation and
// validates every retained sample with RE2 before checking the necessary filter.
func generatedRegexMatch(rng *rand.Rand, re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				if rng.Intn(2) == 0 {
					r = unicode.ToLower(r)
				} else {
					r = unicode.ToUpper(r)
				}
				if rng.Intn(12) == 0 {
					switch unicode.ToLower(r) {
					case 's':
						r = 'ſ'
					case 'k':
						r = 'K'
					}
				}
			}
			b.WriteRune(r)
		}
		return b.String()
	case syntax.OpCharClass:
		var ascii []rune
		for i := 0; i < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1] && r < 128; r++ {
				ascii = append(ascii, r)
			}
		}
		if len(ascii) > 0 && rng.Intn(10) != 0 {
			return string(ascii[rng.Intn(len(ascii))])
		}
		i := 2 * rng.Intn(len(re.Rune)/2)
		return string(re.Rune[i] + rune(rng.Int63n(int64(re.Rune[i+1]-re.Rune[i])+1)))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return string("a0 \v!"[rng.Intn(5)])
	case syntax.OpCapture:
		return generatedRegexMatch(rng, re.Sub[0])
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			b.WriteString(generatedRegexMatch(rng, sub))
		}
		return b.String()
	case syntax.OpAlternate:
		return generatedRegexMatch(rng, re.Sub[rng.Intn(len(re.Sub))])
	case syntax.OpQuest:
		if rng.Intn(2) == 0 {
			return ""
		}
		return generatedRegexMatch(rng, re.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		min, max := 0, 3
		if re.Op == syntax.OpPlus {
			min, max = 1, 4
		}
		if re.Op == syntax.OpRepeat {
			min, max = re.Min, re.Min+3
			if re.Max >= 0 && max > re.Max {
				max = re.Max
			}
		}
		n := min + rng.Intn(max-min+1)
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(generatedRegexMatch(rng, re.Sub[0]))
		}
		return b.String()
	default:
		// EmptyMatch, assertions and NoMatch emit no bytes. RE2 rejects samples
		// that do not satisfy a zero-width assertion or an impossible expression.
		return ""
	}
}

func TestRequiredLiterals_SoundOnGeneratedMatches(t *testing.T) {
	all := allCompiledPatterns(t)
	n := 2000
	if raceEnabled || testing.Short() {
		n = 200
	}
	rng := rand.New(rand.NewSource(60802))
	check := func(t *testing.T, p compiledPattern, m *litMatcher) {
		t.Helper()
		tree, err := syntax.Parse(p.re.String(), syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		tree = tree.Simplify()
		accepted := 0
		for tries := 0; accepted < n && tries < n*100; tries++ {
			sample := generatedRegexMatch(rng, tree)
			if !p.re.MatchString(sample) {
				continue
			}
			accepted++
			context := generatedRegexMatch(rng, &syntax.Regexp{Op: syntax.OpStar, Sub: []*syntax.Regexp{{Op: syntax.OpAnyChar}}})
			for _, s := range []string{sample, context + sample + context} {
				if !p.filter.pass(m.scan(s)) {
					t.Fatalf("%s rejects generated match %q (sample %q)", p.re, s, sample)
				}
			}
		}
		if accepted < n {
			t.Fatalf("%s: accepted only %d of required %d samples", p.re, accepted, n)
		}
	}
	for _, p := range all {
		t.Run("production/"+p.re.String(), func(t *testing.T) { check(t, p, literalMatcher) })
	}
	for _, tt := range literalGoldenCases {
		if _, err := regexp.Compile(tt.expr); err != nil {
			continue
		}
		t.Run("synthetic/"+tt.expr, func(t *testing.T) {
			if tt.expr == `foo\bbar` {
				t.Skip("empty language: no ASCII word boundary exists between o and b; golden still pins derivation")
			}
			p := compilePattern(tt.expr)
			m := buildLiteralMatcher([]*compiledPattern{&p})
			check(t, p, m)
		})
	}
	// Check every explicit security alternative without relying on random coverage.
	src, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`\(\?:FROM\|JOIN\)\[\\s\\v\]\+\(\?:([A-Za-z0-9_|]+)\)\[\\s\\v\]\*\\\(`).FindSubmatch(src)
	if match == nil {
		t.Fatal("ClickHouse alternation missing")
	}
	var positives []string
	for _, name := range strings.Split(string(match[1]), "|") {
		for _, verb := range []string{"FROM", "JOIN"} {
			positives = append(positives, verb+" "+name+"(")
		}
	}
	for _, schema := range []string{"information_schema", "pg_catalog", "mysql", "sys."} {
		suffix := ".tables"
		if schema == "sys." {
			suffix = "tables"
		}
		positive := "UNION SELECT x FROM " + schema + suffix
		for _, p := range all {
			if strings.Contains(p.re.String(), "information_schema|pg_catalog") {
				if !p.re.MatchString(positive) {
					t.Fatalf("system-schema pattern does not match %q", positive)
				}
				if !p.filter.pass(literalMatcher.scan(positive)) {
					t.Fatalf("system-schema filter rejects %q", positive)
				}
			}
		}
		positives = append(positives, positive)
	}
	for _, s := range positives {
		matched := false
		for _, p := range all {
			if p.re.MatchString(s) {
				matched = true
				if !p.filter.pass(literalMatcher.scan(s)) {
					t.Errorf("%s rejects explicit alternative %q", p.re, s)
				}
			}
		}
		if !matched {
			t.Errorf("explicit alternative %q matches no production regex", s)
		}
	}
}

func TestLitMatcher_Capacity(t *testing.T) {
	NewScanner()
	literals, states := len(literalMatcher.lits), len(literalMatcher.out)
	t.Logf("literals=%d states=%d classes=%d", literals, states, literalMatcher.nclass)
	if literals > 128 {
		t.Errorf("%d literals exceed 128", literals)
	}
	if states > 65535 {
		t.Errorf("%d states exceed 65535", states)
	}
}
