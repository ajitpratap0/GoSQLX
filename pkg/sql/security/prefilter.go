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
	"regexp"
	"regexp/syntax"
	"sync"
	"unicode"
	"unicode/utf8"
)

// compiledPattern pairs a compiled regex with the literal prefilter derived from it.
//
// lits holds lowercase ASCII substrings that every match of re must contain. They
// are derived at init from the regex syntax tree by requiredLiterals, never written
// by hand. When the case-folded input (see foldASCII) does not contain all of them,
// the regex cannot match and is skipped. A nil or empty lits means the regex always
// runs.
type compiledPattern struct {
	re   *regexp.Regexp
	lits [][]byte
}

// compilePattern compiles expr and derives its literal prefilter.
func compilePattern(expr string) compiledPattern {
	return compiledPattern{re: regexp.MustCompile(expr), lits: requiredLiterals(expr)}
}

// requiredLiterals returns the lowercase ASCII literal runs that every match of expr
// must contain, in first-seen order and without duplicates.
//
// The walk over the simplified syntax tree is deliberately conservative: only
// literals that are mandatory in every match contribute. Concatenation and capture
// groups extend the current run; one-or-more repetitions (and counted repetitions
// with Min >= 1) contribute their body as separate runs; every other operator
// (character classes, any-char, star, optional, alternation and all zero-width
// assertions) ends the current run without contributing. Runs containing a
// non-ASCII rune are discarded entirely, because the soundness argument of
// foldASCII only covers ASCII literals.
//
// It returns nil (no prefilter, the regex always runs) if expr does not parse; this
// cannot happen for expressions that already passed regexp.MustCompile.
func requiredLiterals(expr string) [][]byte {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()

	var (
		out         [][]byte
		cur         []byte
		hasNonASCII bool
	)
	flush := func() {
		if len(cur) > 0 && !hasNonASCII {
			dup := false
			for _, l := range out {
				if bytes.Equal(l, cur) {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, cur)
			}
		}
		cur = nil
		hasNonASCII = false
	}

	var walk func(re *syntax.Regexp)
	walk = func(re *syntax.Regexp) {
		switch re.Op {
		case syntax.OpLiteral:
			for _, r := range re.Rune {
				if r >= utf8.RuneSelf {
					hasNonASCII = true
					continue
				}
				cur = append(cur, byte(unicode.ToLower(r)))
			}
		case syntax.OpConcat:
			for _, sub := range re.Sub {
				walk(sub)
			}
		case syntax.OpCapture:
			walk(re.Sub[0])
		case syntax.OpPlus:
			flush()
			walk(re.Sub[0])
			flush()
		case syntax.OpRepeat:
			flush()
			if re.Min >= 1 {
				walk(re.Sub[0])
			}
			flush()
		default:
			// CharClass, AnyChar, AnyCharNotNL, Star, Quest, Alternate, the
			// zero-width assertions and EmptyMatch: run breakers that contribute
			// no required literal.
			flush()
		}
	}
	walk(re)
	flush()
	return out
}

// foldASCII appends a case-folded copy of s to dst and returns the result.
//
// ASCII letters are lowercased. The two non-ASCII runes whose Unicode simple-fold
// orbit contains an ASCII letter are mapped to that letter: U+017F LATIN SMALL
// LETTER LONG S to 's' and U+212A KELVIN SIGN to 'k'. Every other byte sequence,
// including invalid UTF-8, is copied unchanged.
//
// Invariant: for any ASCII literal L, if `(?i)L` (or a case-sensitive L) matches
// somewhere in s, then bytes.Contains(foldASCII(nil, s), lower(L)) is true. This
// holds because {U+017F, U+212A} are the only non-ASCII runes that Go's (?i)
// treats as equal to an ASCII letter (enforced by TestFoldASCII_Completeness).
func foldASCII(dst []byte, s string) []byte {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			dst = append(dst, c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case 0x017F: // LATIN SMALL LETTER LONG S
			dst = append(dst, 's')
		case 0x212A: // KELVIN SIGN
			dst = append(dst, 'k')
		default:
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return dst
}

// containsAll reports whether folded contains every literal in lits. An empty
// lits always passes.
func containsAll(folded []byte, lits [][]byte) bool {
	for _, l := range lits {
		if !bytes.Contains(folded, l) {
			return false
		}
	}
	return true
}

// maxPooledFoldBuf bounds the capacity of fold buffers returned to the pool so a
// single huge input does not pin memory indefinitely.
const maxPooledFoldBuf = 64 << 10

// foldBufPool recycles the case-folded copy of the input used by the prefilters.
//
// Ownership: a buffer is owned by the ScanSQL call that got it, is only ever
// passed to bytes.Contains, is never stored in a Finding or ScanResult (finding
// descriptions are substrings of the original SQL), and is returned with defer.
// A pooled buffer therefore carries no observable state across uses: its length is
// reset on Put, and stale bytes beyond the length are overwritten by the next
// foldASCII before they can be read.
var foldBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 256)
		return &b
	},
}

// getFoldBuf returns an empty fold buffer from the pool.
func getFoldBuf() *[]byte {
	bp, ok := foldBufPool.Get().(*[]byte)
	if !ok || bp == nil {
		b := make([]byte, 0, 256)
		return &b
	}
	return bp
}

// putFoldBuf returns a fold buffer to the pool unless it grew too large.
func putFoldBuf(bp *[]byte) {
	if bp == nil || cap(*bp) > maxPooledFoldBuf {
		return
	}
	*bp = (*bp)[:0]
	foldBufPool.Put(bp)
}
