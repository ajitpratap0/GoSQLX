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

// litMatcher is an immutable byte-class Aho-Corasick DFA. Class zero resets
// unmatched bytes; ASCII uppercase shares the lowercase class. Outputs include
// every suffix match reached through the failure chain.
type litMatcher struct {
	class  [256]uint8
	nclass int
	next   []uint16 // state*nclass + class -> state
	hasOut []bool
	out    []litSet
	lits   []string
}

func newLitMatcher(lits []string) *litMatcher {
	a := &litMatcher{lits: lits}
	a.nclass = 1
	for _, l := range lits {
		for i := 0; i < len(l); i++ {
			c := l[i]
			if a.class[c] == 0 {
				a.class[c] = uint8(a.nclass)
				a.nclass++
			}
		}
	}
	for c := 'A'; c <= 'Z'; c++ {
		a.class[c] = a.class[c+32]
	}
	// trie
	type node struct {
		next map[uint8]int
		fail int
		out  litSet
	}
	nodes := []node{{next: map[uint8]int{}}}
	for id, l := range lits {
		s := 0
		for i := 0; i < len(l); i++ {
			k := a.class[l[i]]
			n, ok := nodes[s].next[k]
			if !ok {
				nodes = append(nodes, node{next: map[uint8]int{}})
				n = len(nodes) - 1
				nodes[s].next[k] = n
			}
			s = n
		}
		nodes[s].out.add(id)
	}
	a.next = make([]uint16, len(nodes)*a.nclass)
	a.out = make([]litSet, len(nodes))
	a.hasOut = make([]bool, len(nodes))
	// BFS
	queue := []int{}
	for k := 0; k < a.nclass; k++ {
		if n, ok := nodes[0].next[uint8(k)]; ok {
			nodes[n].fail = 0
			a.next[k] = uint16(n)
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		f := nodes[s].fail
		nodes[s].out[0] |= nodes[f].out[0]
		nodes[s].out[1] |= nodes[f].out[1]
		for k := 0; k < a.nclass; k++ {
			if n, ok := nodes[s].next[uint8(k)]; ok {
				nodes[n].fail = int(a.next[f*a.nclass+k])
				a.next[s*a.nclass+k] = uint16(n)
				queue = append(queue, n)
			} else {
				a.next[s*a.nclass+k] = a.next[f*a.nclass+k]
			}
		}
	}
	for i := range nodes {
		a.out[i] = nodes[i].out
		a.hasOut[i] = nodes[i].out != (litSet{})
	}
	return a
}

// scan reports every literal present in s, folding ASCII and the Unicode simple
// fold equivalents U+017F and U+212A inline. Other non-ASCII bytes use class zero,
// which is equivalent to foldASCII for the ASCII-only literal alphabet.
func (a *litMatcher) scan(s string) litSet {
	var pres litSet
	st := 0
	n := a.nclass
	for i := 0; i < len(s); i++ {
		c := s[i]
		k := a.class[c]
		if c >= 0xC5 {
			if c == 0xC5 && i+1 < len(s) && s[i+1] == 0xBF {
				k = a.class['s']
				i++
			} else if c == 0xE2 && i+2 < len(s) && s[i+1] == 0x84 && s[i+2] == 0xAA {
				k = a.class['k']
				i += 2
			}
		}
		st = int(a.next[st*n+int(k)])
		if a.hasOut[st] {
			pres[0] |= a.out[st][0]
			pres[1] |= a.out[st][1]
		}
	}
	return pres
}

// buildLiteralMatcher interns literals in the supplied deterministic pattern
// order and compiles each CNF into masks. Capacity checks are init-time invariants
// on the constant pattern tables, like regexp.MustCompile.
func buildLiteralMatcher(patterns []*compiledPattern) *litMatcher {
	var lits []string
	ids := make(map[string]int)
	for _, p := range patterns {
		for _, clause := range p.cnf {
			for _, lit := range clause {
				if _, ok := ids[lit]; !ok {
					ids[lit] = len(lits)
					lits = append(lits, lit)
				}
			}
		}
	}
	if len(lits) > 128 {
		panic("security: literal matcher exceeds 128 literals")
	}
	matcher := newLitMatcher(lits)
	if len(matcher.out) > 65535 {
		panic("security: literal matcher exceeds 65535 states")
	}
	for _, p := range patterns {
		var filter litFilter
		for _, clause := range p.cnf {
			var mask litSet
			for _, lit := range clause {
				mask.add(ids[lit])
			}
			if len(clause) == 1 {
				filter.all[0] |= mask[0]
				filter.all[1] |= mask[1]
			} else {
				filter.anyOf = append(filter.anyOf, mask)
			}
		}
		p.filter = filter
	}
	return matcher
}
