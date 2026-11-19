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
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// compiledPattern pairs a regex with its necessary-condition CNF literal filter.
// Each clause requires at least one lowercase ASCII substring. The matcher fills
// filter once at initialization; cnf is retained for diagnostics and tests.
type compiledPattern struct {
	re     *regexp.Regexp
	cnf    [][]string
	filter litFilter
	guard  func(string) bool // optional exact necessary condition (ASCII input only)
}

func compilePattern(expr string) compiledPattern {
	return compiledPattern{re: regexp.MustCompile(expr), cnf: requiredLiterals(expr)}
}

const maxExact = 16

type literalInfo struct {
	exact []string // nil = unknown
	cnf   [][]string
}

// requiredLiterals derives an AND of any-of clauses that every regex match must
// contain. Exact alternatives are crossed through concatenations up to maxExact;
// unknown text breaks a run, while assertions preserve it. Non-ASCII literal runs
// are discarded conservatively. Invalid expressions have no filter.
func requiredLiterals(expr string) [][]string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	in := deriveLiteralInfo(re)
	if in.exact != nil {
		in.cnf = appendLiteralClause(in.cnf, in.exact)
	}
	return normalizeLiteralCNF(in.cnf)
}

func crossLiterals(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			out = appendUniqueLiteral(out, x+y)
		}
	}
	return out
}

func appendUniqueLiteral(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func normalizeLiteralClause(set []string) []string {
	var out []string
	for i, s := range set {
		if s == "" {
			return nil
		}
		redundant := false
		for j, t := range set {
			if i != j && strings.Contains(s, t) && (len(t) < len(s) || j < i) {
				redundant = true
				break
			}
		}
		if !redundant {
			out = appendUniqueLiteral(out, s)
		}
	}
	return out
}

func appendLiteralClause(cnf [][]string, set []string) [][]string {
	c := normalizeLiteralClause(set)
	if len(c) == 0 {
		return cnf
	}
	return append(cnf, c)
}

// literalClauseImplies reports whether every member of d contains a member of c.
func literalClauseImplies(d, c []string) bool {
	for _, x := range d {
		ok := false
		for _, y := range c {
			if strings.Contains(x, y) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func normalizeLiteralCNF(cnf [][]string) [][]string {
	var out [][]string
	for i, c := range cnf {
		drop := false
		for j, d := range cnf {
			if i == j {
				continue
			}
			if literalClauseImplies(d, c) && (!literalClauseImplies(c, d) || j < i) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, c)
		}
	}
	return out
}

func bestLiteralClause(cnf [][]string) []string {
	var best []string
	for _, c := range cnf {
		if best == nil || len(c) < len(best) {
			best = c
		}
	}
	return best
}

func deriveLiteralInfo(re *syntax.Regexp) literalInfo {
	switch re.Op {
	case syntax.OpLiteral:
		var b []byte
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return literalInfo{}
			}
			b = append(b, byte(unicode.ToLower(r)))
		}
		return literalInfo{exact: []string{string(b)}}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return literalInfo{exact: []string{""}}
	case syntax.OpCapture:
		return deriveLiteralInfo(re.Sub[0])
	case syntax.OpConcat:
		cur := []string{""}
		var cnf [][]string
		allExact := true
		var flat []*syntax.Regexp
		var flatten func(subs []*syntax.Regexp)
		flatten = func(subs []*syntax.Regexp) {
			for _, sub := range subs {
				for sub.Op == syntax.OpCapture {
					sub = sub.Sub[0]
				}
				if sub.Op == syntax.OpConcat {
					flatten(sub.Sub)
					continue
				}
				flat = append(flat, sub)
			}
		}
		flatten(re.Sub)
		for _, sub := range flat {
			x := deriveLiteralInfo(sub)
			if x.exact != nil {
				if len(cur)*len(x.exact) <= maxExact {
					cur = crossLiterals(cur, x.exact)
				} else {
					allExact = false
					cnf = appendLiteralClause(cnf, cur)
					cur = x.exact
				}
				continue
			}
			allExact = false
			cnf = appendLiteralClause(cnf, cur)
			cnf = append(cnf, x.cnf...)
			cur = []string{""}
		}
		if allExact {
			return literalInfo{exact: cur}
		}
		return literalInfo{cnf: appendLiteralClause(cnf, cur)}
	case syntax.OpAlternate:
		var union []string
		exactOK := true
		var clause []string
		clauseOK := true
		for _, sub := range re.Sub {
			x := deriveLiteralInfo(sub)
			if x.exact != nil {
				for _, s := range x.exact {
					union = appendUniqueLiteral(union, s)
				}
				clause = append(clause, x.exact...)
				continue
			}
			exactOK = false
			b := bestLiteralClause(x.cnf)
			if b == nil {
				clauseOK = false
			}
			clause = append(clause, b...)
		}
		if exactOK && len(union) <= maxExact {
			return literalInfo{exact: union}
		}
		if !clauseOK {
			return literalInfo{}
		}
		return literalInfo{cnf: appendLiteralClause(nil, clause)}
	case syntax.OpQuest:
		x := deriveLiteralInfo(re.Sub[0])
		if x.exact != nil && len(x.exact)+1 <= maxExact {
			return literalInfo{exact: appendUniqueLiteral(append([]string(nil), x.exact...), "")}
		}
		return literalInfo{}
	case syntax.OpPlus:
		x := deriveLiteralInfo(re.Sub[0])
		if x.exact != nil {
			return literalInfo{cnf: appendLiteralClause(nil, x.exact)}
		}
		return literalInfo{cnf: x.cnf}
	case syntax.OpRepeat:
		if re.Min < 1 {
			return literalInfo{}
		}
		x := deriveLiteralInfo(re.Sub[0])
		if x.exact != nil {
			return literalInfo{cnf: appendLiteralClause(nil, x.exact)}
		}
		return literalInfo{cnf: x.cnf}
	}
	return literalInfo{}
}

// litSet records the presence of up to 128 interned ASCII literals.
type litSet [2]uint64

func (s *litSet) add(id int) { s[id/64] |= 1 << (id % 64) }

func (s litSet) hasAll(required litSet) bool {
	return s[0]&required[0] == required[0] && s[1]&required[1] == required[1]
}

func (s litSet) intersects(other litSet) bool {
	return s[0]&other[0] != 0 || s[1]&other[1] != 0
}

// litFilter combines singleton clauses into all and keeps disjunctions in anyOf.
type litFilter struct {
	all   litSet
	anyOf []litSet
}

func (f *litFilter) pass(present litSet) bool {
	if !present.hasAll(f.all) {
		return false
	}
	for _, clause := range f.anyOf {
		if !present.intersects(clause) {
			return false
		}
	}
	return true
}

// scanPrefilter is passed by value; its zero value disables filters and guards.
type scanPrefilter struct {
	on      bool
	present litSet
}
