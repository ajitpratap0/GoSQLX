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

import "strings"

func withGuard(p compiledPattern, g func(string) bool) compiledPattern { p.guard = g; return p }

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func identRunByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

// hasEqualIdentPair is a necessary condition for the identifier tautology
// capture pattern: around some '=', a suffix of the left identifier run equals
// (case-insensitively) a prefix of the right run. The runs include every byte
// accepted by [a-z_][a-z0-9_.]*; sqlWhitespace includes [\s\v]. Trying all
// suffix/prefix lengths up to 51 permits the regex's unanchored and partial
// matches: initTautologyCapturePatterns uses [a-z_][a-z0-9_.]{0,50}, so each
// ASCII capture has at most 51 bytes. A confirmed equality cannot require a
// longer comparison. Bounding k also keeps comparison work per '=' constant
// rather than quadratic in the lengths of unequal identifier runs.
// Call only for ASCII input: (?i) also folds U+017F (long s) to S and U+212A
// (Kelvin sign) to K, which these byte runs cannot recognize.
func hasEqualIdentPair(sql string) bool {
	for off := 0; off < len(sql); {
		r := strings.IndexByte(sql[off:], '=')
		if r < 0 {
			return false
		}
		eq := off + r
		off = eq + 1
		l, rr := eq, eq+1
		for l > 0 && sqlWhitespace(sql[l-1]) {
			l--
		}
		for rr < len(sql) && sqlWhitespace(sql[rr]) {
			rr++
		}
		s, e := l, rr
		for s > 0 && identRunByte(sql[s-1]) {
			s--
		}
		for e < len(sql) && identRunByte(sql[e]) {
			e++
		}
		left, right := sql[s:l], sql[rr:e]
		for k := 1; k <= 51 && k <= len(left) && k <= len(right); k++ {
			if strings.EqualFold(left[len(left)-k:], right[:k]) {
				return true
			}
		}
	}
	return false
}

var chNames = map[string]bool{}

func init() {
	for _, n := range strings.Split("url|urlcluster|file|filecluster|remote|remotesecure|s3|s3cluster|gcs|azureblobstorage|hdfs|hdfscluster|jdbc|odbc|mysql|postgresql|mongodb|redis|sqlite|executable", "|") {
		chNames[n] = true
	}
}

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// hasTableFnCandidate: some '(' is preceded by optional whitespace, a listed
// table-function name as a whole word, and a whitespace byte. Any match of the
// FROM/JOIN regex must contain that suffix; the regex still confirms FROM/JOIN.
// sqlWhitespace includes exactly [\s\v], and the longest listed name fits buf.
// Call only for ASCII input: (?i) can match U+017F (long s) as S and U+212A
// (Kelvin sign) as K; ASCII name scanning would otherwise miss such matches.
func hasTableFnCandidate(sql string) bool {
	var buf [16]byte
	for off := 0; off < len(sql); {
		r := strings.IndexByte(sql[off:], '(')
		if r < 0 {
			return false
		}
		p := off + r
		off = p + 1
		e := p
		for e > 0 && sqlWhitespace(sql[e-1]) {
			e--
		}
		s := e
		for s > 0 && wordByte(sql[s-1]) {
			s--
		}
		if e-s < 2 || e-s > len(buf) || s == 0 || !sqlWhitespace(sql[s-1]) {
			continue
		}
		for i := s; i < e; i++ {
			c := sql[i]
			if 'A' <= c && c <= 'Z' {
				c += 32
			}
			buf[i-s] = c
		}
		if chNames[string(buf[:e-s])] {
			return true
		}
	}
	return false
}
