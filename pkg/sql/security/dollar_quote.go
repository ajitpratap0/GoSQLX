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

// stripDollarQuotedStrings removes bodies of PostgreSQL ($$ and $tag$) and
// Snowflake ($$) quotes outside strings, identifiers and comments. Ambiguous
// escapes, block nesting and bracket identifiers must permit an opener in every
// interpretation before text
// is hidden. ScanSQL has no dialect: MySQL can use $x$ as an identifier, so a
// MySQL-only payload of that shape is still stripped.
func stripDollarQuotedStrings(sql string) string {
	if strings.IndexByte(sql, '$') < 0 || !hasDollarOpener(sql) {
		return sql
	}
	// Cross product of escapes, nesting, bracket identifiers, hash comments and
	// PostgreSQL E-string-only escapes.
	var states [32]sqlLexState
	resetDollarStates(&states)
	var out strings.Builder
	start := 0
	for i := 0; i < len(sql); i++ {
		code := true
		for j := range states {
			code = code && states[j].code()
		}
		if code && sql[i] == '$' && (i == 0 || !identifierByte(sql[i-1])) {
			if end := dollarTagEnd(sql, i); end != 0 {
				tag := sql[i:end]
				closeAt := strings.Index(sql[end:], tag)
				if closeAt < 0 {
					break
				}
				if start == 0 {
					out.Grow(len(sql))
				}
				out.WriteString(sql[start:end])
				out.WriteString(tag)
				i = end + closeAt + len(tag) - 1
				start = i + 1
				resetDollarStates(&states)
				continue
			}
		}
		for j := range states {
			states[j].step(sql, i, j&1 != 0, j&2 != 0, j&8 != 0, j&4 != 0)
		}
	}
	if start == 0 {
		return sql
	}
	out.WriteString(sql[start:])
	return out.String()
}

func resetDollarStates(states *[32]sqlLexState) {
	for j := range states {
		states[j] = sqlLexState{eOnly: j&16 != 0}
	}
}

// hasDollarOpener reports whether any '$' could open a dollar quote (the same
// opener condition the lexer loop below uses); when none can, the 32-state
// lexer can never strip anything, so it is skipped.
func hasDollarOpener(sql string) bool {
	for i := strings.IndexByte(sql, '$'); i >= 0; {
		if (i == 0 || !identifierByte(sql[i-1])) && dollarTagEnd(sql, i) != 0 {
			return true
		}
		j := strings.IndexByte(sql[i+1:], '$')
		if j < 0 {
			return false
		}
		i += 1 + j
	}
	return false
}
