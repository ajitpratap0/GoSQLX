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

// sqlLexState tracks one dialect interpretation without decoding UTF-8. skip
// consumes the second byte of a doubled quote, escape, or comment delimiter.
type sqlLexState struct {
	quote byte
	line  bool
	depth int
	skip  bool
	// mysqlDash starts a -- comment only before whitespace, a control
	// character or the end of input, as MySQL does; 1--1 is arithmetic there.
	mysqlDash bool
	// eOnly applies backslash escapes only to E'...' strings, as PostgreSQL
	// does when standard_conforming_strings is on; eQuote marks such a string.
	eOnly  bool
	eQuote bool
}

// eStringPrefix reports whether the quote at s[i] is prefixed by a lone E/e.
func eStringPrefix(s string, i int) bool {
	return i > 0 && (s[i-1] == 'E' || s[i-1] == 'e') && (i < 2 || !identifierByte(s[i-2]))
}

// dashComment reports whether "--" at s[i] starts a line comment.
func dashComment(s string, i int, mysqlDash bool) bool {
	if s[i] != '-' || i+1 >= len(s) || s[i+1] != '-' {
		return false
	}
	return !mysqlDash || i+2 >= len(s) || s[i+2] <= ' '
}

// hasMySQLArithmeticDash reports whether some "--" is followed by a byte that
// MySQL would not treat as a comment start.
func hasMySQLArithmeticDash(s string) bool {
	for i := strings.Index(s, "--"); i >= 0; {
		if i+2 < len(s) && s[i+2] > ' ' {
			return true
		}
		next := strings.Index(s[i+1:], "--")
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
}

func (l *sqlLexState) code() bool { return l.quote == 0 && !l.line && l.depth == 0 && !l.skip }

func (l *sqlLexState) step(s string, i int, escapes, nested, hash, brackets bool) {
	if l.skip {
		l.skip = false
		return
	}
	c := s[i]
	var next byte
	if i+1 < len(s) {
		next = s[i+1]
	}
	if l.line {
		if c == '\n' || c == '\r' {
			l.line = false
		}
		return
	}
	if l.depth > 0 {
		if c == '*' && next == '/' {
			l.depth--
			l.skip = true
		} else if nested && c == '/' && next == '*' {
			l.depth++
			l.skip = true
		}
		return
	}
	if l.quote != 0 {
		if (escapes || l.eQuote) && (l.quote == '\'' || l.quote == '"') && c == '\\' && i+1 < len(s) {
			l.skip = true
		} else if c == l.quote {
			if next == c {
				l.skip = true
			} else {
				l.quote = 0
			}
		}
		return
	}
	switch {
	case c == '\'' || c == '"' || c == '`':
		l.quote = c
		l.eQuote = l.eOnly && c == '\'' && eStringPrefix(s, i)
	case brackets && c == '[':
		l.quote = ']'
	case c == '-' && next == '-' && dashComment(s, i, l.mysqlDash), hash && c == '#':
		l.line = true
	case c == '/' && next == '*':
		l.depth = 1
		l.skip = true
	}
}

func identifierByte(c byte) bool {
	return c >= 0x80 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '$'
}

func sqlWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func sqlWordBoundary(sql string, pos int) bool {
	word := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
	}
	before := pos > 0 && word(sql[pos-1])
	after := pos < len(sql) && word(sql[pos])
	return before != after
}

// dollarTagEnd implements $([A-Za-z_][A-Za-z0-9_]*)?$ without a regex.
func dollarTagEnd(s string, i int) int {
	j := i + 1
	if j == len(s) {
		return 0
	}
	if s[j] == '$' {
		return j + 1
	}
	if !tagLetter(s[j]) {
		return 0
	}
	for j++; j < len(s); j++ {
		if s[j] == '$' {
			return j + 1
		}
		if !tagLetter(s[j]) && !(s[j] >= '0' && s[j] <= '9') {
			return 0
		}
	}
	return 0
}

func tagLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// commentViews adds interpretations for matching; it never replaces the raw view.
// Build the PostgreSQL nested view only when a nested opener occurred in a block.
func commentViews(sql string) []string {
	if !strings.Contains(sql, "/*") && !strings.Contains(sql, "--") && !strings.Contains(sql, "#") {
		return nil
	}
	// Interpret escapes, brackets and hash comments independently: any dialect
	// view may expose executable code. Omit modes that cannot change this input.
	var enabled uint8
	if strings.Contains(sql, "\\") {
		enabled |= 1
	}
	if strings.Contains(sql, "[") {
		enabled |= 2
	}
	if strings.Contains(sql, "#") {
		enabled |= 4
	}
	if hasMySQLArithmeticDash(sql) {
		enabled |= 8
	}
	if strings.Contains(sql, "\\") && (strings.Contains(sql, "E'") || strings.Contains(sql, "e'")) {
		enabled |= 16
	}
	var views []string
	add := func(view string) {
		if view == sql {
			return
		}
		for _, old := range views {
			if old == view {
				return
			}
		}
		views = append(views, view)
	}
	for mode := uint8(0); mode < 32; mode++ {
		if mode & ^enabled != 0 {
			continue
		}
		var flat string
		var nested bool
		if mode == 0 {
			flat, nested = normalizeComments(sql, false)
		} else {
			flat, nested = normalizeCommentView(sql, false, mode&1 != 0, mode&2 != 0, mode&4 != 0, mode&8 != 0, mode&16 != 0)
		}
		add(flat)
		if nested {
			pg, _ := normalizeCommentView(sql, true, mode&1 != 0, mode&2 != 0, mode&4 != 0, mode&8 != 0, mode&16 != 0)
			add(pg)
		}
	}
	return views
}

func normalizeComments(sql string, nested bool) (string, bool) {
	return normalizeCommentView(sql, nested, false, false, false, false, false)
}

func normalizeCommentView(sql string, nested, escapes, brackets, hash, mysqlDash, eOnly bool) (string, bool) {
	var out strings.Builder
	lex := sqlLexState{mysqlDash: mysqlDash, eOnly: eOnly}
	start := 0
	hasNested := false
	for i := 0; i < len(sql); i++ {
		if lex.code() && i+1 < len(sql) {
			if dashComment(sql, i, mysqlDash) || hash && sql[i] == '#' {
				if start == 0 {
					out.Grow(len(sql))
				}
				out.WriteString(sql[start:i])
				out.WriteByte(' ')
				width := 2
				if sql[i] == '#' {
					width = 1
				}
				for i += width; i < len(sql) && sql[i] != '\n' && sql[i] != '\r'; i++ {
				}
				start = i
				i--
				continue
			}
			if sql[i] == '/' && sql[i+1] == '*' {
				if start == 0 {
					out.Grow(len(sql))
				}
				out.WriteString(sql[start:i])
				out.WriteByte(' ')
				body := i + 2
				executable := body < len(sql) && sql[body] == '!'
				if body+1 < len(sql) && (sql[body] == 'M' || sql[body] == 'm') && sql[body+1] == '!' {
					executable = true
					body++
				}
				if executable {
					body++
					for body < len(sql) && sql[body] >= '0' && sql[body] <= '9' {
						body++
					}
				}
				j, depth := i+2, 1
				for j+1 < len(sql) {
					if sql[j] == '*' && sql[j+1] == '/' {
						depth--
						if depth == 0 {
							break
						}
						j += 2
					} else if sql[j] == '/' && sql[j+1] == '*' {
						hasNested = true
						if nested {
							depth++
							j += 2
						} else {
							// Flat comments may close at the overlapping */ in /*/.
							j++
						}
					} else {
						j++
					}
				}
				if depth != 0 {
					j = len(sql)
				}
				if executable && depth == 0 {
					out.WriteString(sql[body:j])
					out.WriteByte(' ')
				}
				if j < len(sql) {
					j += 2
				}
				start = j
				i = j - 1
				continue
			}
		}
		// This interpretation only adds matches; the raw view is always retained.
		lex.step(sql, i, escapes, nested, hash, brackets)
	}
	if start == 0 {
		return sql, hasNested
	}
	out.WriteString(sql[start:])
	return out.String(), hasNested
}
