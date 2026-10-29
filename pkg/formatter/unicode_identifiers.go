// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// RestoreUnicodeIdentifiers restores source spellings after rendering a single
// statement. Decoded names on the AST remain available to semantic consumers.
// U& spellings are PostgreSQL syntax, so they are restored only when the
// target dialect is unset, generic or PostgreSQL; other targets keep the
// decoded name. Ordinary statements take the allocation-free fast path.
func RestoreUnicodeIdentifiers(tree *ast.AST, statement int, sql, dialect string) string {
	if tree == nil || len(tree.UnicodeIdentifiers[statement]) == 0 || !keepsUnicodeSpelling(dialect) {
		return sql
	}
	names := tree.UnicodeIdentifiers[statement]
	used := make([]bool, len(names))
	var out strings.Builder
	last := 0
	replace := func(start, end int, name string, quoted bool) {
		for n, entry := range names {
			if used[n] || entry.Name != name || entry.Quoted != quoted {
				continue
			}
			used[n] = true
			if entry.Spelling != "" {
				out.WriteString(sql[last:start])
				out.WriteString(entry.Spelling)
				last = end
			}
			break
		}
	}
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '\'':
			// PostgreSQL E strings also escape quotes with a backslash.
			escaped := i > 0 && (sql[i-1] == 'E' || sql[i-1] == 'e')
			if escaped {
				i++
				for i < len(sql) {
					if sql[i] == '\\' && i+1 < len(sql) {
						i += 2
						continue
					}
					if sql[i] == '\'' {
						if i+1 < len(sql) && sql[i+1] == '\'' {
							i += 2
							continue
						}
						i++
						break
					}
					i++
				}
			} else {
				i = quotedEnd(sql, i, '\'')
			}
		case strings.HasPrefix(sql[i:], "--"):
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				i = len(sql)
			} else {
				i += end
			}
		case strings.HasPrefix(sql[i:], "/*"):
			i += 2
			depth := 1
			for i < len(sql) && depth > 0 {
				if strings.HasPrefix(sql[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(sql[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case sql[i] == '$':
			// PostgreSQL dollar strings can contain arbitrary quoted names.
			j := i + 1
			for j < len(sql) && ((sql[j] >= 'a' && sql[j] <= 'z') || (sql[j] >= 'A' && sql[j] <= 'Z') || (sql[j] >= '0' && sql[j] <= '9') || sql[j] == '_') {
				j++
			}
			if j < len(sql) && sql[j] == '$' {
				tag := sql[i : j+1]
				if end := strings.Index(sql[j+1:], tag); end >= 0 {
					i = j + 1 + end + len(tag)
					continue
				}
			}
			i++
		case sql[i] == '"':
			end := quotedEnd(sql, i, '"')
			if end <= i+1 || sql[end-1] != '"' {
				return sql
			}
			name := strings.ReplaceAll(sql[i+1:end-1], `""`, `"`)
			replace(i, end, name, true)
			i = end
		default:
			r, size := utf8.DecodeRuneInString(sql[i:])
			if r == '_' || unicode.IsLetter(r) {
				start := i
				i += size
				for i < len(sql) {
					r, size = utf8.DecodeRuneInString(sql[i:])
					if r != '_' && r != '$' && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r) {
						break
					}
					i += size
				}
				replace(start, i, sql[start:i], false)
			} else {
				i += size
			}
		}
	}
	if last == 0 {
		return sql
	}
	out.WriteString(sql[last:])
	return out.String()
}

func quotedEnd(sql string, start int, quote byte) int {
	for i := start + 1; i < len(sql); i++ {
		if sql[i] != quote {
			continue
		}
		if i+1 < len(sql) && sql[i+1] == quote {
			i++
			continue
		}
		return i + 1
	}
	return len(sql)
}

// keepsUnicodeSpelling reports whether the target dialect accepts U& identifiers.
func keepsUnicodeSpelling(dialect string) bool {
	switch strings.ToLower(dialect) {
	case "", "generic", "postgresql", "postgres":
		return true
	}
	return false
}
