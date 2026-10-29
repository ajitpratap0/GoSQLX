// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package dropcheck is a cheap detector for clauses a formatter silently
// drops even though its output re-parses: it reports words of the input
// (outside comments and string literals) that are missing from the output.
// It is shared by the real-world corpus test and scripts/dialect-audit.
// This is a heuristic: it can miss a moved clause or other semantic changes.
package dropcheck

import (
	"regexp"
	"strings"

	sqldialect "github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// DroppedWords compares word multisets, reporting each missing occurrence in
// input order after canonicalizing synonyms and ignoring optional noise words.
// The optional dialect is passed to Words.
func DroppedWords(in, out string, dialect ...string) []string {
	in = CanonicalSynonyms(in)
	have := map[string]int{}
	for _, w := range Words(out, dialect...) {
		have[w]++
	}
	var lost []string
	for _, w := range Words(in, dialect...) {
		if have[w] > 0 {
			have[w]--
		} else if !ignorable[w] {
			lost = append(lost, w)
		}
	}
	return lost
}

// synonyms matches spellings the formatter writes in their canonical
// form because the dialects define them as exact synonyms: SELECT ALL (ALL is
// the default quantifier), DISTINCTROW (MySQL) and SELECT UNIQUE (Oracle) for
// DISTINCT, and the postfix
// ISNULL / NOTNULL (PostgreSQL, SQLite) for IS NULL / IS NOT NULL. UNION ALL
// and the function ISNULL(...) are not touched.
var synonyms = regexp.MustCompile(`(?i)\b(SELECT\s+ALL|SELECT\s+UNIQUE|DISTINCTROW|ISNULL|NOTNULL)\b`)

// CanonicalSynonyms rewrites SQL synonyms in s
// to the canonical spelling the formatter writes.
func CanonicalSynonyms(s string) string {
	var sb strings.Builder
	last := 0
	for _, m := range synonyms.FindAllStringIndex(s, -1) {
		word := strings.ToUpper(s[m[0]:m[1]])
		rest := strings.TrimLeft(s[m[1]:], " \t\r\n")
		var repl string
		switch {
		case strings.HasPrefix(word, "SELECT") && strings.HasSuffix(word, "UNIQUE"):
			repl = "SELECT DISTINCT"
		case strings.HasPrefix(word, "SELECT"):
			repl = "SELECT"
		case word == "DISTINCTROW":
			repl = "DISTINCT"
		case strings.HasPrefix(rest, "("): // the ISNULL(...) function
			continue
		case word == "ISNULL":
			repl = "IS NULL"
		default:
			repl = "IS NOT NULL"
		}
		sb.WriteString(s[last:m[0]])
		sb.WriteString(repl)
		last = m[1]
	}
	sb.WriteString(s[last:])
	return sb.String()
}

// ignorable are noise words the formatter may legitimately add or drop.
var ignorable = map[string]bool{"AS": true, "ASC": true, "INNER": true, "OUTER": true}

// Words returns the upper-cased identifier-like words of s, skipping
// comments and quoted string literals but keeping quoted identifiers' text.
// For MySQL and MariaDB, '#' also starts a line comment (outside backticks).
// The optional dialect uses the tokenizer's string escape rules; omitted means
// generic SQL. PostgreSQL E-prefixed strings always allow backslash escapes.
func Words(s string, dialect ...string) []string {
	d := sqldialect.Generic
	if len(dialect) > 0 {
		d = sqldialect.Parse(dialect[0])
	}
	backslash := d.StringEscape() != sqldialect.StringEscapeNone
	mysqlFamily := d == sqldialect.MySQL || d == sqldialect.MariaDB
	var words []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '`' && mysqlFamily:
			// A backtick identifier: keep its words, but a '#' inside it does
			// not start a comment.
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				end = len(s) - i - 1
			}
			words = append(words, Words(s[i+1:i+1+end])...)
			i += end + 2
		case c == '-' && i+1 < len(s) && s[i+1] == '-', c == '#' && mysqlFamily:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return words
			}
			i += end + 4
		case c == '$' && dollarQuoteEnd(s, i) > i:
			i = dollarQuoteEnd(s, i)
		case c == '\'' || (c == 'E' || c == 'e') && i+1 < len(s) && s[i+1] == '\'' && d == sqldialect.PostgreSQL:
			escapes := backslash
			if c != '\'' {
				i++
				escapes = true
			}
			for i++; i < len(s); i++ {
				if s[i] == '\\' && escapes {
					i++
					continue
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			i++
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= 0x80:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '$' || s[j] >= '0' && s[j] <= '9' ||
				s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 0x80) {
				j++
			}
			words = append(words, strings.ToUpper(s[i:j]))
			i = j
		case c >= '0' && c <= '9':
			for i < len(s) && (s[i] == '.' || s[i] == '_' || s[i] >= '0' && s[i] <= '9' ||
				s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
				i++
			}
		default:
			i++
		}
	}
	return words
}

// dollarQuoteEnd returns the offset just past the dollar-quoted
// string ($$...$$ or $tag$...$tag$) that starts at s[i], or i when s[i] does
// not start one.
func dollarQuoteEnd(s string, i int) int {
	j := i + 1
	for j < len(s) && (s[j] == '_' || s[j] >= '0' && s[j] <= '9' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z') {
		j++
	}
	if j >= len(s) || s[j] != '$' || (j > i+1 && s[i+1] >= '0' && s[i+1] <= '9') {
		return i
	}
	tag := s[i : j+1]
	end := strings.Index(s[j+1:], tag)
	if end < 0 {
		return i
	}
	return j + 1 + end + len(tag)
}
