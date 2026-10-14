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

// This file holds the quoting helpers for names the AST stores as plain
// strings (CTE names and column lists, view names and column lists, table
// references). Those positions record no quote information, so a name is
// quoted whenever a bare rendering could not re-parse as the same name.
package ast

import (
	"bytes"
	"strings"
	"unicode"
)

// reservedNameWords lists the words the parser rejects as a bare name, keyed
// in upper case. A true value means the word is rejected bare in every name
// position, including FROM/JOIN table names; false means it is rejected only
// in CTE names and CTE/view column lists.
//
// The lists were derived by parsing every keyword bare in each of these
// positions across all nine supported dialects. A word belongs here only if
// the parser rejects it bare in that position in every dialect, so any parsed
// name equal to it must have been quoted in the source, and quoting it on
// output reproduces the source exactly. TestReservedNameWordsRejectedBare
// enforces this: if the parser starts accepting one of these words bare, the
// word must be removed from the list.
var reservedNameWords = map[string]bool{
	// Reserved in every name position.
	"ADD": true, "ALL": true, "ALTER": true, "AND": true, "ARRAY": true,
	"AS": true, "ASC": true, "AUTOINCREMENT": true, "BETWEEN": true, "BY": true,
	"CASCADE": true, "CASE": true, "CAST": true, "CHECK": true, "COLLATE": true,
	"CONCURRENTLY": true, "CONSTRAINT": true, "CREATE": true, "CROSS": true, "CUBE": true,
	"CURRENT": true, "DELETE": true, "DESC": true, "DESCRIBE": true, "DISTINCT": true,
	"DROP": true, "ELSE": true, "END": true, "EXCEPT": true, "EXCLUDE": true,
	"EXISTS": true, "EXPLAIN": true, "FALSE": true, "FETCH": true, "FILTER": true,
	"FINAL": true, "FIRST": true, "FOLLOWING": true, "FOR": true, "FOREIGN": true,
	"FROM": true, "FULL": true, "GROUP": true, "GROUPING": true, "GROUPS": true,
	"HASH": true, "HAVING": true, "IF": true, "ILIKE": true, "IN": true,
	"INNER": true, "INSERT": true, "INTERSECT": true, "INTERVAL": true, "INTO": true,
	"IS": true, "JOIN": true, "LAST": true, "LATERAL": true, "LEFT": true,
	"LESS": true, "LIKE": true, "LIMIT": true, "LIST": true, "LOCKED": true,
	"MATERIALIZED": true, "MAXVALUE": true, "MERGE": true, "NATURAL": true, "NEXT": true,
	"NOT": true, "NOWAIT": true, "NULL": true, "NULLS": true, "OF": true,
	"OFFSET": true, "ON": true, "ONLY": true, "OR": true, "ORDER": true,
	"OUTER": true, "OVER": true, "PERCENT": true, "PRECEDING": true, "PREWHERE": true,
	"PRIMARY": true, "RANGE": true, "RECURSIVE": true, "REFERENCES": true, "REFRESH": true,
	"RENAME": true, "REPLACE": true, "RESTRICT": true, "RIGHT": true, "ROLLUP": true,
	"ROW": true, "SELECT": true, "SET": true, "SETS": true, "SHARE": true,
	"SHOW": true, "SKIP": true, "TABLESPACE": true, "TEMPORARY": true, "THAN": true,
	"THEN": true, "TIES": true, "TO": true, "TRUE": true, "TRUNCATE": true,
	"UNBOUNDED": true, "UNION": true, "UNIQUE": true, "UPDATE": true, "USING": true,
	"VALUES": true, "WHEN": true, "WHERE": true, "WITH": true, "WITHIN": true,

	// Reserved only in CTE names and CTE/view column lists.
	"COLUMN": false, "DATABASES": false, "DEFAULT": false, "INDEX": false, "KEY": false,
	"MATCHED": false, "PARTITION": false, "ROWS": false, "SOURCE": false, "TABLE": false,
	"TABLES": false, "TARGET": false, "VIEW": false,
}

// maxReservedNameLen bounds the stack buffer isReservedName upper-cases into;
// it is at least the length of the longest word in reservedNameWords.
const maxReservedNameLen = 16

// isReservedName reports whether name is in reservedNameWords for the given
// position: table is true for a FROM/JOIN table or view name part and false
// for a CTE name or column-list entry. The lookup does not allocate.
func isReservedName(name string, table bool) bool {
	if len(name) < 2 || len(name) > maxReservedNameLen {
		return false
	}
	var up [maxReservedNameLen]byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case c >= 'A' && c <= 'Z', c == '_':
		default:
			return false
		}
		up[i] = c
	}
	inAll, ok := reservedNameWords[string(up[:len(name)])]
	return ok && (inAll || !table)
}

// nameNeedsQuoting reports whether a single name part must be double-quoted
// to re-parse as the same name: it contains a character other than a letter,
// digit or '_' (or, after the first rune, a combining mark or connector
// punctuation, which the tokenizer also accepts in a bare identifier), or it
// is a reserved word for the position. In table positions (table is true)
// '$', '#' and '@' are also allowed bare so SQL Server #temp tables and
// Snowflake @stage references keep their form.
func nameNeedsQuoting(name string, table bool) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		// Mirrors tokenizer.unicodeIdentifierPartSlow: Mn and Mc combining
		// marks (Indic vowel signs, decomposed accents) and Pc connector
		// punctuation are bare identifier parts, but never a first rune.
		if i > 0 && r >= 0x80 && (unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r)) {
			continue
		}
		if table && (r == '$' || r == '#' || r == '@') {
			continue
		}
		return true
	}
	return isReservedName(name, table)
}

// writeQuotedIdentifier writes name as an ANSI double-quoted identifier,
// doubling any embedded double quote.
func writeQuotedIdentifier(buf *bytes.Buffer, name string) {
	buf.WriteByte('"')
	for i := 0; i < len(name); i++ {
		if name[i] == '"' {
			buf.WriteString(`""`)
		} else {
			buf.WriteByte(name[i])
		}
	}
	buf.WriteByte('"')
}

// writeName writes a CTE name or a column-list entry, quoting it if needed.
func writeName(buf *bytes.Buffer, name string) {
	if nameNeedsQuoting(name, false) {
		writeQuotedIdentifier(buf, name)
		return
	}
	buf.WriteString(name)
}

// writeNameList writes names separated by ", ", quoting each as needed.
func writeNameList(buf *bytes.Buffer, names []string) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeName(buf, n)
	}
}

// writeQualifiedName writes a possibly dotted table or view name, quoting
// each dot-separated part on its own as needed. A dot is always treated as a
// part separator (the same convention as writeDottedIdentifier). An empty
// name writes nothing. A name starting with '@' is a Snowflake stage
// reference, which may carry a /path suffix; it is written verbatim.
func writeQualifiedName(buf *bytes.Buffer, name string) {
	if name == "" {
		return
	}
	if name[0] == '@' {
		buf.WriteString(name)
		return
	}
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if part == "" || nameNeedsQuoting(part, true) {
			writeQuotedIdentifier(buf, part)
		} else {
			buf.WriteString(part)
		}
		if dot < 0 {
			return
		}
		buf.WriteByte('.')
		name = name[dot+1:]
	}
}

// qualifiedNameNeedsQuoting reports whether writeQualifiedName would quote
// some part of the non-empty name.
func qualifiedNameNeedsQuoting(name string) bool {
	if name[0] == '@' {
		return false
	}
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if part == "" || nameNeedsQuoting(part, true) {
			return true
		}
		if dot < 0 {
			return false
		}
		name = name[dot+1:]
	}
}

// QuoteName returns a single-part name, such as a CTE name or a CTE/view
// column-list entry, double-quoted when a bare rendering would not re-parse
// as the same name: it contains a character other than a letter, digit or
// '_', or it is a word the parser rejects bare in those positions. Otherwise
// name is returned unchanged without allocating. The output uses ANSI double
// quotes regardless of dialect.
func QuoteName(name string) string {
	if !nameNeedsQuoting(name, false) {
		return name
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, name)
	return buf.String()
}

// QuoteQualifiedName returns a dotted table or view name with each
// dot-separated part double-quoted when a bare rendering would not re-parse
// as the same name. '$', '#' and '@' are kept bare so forms such as SQL
// Server #temp and Snowflake @stage are unchanged, and a name starting with
// '@' (a Snowflake stage, possibly with a /path suffix such as
// @mystage/data) is returned as is. When no part needs quoting
// name is returned unchanged without allocating. The output uses ANSI double
// quotes regardless of dialect.
func QuoteQualifiedName(name string) string {
	if name == "" || !qualifiedNameNeedsQuoting(name) {
		return name
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQualifiedName(buf, name)
	return buf.String()
}
