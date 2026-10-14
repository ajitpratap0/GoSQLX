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
// references and INSERT/UPDATE/DELETE targets, select-item, table and
// ARRAY JOIN aliases, window names, DDL object, column and constraint names,
// function names) and for the free-text positions rendered next to them
// (column data types, table option and PRAGMA values). Those positions record
// no quote information, so a name is quoted whenever a bare rendering could
// not re-parse as the same name, and a free-text value that is not plainly
// shaped is quoted as a whole.
package ast

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
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

// reservedLenMask has bit n of entry c-'A' set when reservedNameWords holds
// a word of length n starting with letter c. isReservedName consults it to
// skip the map lookup for most ordinary names.
var reservedLenMask = func() (m [26]uint32) {
	for w := range reservedNameWords {
		m[w[0]-'A'] |= 1 << len(w)
	}
	return m
}()

// isReservedName reports whether name is in reservedNameWords for the given
// position: table is true for a FROM/JOIN table or view name part and false
// for a CTE name or column-list entry. The lookup does not allocate.
func isReservedName(name string, table bool) bool {
	if len(name) < 2 || len(name) > maxReservedNameLen {
		return false
	}
	first := name[0] | 0x20 // ASCII lower case; non-letters fail below
	if first < 'a' || first > 'z' || reservedLenMask[first-'a']&(1<<len(name)) == 0 {
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
// is a reserved word for the position. In table positions (table is true) a
// leading run of '#' is also allowed bare so SQL Server #temp and ##global
// tables keep their form; '#' anywhere else is quoted (the tokenizer does not
// accept it bare there, and MySQL would read the rest of the line as a
// comment).
func nameNeedsQuoting(name string, table bool) bool {
	return !isBareNameChars(name, table) || isReservedName(name, table)
}

// isBareNameChars reports whether every rune of name may appear in a bare
// identifier (see nameNeedsQuoting); leadingHash additionally allows a
// leading run of '#' followed by at least one other rune. An empty name
// reports true.
func isBareNameChars(name string, leadingHash bool) bool {
	if leadingHash && name != "" && name[0] == '#' {
		name = strings.TrimLeft(name, "#")
		if name == "" {
			return false
		}
	}
	// ASCII fast path; the first non-ASCII byte hands over to the rune loop.
	i := 0
	for ; i < len(name); i++ {
		c := name[i]
		if c >= 0x80 {
			break
		}
		if c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	if i == len(name) {
		return true
	}
	for j, r := range name[i:] {
		if r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		// Mirrors tokenizer.unicodeIdentifierPartSlow: Mn and Mc combining
		// marks (Indic vowel signs, decomposed accents) and Pc connector
		// punctuation are bare identifier parts, but never a first rune.
		if i+j > 0 && r >= 0x80 && (unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r)) {
			continue
		}
		return false
	}
	return true
}

// isStageReference reports whether name is a Snowflake stage reference that
// can be written bare: '@' followed by letters, digits and the path
// characters '_', '.', '/', '~', '%', '$' and '-' (never "--"). Anything else
// starting with '@' is quoted like any other name.
func isStageReference(name string) bool {
	if len(name) < 2 || name[0] != '@' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_' || c == '.' || c == '/' || c == '~' || c == '%' || c == '$',
			c|0x20 >= 'a' && c|0x20 <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i+1 < len(name) && name[i+1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// tableAliasNeedsQuoting reports whether a table alias (FROM/JOIN, derived
// table, PIVOT/UNPIVOT, UPDATE/DELETE or MERGE target/source) must be
// double-quoted: it contains a character a bare identifier cannot, or it is a
// word the parser rejects bare in every name position. Position-only words
// such as SOURCE, TARGET and KEY stay bare, the same rule as a qualifier
// that refers to the alias (writeDottedIdentifier), so "source".x and
// AS "source" keep matching after case folding.
func tableAliasNeedsQuoting(name string) bool {
	return !isBareNameChars(name, false) || isReservedName(name, true)
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

// writeTableAlias writes a table alias, quoting it if needed (see
// tableAliasNeedsQuoting).
func writeTableAlias(buf *bytes.Buffer, name string) {
	if tableAliasNeedsQuoting(name) {
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
// name writes nothing. A Snowflake stage reference ('@' and path characters,
// see isStageReference), which may carry a /path suffix, is written verbatim.
func writeQualifiedName(buf *bytes.Buffer, name string) {
	if name == "" {
		return
	}
	if isStageReference(name) {
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
	if isStageReference(name) {
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

// QuoteName returns a single-part name, such as a CTE name, a CTE/view
// column-list entry, a select-item or ARRAY JOIN alias, or a window name,
// double-quoted when a bare rendering would not re-parse
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
// as the same name. A leading '#' is kept bare so SQL Server #temp tables are
// unchanged, and a Snowflake stage reference ('@' followed by name and path
// characters, possibly with a /path suffix such as @mystage/data) is returned
// as is. When no part needs quoting
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

// QuoteTableAlias returns a table alias (FROM/JOIN, derived table,
// PIVOT/UNPIVOT, UPDATE/DELETE or MERGE target/source) double-quoted when a
// bare rendering would not re-parse as the same alias: it contains a
// character other than a letter, digit or '_', or it is a word the parser
// rejects bare in every name position. Position-only words such as SOURCE,
// TARGET and KEY are returned unchanged, matching how a qualifier that
// refers to the alias renders, as is any other name that needs no quoting,
// without allocating. The output uses ANSI double quotes regardless of
// dialect.
func QuoteTableAlias(name string) string {
	if !tableAliasNeedsQuoting(name) {
		return name
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, name)
	return buf.String()
}

// writeColumnName writes a single-part DDL column, constraint or index-method
// name (or a column-list entry of a constraint, REFERENCES clause, index,
// PARTITION BY or MERGE INSERT), quoting it when it contains a character a
// bare identifier cannot or is a word the parser rejects bare in every name
// position: the same rule as a table alias (tableAliasNeedsQuoting), so
// column names such as key or default stay bare as they are accepted.
func writeColumnName(buf *bytes.Buffer, name string) {
	writeTableAlias(buf, name)
}

// writeColumnNameList writes names separated by ", ", each via
// writeColumnName.
func writeColumnNameList(buf *bytes.Buffer, names []string) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeColumnName(buf, n)
	}
}

// QuoteColumnName returns a single-part DDL column, constraint or
// index-method name double-quoted when a bare rendering would not re-parse as
// the same name: it contains a character other than a letter, digit or '_',
// or it is a word the parser rejects bare in every name position. Otherwise
// name is returned unchanged without allocating. The output uses ANSI double
// quotes regardless of dialect.
func QuoteColumnName(name string) string {
	return QuoteTableAlias(name)
}

// functionNamePartNeedsQuoting reports whether one dot-separated part of a
// function name must be quoted. Keywords are not: the parser accepts many as
// function names (LEFT, RIGHT, REPLACE, IF), so only the characters decide.
func functionNamePartNeedsQuoting(part string) bool {
	return part == "" || !isBareNameChars(part, false)
}

// writeFunctionName writes a possibly schema-qualified function name, quoting
// each dot-separated part that contains a character a bare identifier cannot.
// Keyword names (COUNT, LEFT, REPLACE, IF) and qualified names (s.fn) are
// written unchanged. An empty name writes nothing.
func writeFunctionName(buf *bytes.Buffer, name string) {
	if name == "" {
		return
	}
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if functionNamePartNeedsQuoting(part) {
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

// dataTypeIsPlain reports whether a column data type (or a table option's
// argument list) can be written verbatim: it is made only of letters, digits,
// spaces and the punctuation type syntax uses ('_', ',', '.', '(', ')', '[',
// ']', '<', '>', '=', '+', '-'), its parentheses balance, it has no "--", and
// any single-quoted segments (ENUM('a', 'b'), DateTime64(3, 'UTC')) are
// closed, double an embedded quote and contain no backslash (which some
// dialects treat as an escape). Such text can neither end the statement nor
// start a comment.
func dataTypeIsPlain(typ string) bool {
	depth := 0
	for i := 0; i < len(typ); i++ {
		c := typ[i]
		switch {
		case c == '\'':
			for i++; ; i++ {
				if i >= len(typ) || typ[i] == '\\' {
					return false
				}
				if typ[i] == '\'' {
					if i+1 < len(typ) && typ[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return false
			}
		case c == '-':
			if i+1 < len(typ) && typ[i+1] == '-' {
				return false
			}
		case c == '_' || c == ' ' || c == ',' || c == '.' || c == '[' || c == ']' ||
			c == '<' || c == '>' || c == '=' || c == '+',
			c|0x20 >= 'a' && c|0x20 <= 'z', c >= '0' && c <= '9':
		case c >= utf8.RuneSelf:
			r, size := utf8.DecodeRuneInString(typ[i:])
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return false
			}
			i += size - 1
		default:
			return false
		}
	}
	return depth == 0
}

// writeDataType writes a column data type verbatim when it is plainly shaped
// (dataTypeIsPlain) and as one double-quoted identifier otherwise, which the
// parser reads back as a custom type with the same text.
func writeDataType(buf *bytes.Buffer, typ string) {
	if dataTypeIsPlain(typ) {
		buf.WriteString(typ)
		return
	}
	writeQuotedIdentifier(buf, typ)
}

// QuoteDataType returns a column data type unchanged when it is plainly
// shaped (type names, spaces, balanced parentheses, closed single-quoted
// arguments) and as one double-quoted identifier otherwise.
func QuoteDataType(typ string) string {
	if dataTypeIsPlain(typ) {
		return typ
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, typ)
	return buf.String()
}

// optionValueIsPlain reports whether a CREATE TABLE option value (ENGINE,
// CHARSET, COLLATE, COMMENT) can be written verbatim: a bare word, optionally
// followed by a plainly shaped argument list such as MergeTree() or
// ReplicatedMergeTree('/path', '{replica}').
func optionValueIsPlain(v string) bool {
	word := v
	args := ""
	if p := strings.IndexByte(v, '('); p >= 0 {
		word, args = v[:p], v[p:]
	}
	return word != "" && isBareNameChars(word, false) && dataTypeIsPlain(args)
}

// writeStringLiteral writes s as a single-quoted SQL string literal, escaped
// as LiteralValue renders strings.
func writeStringLiteral(buf *bytes.Buffer, s string) {
	buf.WriteByte('\'')
	writeEscapedStringLiteral(buf, s)
	buf.WriteByte('\'')
}

// writeOptionValue writes a CREATE TABLE option value verbatim when it is
// plainly shaped (optionValueIsPlain) and as one double-quoted identifier
// otherwise, which the parser reads back as the same value.
func writeOptionValue(buf *bytes.Buffer, v string) {
	if optionValueIsPlain(v) {
		buf.WriteString(v)
		return
	}
	writeQuotedIdentifier(buf, v)
}

// QuoteTableOptionValue returns a CREATE TABLE option value unchanged when it
// is a bare word with an optional plainly shaped argument list, and as one
// double-quoted identifier otherwise.
func QuoteTableOptionValue(v string) string {
	if optionValueIsPlain(v) {
		return v
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, v)
	return buf.String()
}

// writePragmaValue writes a PRAGMA argument or assigned value: a bare word or
// an unsigned decimal number is written verbatim, anything else as a string
// literal (SQLite accepts either form).
func writePragmaValue(buf *bytes.Buffer, v string) {
	plain := v != "" && isBareNameChars(v, false)
	if !plain && v != "" {
		plain = true
		for i := 0; i < len(v); i++ {
			if (v[i] < '0' || v[i] > '9') && v[i] != '.' {
				plain = false
				break
			}
		}
	}
	if plain {
		buf.WriteString(v)
		return
	}
	writeStringLiteral(buf, v)
}

// IsPlainKeywordText reports whether s is non-empty and made only of ASCII
// letters, digits, '_' and single spaces between words, i.e. keyword text
// such as "CREATE TABLE" that can be written bare.
func IsPlainKeywordText(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if c == ' ' && s[i-1] != ' ' {
			continue
		}
		return false
	}
	return true
}

// writeShowType writes the SHOW statement kind. Keyword text (TABLES,
// CREATE TABLE) is written as is; the parser also stores the upper-cased
// text of a quoted kind (SHOW "x", SHOW CREATE "x" name), which is quoted so
// it re-parses to the same kind.
func writeShowType(buf *bytes.Buffer, t string) {
	if t == "" || IsPlainKeywordText(t) {
		buf.WriteString(t)
		return
	}
	if rest, ok := strings.CutPrefix(t, "CREATE "); ok {
		buf.WriteString("CREATE ")
		t = rest
	}
	writeQuotedIdentifier(buf, t)
}

// writeQualifiedNameList writes names separated by ", ", each via
// writeQualifiedName.
func writeQualifiedNameList(buf *bytes.Buffer, names []string) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeQualifiedName(buf, n)
	}
}

// ShowTakesFrom reports whether a SHOW statement of this kind names its
// object after FROM (SHOW COLUMNS FROM t, SHOW INDEX FROM t) rather than
// directly (SHOW CREATE TABLE t).
func ShowTakesFrom(showType string) bool {
	switch showType {
	case "COLUMNS", "INDEX", "INDEXES", "KEYS":
		return true
	}
	return false
}
