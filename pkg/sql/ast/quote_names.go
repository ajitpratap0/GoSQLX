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
// position, including FROM/JOIN table names and CTE names (which take the
// same words as a table alias); false means it is rejected only in CTE/view
// column lists.
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
	"FIRST": true, "FOLLOWING": true, "FOR": true, "FOREIGN": true,
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

	// Reserved only in CTE/view column lists.
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
// identifier (see nameNeedsQuoting) and name does not start with a digit
// (1abc would re-read as the number 1 followed by abc); leadingHash
// additionally allows a leading run of '#' followed by at least one other
// rune. An empty name reports true.
func isBareNameChars(name string, leadingHash bool) bool {
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		return false
	}
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
		if c == '$' && i > 0 {
			// Not a first character: Oracle v$session, Snowflake SYSTEM$TYPEOF.
			continue
		}
		return false
	}
	if i == len(name) {
		return true
	}
	for j, r := range name[i:] {
		if r == '_' || unicode.IsLetter(r) {
			continue
		}
		if r == '$' && i+j > 0 {
			continue
		}
		if unicode.IsDigit(r) {
			if i+j == 0 {
				return false // a non-ASCII digit cannot start a bare identifier
			}
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
	for prevEmpty := true; ; {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if part == "" && !prevEmpty && isEmptyMiddlePart(name, dot) {
			// SQL Server db..t: an empty schema part is written as nothing.
			prevEmpty = true
		} else if part == "" || nameNeedsQuoting(part, true) {
			prevEmpty = part == ""
			writeQuotedIdentifier(buf, part)
		} else {
			prevEmpty = false
			buf.WriteString(part)
		}
		if dot < 0 {
			return
		}
		buf.WriteByte('.')
		name = name[dot+1:]
	}
}

// isEmptyMiddlePart reports whether the empty part ending at dot (the index
// of the "." after it in the remaining name, -1 for the last part) lies
// between two non-empty parts, as the schema of SQL Server db..t does.
func isEmptyMiddlePart(rest string, dot int) bool {
	return dot == 0 && len(rest) > 1 && rest[1] != '.'
}

// qualifiedNameNeedsQuoting reports whether writeQualifiedName would quote
// some part of the non-empty name.
func qualifiedNameNeedsQuoting(name string) bool {
	if isStageReference(name) {
		return false
	}
	for first := true; ; first = false {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if part == "" && !first && isEmptyMiddlePart(name, dot) {
			// db..t: the empty part sits between two non-empty parts (an
			// empty part before it was reported already).
			name = name[dot+1:]
			continue
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

// constraintNameWords lists, in upper case, the words besides
// reservedNameWords that the parser does not accept bare as a table
// constraint name (it takes only an identifier or a double-quoted name
// there). TestConstraintNameWords keeps the list in step with the parser.
var constraintNameWords = map[string]bool{
	"ANY": true, "AUTO_INCREMENT": true, "CONNECTOR": true, "DCPROPERTIES": true,
	"FINAL": true, "MEMBER": true, "NOCREATEDB": true, "NOCREATEROLE": true, "NOLOGIN": true,
	"NOSUPERUSER": true, "OWNER": true, "POLICY": true, "RESET": true,
	"SOME": true, "UNTIL": true, "URL": true, "VALID": true,
}

// constraintNameNeedsQuoting reports whether a table constraint name must be
// written double-quoted: it is not plain (ASCII letters, digits and '_', not
// starting with a digit), or it is a keyword (KEY, INDEX, DEFAULT, TABLE, ...)
// the parser does not accept bare in that position. Case alone does not force
// quotes: the AST does not record whether a name was quoted, and quoting an
// unquoted PK_USERS would change the name in case-folding dialects. This
// matches Identifier.SQL(), which renders names quoted only for case bare.
func constraintNameNeedsQuoting(name string) bool {
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		return true
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return true
		}
	}
	return isReservedName(name, false) || constraintNameWords[strings.ToUpper(name)]
}

// writeConstraintName writes a table constraint name, double-quoting it when
// constraintNameNeedsQuoting says so.
func writeConstraintName(buf *bytes.Buffer, name string) {
	if constraintNameNeedsQuoting(name) {
		writeQuotedIdentifier(buf, name)
		return
	}
	buf.WriteString(name)
}

// QuoteConstraintName returns a table constraint name as SQL() writes it:
// bare when plain and not a keyword, double-quoted otherwise.
func QuoteConstraintName(name string) string {
	if !constraintNameNeedsQuoting(name) {
		return name
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, name)
	return buf.String()
}

// functionNamePartNeedsQuoting reports whether one dot-separated part of a
// function name must be quoted: it is empty or contains a character a bare
// identifier cannot. Keywords are left bare, since the parser accepts many as
// function names (REPLACE, IF), except in an unqualified name (single is
// true) that is a word the parser rejects bare in every name position and
// does not accept as a function name, such as "select"(x).
func functionNamePartNeedsQuoting(part string, single bool) bool {
	if part == "" || !isBareNameChars(part, false) {
		return true
	}
	return single && isReservedName(part, true) && !keywordFunctionNames[strings.ToUpper(part)]
}

// keywordFunctionNames lists the words in reservedNameWords that the parser
// still accepts bare as a function name (IF(a, b, c), REPLACE(s, x, y), LEFT(s, 2),
// VALUES(col) in ON DUPLICATE KEY UPDATE, FIRST/LAST, and the ClickHouse
// table functions merge(...) and null(...)). Any other reserved word written
// as a function name must have been quoted in the source.
// TestKeywordFunctionNames enforces the list against the parser.
var keywordFunctionNames = map[string]bool{
	"FIRST": true, "IF": true, "LAST": true, "MERGE": true, "NULL": true,
	"REPLACE": true, "VALUES": true,
	// Keyword-named functions: LEFT(s, 2), RIGHT(s, 2), GROUPING(a),
	// ROW(1, 2), TRUNCATE(x, 1), INSERT(s, 1, 2, 'x'), ClickHouse range(n)
	// and Snowflake HASH(a), and MySQL INTERVAL(n, n1, n2).
	"GROUPING": true, "HASH": true, "INSERT": true, "INTERVAL": true, "LEFT": true, "RANGE": true,
	"RIGHT": true, "ROW": true, "TRUNCATE": true,
}

// writeFunctionName writes a possibly schema-qualified function name, quoting
// each dot-separated part that contains a character a bare identifier cannot.
// Keyword names (COUNT, LEFT, REPLACE, IF) and qualified names (s.fn) are
// written unchanged. An empty name writes nothing.
func writeFunctionName(buf *bytes.Buffer, name string) {
	if name == "" {
		return
	}
	if isStageReference(name) {
		// Snowflake stage read with options: @stage/path (FILE_FORMAT => ...).
		// The space keeps "(" out of the stage path.
		buf.WriteString(name)
		buf.WriteByte(' ')
		return
	}
	multi := strings.IndexByte(name, '.') >= 0
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if functionNamePartNeedsQuoting(part, !multi) {
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
// ']', '<', '>', '=', '+', '-'), its parentheses balance, brackets appear
// only as an array suffix ([] or [n]), it has no "--", and
// any single-quoted segments (ENUM('a', 'b'), DateTime64(3, 'UTC')) are
// closed, double an embedded quote and contain no backslash (which some
// dialects treat as an escape). Such text can neither end the statement nor
// start a comment. A space outside parentheses must start one of the words
// of a known multi-word type (DOUBLE PRECISION, CHARACTER VARYING(n),
// TIMESTAMP WITH TIME ZONE, INT UNSIGNED, and the ClickHouse column codec the
// parser appends to the type, UInt64 CODEC(ZSTD(3)); see typeModifierWords): any other
// spaced text, such as the quoted custom type "a b", would re-parse as a
// different type, so it is quoted instead.
func dataTypeIsPlain(typ string) bool {
	depth := 0
	for i := 0; i < len(typ); i++ {
		c := typ[i]
		switch {
		case c == ' ' && depth == 0:
			if i == 0 {
				return false // a modifier word cannot start a type
			}
			j := i + 1
			for j < len(typ) && (typ[j]|0x20 >= 'a' && typ[j]|0x20 <= 'z') {
				j++
			}
			w := typ[i+1 : j]
			if strings.EqualFold(w, "SET") || strings.EqualFold(w, "CHARSET") {
				// MySQL CHARACTER SET name / CHARSET name: a bare charset
				// name follows the word.
				m := j + 1
				if j >= len(typ) || typ[j] != ' ' {
					return false
				}
				for m < len(typ) && (typ[m] == '_' || typ[m] >= '0' && typ[m] <= '9' || typ[m]|0x20 >= 'a' && typ[m]|0x20 <= 'z') {
					m++
				}
				if m == j+1 {
					return false
				}
				i = m - 1
				continue
			}
			if !isTypeModifierWord(w) && !(isSignednessInt(w) && prevWordIsSignedness(typ, i)) {
				return false
			}
			// The ClickHouse column CODEC the parser appends to the type is
			// always followed by its argument list: CODEC(ZSTD(3)).
			if len(w) == len("CODEC") && strings.EqualFold(w, "CODEC") && (j >= len(typ) || typ[j] != '(') {
				return false
			}
			i = j - 1
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
		case c == '[':
			// Only an array suffix: [] or [n].
			j := i + 1
			for j < len(typ) && typ[j] >= '0' && typ[j] <= '9' {
				j++
			}
			if j >= len(typ) || typ[j] != ']' {
				return false
			}
			i = j
		case c == '_' || c == ' ' || c == ',' || c == '.' ||
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

// typeModifierWords lists, in upper case, the words that may follow a space
// outside parentheses in a plain data type: the later words of the standard
// and common multi-word types, and CODEC, which the ClickHouse parser appends
// to a column type with its argument list (dataTypeIsPlain requires the "(").
var typeModifierWords = map[string]bool{
	"PRECISION": true, "VARYING": true, "CHARACTER": true, "CHAR": true, "VARCHAR": true,
	"WITH": true, "WITHOUT": true, "LOCAL": true, "TIME": true, "ZONE": true,
	"UNSIGNED": true, "SIGNED": true, "ZEROFILL": true, "LARGE": true, "OBJECT": true,
	"RAW": true, "BINARY": true, "CODEC": true, "INTEGER": true, "INT": true,
}

// isSignednessInt reports whether w is INT or INTEGER, the optional word that
// follows MySQL's SIGNED and UNSIGNED in a cast type (SIGNED INTEGER).
func isSignednessInt(w string) bool {
	return strings.EqualFold(w, "INT") || strings.EqualFold(w, "INTEGER")
}

// prevWordIsSignedness reports whether the word of typ that ends just before
// index end (the space) is SIGNED or UNSIGNED.
func prevWordIsSignedness(typ string, end int) bool {
	start := end
	for start > 0 && typ[start-1]|0x20 >= 'a' && typ[start-1]|0x20 <= 'z' {
		start--
	}
	w := typ[start:end]
	return strings.EqualFold(w, "SIGNED") || strings.EqualFold(w, "UNSIGNED")
}

// maxTypeModifierLen bounds the stack buffer isTypeModifierWord upper-cases
// into; it is the length of the longest word in typeModifierWords.
const maxTypeModifierLen = 9

// isTypeModifierWord reports whether w (ASCII letters) is in
// typeModifierWords, without allocating.
func isTypeModifierWord(w string) bool {
	if w == "" || len(w) > maxTypeModifierLen {
		return false
	}
	var up [maxTypeModifierLen]byte
	for i := 0; i < len(w); i++ {
		up[i] = w[i] &^ 0x20
	}
	return typeModifierWords[string(up[:len(w)])]
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

// customOperatorIsSafe reports whether a PostgreSQL OPERATOR(schema.op)
// operator can be written verbatim: every part but the last is a bare name
// and the last is operator text (see IsOperatorText).
func customOperatorIsSafe(op *CustomBinaryOperator) bool {
	if len(op.Parts) == 0 {
		return false
	}
	for i, p := range op.Parts {
		if i == len(op.Parts)-1 {
			return IsOperatorText(p) && !strings.ContainsAny(p, " ()")
		}
		if p == "" || !isBareNameChars(p, false) {
			return false
		}
	}
	return true
}

// IsOperatorText reports whether op can be written verbatim as a binary
// operator: it is a run of operator punctuation (=, <>, ->>, #>, @>, ||)
// that contains no comment opener or closer ("--", "/*", "*/"), or exactly
// one of the keyword operators (AND, LIKE, IS DISTINCT FROM, see
// binaryWordOperators; any case).
func IsOperatorText(op string) bool {
	if op == "" {
		return false
	}
	if c := op[0]; c|0x20 >= 'a' && c|0x20 <= 'z' {
		return keywordOneOf(op, binaryWordOperators) != ""
	}
	for i := 0; i < len(op); i++ {
		switch op[i] {
		case '+', '*', '%', '<', '>', '=', '!', '~', '^', '&', '|', '#', '@', '?', ':':
		case '-':
			if i+1 < len(op) && op[i+1] == '-' {
				return false
			}
		case '/':
			if i+1 < len(op) && op[i+1] == '*' {
				return false
			}
		default:
			return false
		}
		if op[i] == '*' && i+1 < len(op) && op[i+1] == '/' {
			return false
		}
	}
	return true
}

// writeOperator writes a binary, set or quantified-comparison operator:
// verbatim when it is operator or keyword text (IsOperatorText), and as a
// double-quoted identifier otherwise, which cannot end the statement and
// fails to re-parse rather than changing its meaning. Only a hand-built AST
// can hold such an operator.
func writeOperator(buf *bytes.Buffer, op string) {
	if IsOperatorText(op) {
		buf.WriteString(op)
		return
	}
	writeQuotedIdentifier(buf, op)
}

// writeSetOperator writes a set operator: verbatim when it is one of the
// known operators (SetOperatorText), and otherwise as UNION followed by the
// double-quoted text. A quoted token alone would re-parse as an alias of the
// left query, followed by the right query as a second statement; after UNION
// the parser requires SELECT or "(", so the fallback fails to parse instead.
// A hand-built Oracle/Snowflake MINUS is written as its equivalent EXCEPT,
// which every dialect parses (the parser itself stores MINUS as EXCEPT).
func writeSetOperator(buf *bytes.Buffer, op string) {
	op = minusAsExcept(op)
	if SetOperatorText(op) != "" {
		buf.WriteString(op)
		return
	}
	buf.WriteString("UNION ")
	writeQuotedIdentifier(buf, op)
}

// minusAsExcept returns EXCEPT (with the same ALL/DISTINCT suffix) for a
// MINUS set operator in any case, and op unchanged otherwise.
func minusAsExcept(op string) string {
	if len(op) < 5 || !strings.EqualFold(op[:5], "MINUS") {
		return op
	}
	switch rest := op[5:]; {
	case rest == "", strings.EqualFold(rest, " ALL"), strings.EqualFold(rest, " DISTINCT"):
		return "EXCEPT" + strings.ToUpper(rest)
	}
	return op
}

// SetOperatorSQL returns op as writeSetOperator writes it, and whether it is
// a known set operator (MINUS counts, written as EXCEPT).
func SetOperatorSQL(op string) (string, bool) {
	op = minusAsExcept(op)
	if SetOperatorText(op) != "" {
		return op, true
	}
	buf := getBuf()
	defer putBuf(buf)
	writeSetOperator(buf, op)
	return buf.String(), false
}

// QuoteOperator returns op unchanged when it is operator or keyword text
// (IsOperatorText) and double-quoted otherwise; see writeOperator.
func QuoteOperator(op string) string {
	if IsOperatorText(op) {
		return op
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, op)
	return buf.String()
}

// columnRefNeedsQuoting reports whether e is an identifier whose name is a
// word the parser rejects bare in every name position but which Identifier
// rendering would leave bare (it was not recorded as Quoted, for example a
// MySQL `select` or SQL Server [select]). Such a name is quoted where it is
// a write target: an INSERT column, a SET or DO UPDATE SET target, an ON
// CONFLICT target.
func columnRefNeedsQuoting(e Expression) (*Identifier, bool) {
	id, ok := e.(*Identifier)
	if !ok || id == nil || id.Quoted || !isReservedName(id.Name, true) {
		return nil, false
	}
	return id, true
}

// writeColumnRef writes a write-target column (see columnRefNeedsQuoting),
// quoting a reserved-word name, and any other expression as usual.
func writeColumnRef(buf *bytes.Buffer, e Expression) {
	id, ok := columnRefNeedsQuoting(e)
	if !ok {
		writeExpr(buf, e)
		return
	}
	if id.Table != "" {
		writeDottedIdentifier(buf, id.Table)
		buf.WriteByte('.')
	}
	writeQuotedIdentifier(buf, id.Name)
}

// writeColumnRefList writes exprs separated by ", ", each via writeColumnRef.
func writeColumnRefList(buf *bytes.Buffer, exprs []Expression) {
	for i, e := range exprs {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeColumnRef(buf, e)
	}
}

// ColumnRefSQL renders a write-target column (an INSERT column, a SET or DO
// UPDATE SET target, an ON CONFLICT target): like the expression's own SQL(),
// except that an identifier whose name is a reserved word is double-quoted
// even when it was not written with ANSI double quotes, so INSERT INTO t
// (`select`) renders as INSERT INTO t ("select").
func ColumnRefSQL(e Expression) string {
	if _, ok := columnRefNeedsQuoting(e); !ok {
		return exprSQL(e)
	}
	buf := getBuf()
	defer putBuf(buf)
	writeColumnRef(buf, e)
	return buf.String()
}

// ColumnRefListSQL joins exprs with ", ", each via ColumnRefSQL.
func ColumnRefListSQL(exprs []Expression) string {
	buf := getBuf()
	defer putBuf(buf)
	writeColumnRefList(buf, exprs)
	return buf.String()
}

// Keyword-valued fields (join types, DROP object types, set operators, ...)
// are written only when they are exactly one of a fixed set of keyword texts,
// compared ignoring ASCII case with single spaces between words. A looser
// gate such as "letters and spaces" is not enough: the parser accepts
// consecutive statements without ';', so a hand-built join type "CROSS JOIN c
// DROP TABLE pwn SELECT 1 FROM a INNER" would render as three statements.
// Each set holds every value the parser stores for the field (pinned by
// TestKeywordAllowListsCoverParserValues_PR632 over testdata/**/*.sql in
// every dialect) plus a few equivalent spellings a hand-built AST may use.
var (
	// joinTypeKeywords: parseJoinType stores INNER, LEFT, RIGHT, FULL, CROSS,
	// NATURAL [INNER|LEFT|RIGHT|FULL], CROSS APPLY and OUTER APPLY.
	joinTypeKeywords = []string{
		"INNER", "LEFT", "RIGHT", "FULL", "CROSS",
		"LEFT OUTER", "RIGHT OUTER", "FULL OUTER",
		"NATURAL", "NATURAL INNER", "NATURAL LEFT", "NATURAL RIGHT", "NATURAL FULL",
		"NATURAL LEFT OUTER", "NATURAL RIGHT OUTER", "NATURAL FULL OUTER",
		"CROSS APPLY", "OUTER APPLY",
	}
	// dropObjectTypeKeywords: the parser stores TABLE, VIEW, MATERIALIZED
	// VIEW and INDEX; the rest are other DROP-able object kinds.
	dropObjectTypeKeywords = []string{
		"TABLE", "VIEW", "MATERIALIZED VIEW", "INDEX",
		"SEQUENCE", "SCHEMA", "DATABASE", "FUNCTION", "PROCEDURE", "TRIGGER",
		"TYPE", "DOMAIN", "EXTENSION", "ROLE", "USER",
	}
	nullTreatmentKeywords = []string{"IGNORE NULLS", "RESPECT NULLS"}
	// intervalLeadingFields and intervalTrailingFields mirror the parser's
	// parseIntervalQualifier: a leading field alone, or "<leading> TO
	// <trailing>".
	intervalLeadingFields = []string{
		"YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND",
		"WEEK", "QUARTER", "MICROSECOND", "MILLISECOND",
		"SECOND_MICROSECOND", "MINUTE_MICROSECOND", "MINUTE_SECOND",
		"HOUR_MICROSECOND", "HOUR_SECOND", "HOUR_MINUTE",
		"DAY_MICROSECOND", "DAY_SECOND", "DAY_MINUTE", "DAY_HOUR",
		"YEAR_MONTH",
	}
	intervalTrailingFields = []string{"MONTH", "HOUR", "MINUTE", "SECOND"}
	// setOperatorKeywords: the parser stores the UNION / EXCEPT / INTERSECT
	// token as written (MINUS is normalised to EXCEPT; ALL is a separate
	// flag). MINUS itself is left out: outside Oracle and Snowflake it would
	// re-parse as a table alias followed by a second statement.
	setOperatorKeywords = []string{
		"UNION", "EXCEPT", "INTERSECT",
		"UNION ALL", "EXCEPT ALL", "INTERSECT ALL",
		"UNION DISTINCT", "EXCEPT DISTINCT", "INTERSECT DISTINCT",
	}
	// binaryWordOperators are the keyword forms of binary operators: the
	// parser stores AND, OR, NOT, LIKE / ILIKE [ANY|ALL], REGEXP, RLIKE,
	// IS NULL and AGAINST; the rest are standard keyword operators.
	binaryWordOperators = []string{
		"AND", "OR", "XOR", "NOT",
		"LIKE", "ILIKE", "NOT LIKE", "NOT ILIKE",
		"LIKE ANY", "LIKE ALL", "ILIKE ANY", "ILIKE ALL",
		"SIMILAR TO", "NOT SIMILAR TO",
		"REGEXP", "RLIKE", "NOT REGEXP", "NOT RLIKE",
		"IS NULL", "IS NOT NULL", "IS", "IS NOT",
		"IS DISTINCT FROM", "IS NOT DISTINCT FROM",
		"IN", "NOT IN", "AGAINST", "DIV", "MOD", "OVERLAPS", "GLOB",
		"NOT GLOB", "MATCH", "NOT MATCH", "SOUNDS LIKE",
	}
	// columnConstraintKeywords: the constraint kinds columnConstraintSQL
	// writes as bare keyword text (the parser stores NULL, AUTO_INCREMENT and
	// GENERATED ALWAYS AS ROW START / END; the others in any case).
	columnConstraintKeywords = []string{
		"NOT NULL", "NULL", "UNIQUE", "PRIMARY KEY", "AUTO_INCREMENT",
		"GENERATED ALWAYS AS ROW START", "GENERATED ALWAYS AS ROW END",
	}
	partitionByKeywords = []string{
		"RANGE", "LIST", "HASH", "KEY", "LINEAR HASH", "LINEAR KEY",
		"RANGE COLUMNS", "LIST COLUMNS", "SYSTEM_TIME",
	}
	// alterTableActionKeywords: the legacy AlterTableStatement (never produced
	// by the parser) writes an action other than its explicit cases as bare
	// keyword text.
	alterTableActionKeywords = []string{
		"ADD COLUMN", "DROP COLUMN", "ADD CONSTRAINT", "DROP CONSTRAINT",
		"ALTER COLUMN", "RENAME COLUMN", "RENAME TO",
	}
	// tableOptionNames: the parser stores ENGINE, CHARSET, COLLATE and
	// COMMENT as written.
	tableOptionNames = []string{
		"ENGINE", "CHARSET", "DEFAULT CHARSET", "CHARACTER SET", "DEFAULT CHARACTER SET",
		"COLLATE", "DEFAULT COLLATE", "COMMENT", "AUTO_INCREMENT", "ROW_FORMAT",
		// Further MySQL / MariaDB options.
		"KEY_BLOCK_SIZE", "AVG_ROW_LENGTH", "MAX_ROWS", "MIN_ROWS", "PACK_KEYS",
		"CHECKSUM", "DELAY_KEY_WRITE", "STATS_PERSISTENT", "STATS_AUTO_RECALC",
		"STATS_SAMPLE_PAGES", "COMPRESSION", "ENCRYPTION", "PAGE_CHECKSUM",
		"TRANSACTIONAL", "INSERT_METHOD", "DATA DIRECTORY", "INDEX DIRECTORY",
		// PostgreSQL, Oracle and SQL Server storage options.
		"TABLESPACE", "USING", "PCTFREE", "PCTUSED", "INITRANS", "MAXTRANS", "PARALLEL",
		"WITH", "ON COMMIT DELETE ROWS", "ON COMMIT PRESERVE ROWS", "ON COMMIT DROP",
		"WITHOUT OIDS", "LOGGING", "NOLOGGING", "COMPRESS", "NOCOMPRESS", "NOCACHE",
		"NOPARALLEL", "ROWDEPENDENCIES", "NOROWDEPENDENCIES", "MONITORING", "NOMONITORING",
		"ENABLE ROW MOVEMENT", "DISABLE ROW MOVEMENT", "SEGMENT CREATION IMMEDIATE",
		"SEGMENT CREATION DEFERRED", "ORGANIZATION HEAP", "ORGANIZATION INDEX",
		// SQLite.
		"STRICT", "WITHOUT ROWID",
		// Snowflake.
		"DATA_RETENTION_TIME_IN_DAYS", "MAX_DATA_EXTENSION_TIME_IN_DAYS", "CHANGE_TRACKING",
		"DEFAULT_DDL_COLLATION", "ENABLE_SCHEMA_EVOLUTION", "CLUSTER BY", "COPY GRANTS",
		// CREATE INDEX options.
		"NULLS NOT DISTINCT", "NULLS DISTINCT", "ALGORITHM", "LOCK", "LOCAL", "GLOBAL",
		"ONLINE", "REVERSE", "VISIBLE", "INVISIBLE",
	}
	viewWithOptionKeywords = []string{"CHECK OPTION", "CASCADED CHECK OPTION", "LOCAL CHECK OPTION"}
	// mergeWhenKeywords: the parser stores MATCHED, NOT_MATCHED and
	// NOT_MATCHED_BY_SOURCE, which the renderers spell out; a hand-built AST
	// may also use the spelled-out forms.
	mergeWhenKeywords = []string{"MATCHED", "NOT MATCHED", "NOT MATCHED BY SOURCE", "NOT MATCHED BY TARGET"}
	// mergeActionKeywords: the actions written as bare keyword text (UPDATE
	// and INSERT carry their own clauses and are written by the renderers).
	mergeActionKeywords = []string{"DELETE", "DO NOTHING"}
)

// JoinTypeText returns s when it is a join type (see joinTypeKeywords; any
// case) and "" otherwise. Renderers write an unknown join type as a plain
// JOIN: the type is an optional modifier, and dropping it keeps the join
// inside the statement.
func JoinTypeText(s string) string { return keywordOneOf(s, joinTypeKeywords) }

// DropObjectTypeText returns s when it is a DROP object type (TABLE, VIEW,
// MATERIALIZED VIEW, INDEX, ...; any case) and "" otherwise. Renderers then
// write "DROP  name", which does not parse: guessing an object type would
// silently change what is dropped.
func DropObjectTypeText(s string) string { return keywordOneOf(s, dropObjectTypeKeywords) }

// NullTreatmentText returns s when it is IGNORE NULLS or RESPECT NULLS (any
// case) and "" otherwise; an unknown null treatment is dropped.
func NullTreatmentText(s string) string { return keywordOneOf(s, nullTreatmentKeywords) }

// IntervalQualifierText returns s when it is an interval qualifier the parser
// produces (a datetime field or MySQL unit such as DAY or YEAR_MONTH, or
// "<field> TO <field>" such as DAY TO SECOND; any case) and "" otherwise; an
// unknown qualifier is dropped.
func IntervalQualifierText(s string) string {
	if keywordOneOf(s, intervalLeadingFields) != "" {
		return s
	}
	lead, rest, ok := strings.Cut(s, " ")
	if !ok || len(rest) < 3 || !strings.EqualFold(rest[:3], "TO ") {
		return ""
	}
	if keywordOneOf(lead, intervalLeadingFields) == "" ||
		keywordOneOf(rest[3:], intervalTrailingFields) == "" {
		return ""
	}
	return s
}

// SetOperatorText returns s when it is a set operator (UNION, EXCEPT,
// INTERSECT, optionally followed by ALL or DISTINCT; any case) and ""
// otherwise. Dropping an unknown operator would merge the two queries into
// consecutive statements, so renderers write it as UNION followed by the
// double-quoted text (see writeSetOperator), which fails to parse.
func SetOperatorText(s string) string { return keywordOneOf(s, setOperatorKeywords) }

// ColumnConstraintText returns s when it is a column constraint kind written
// as bare keyword text (see columnConstraintKeywords; any case) and ""
// otherwise; an unknown constraint is dropped.
func ColumnConstraintText(s string) string { return keywordOneOf(s, columnConstraintKeywords) }

// PartitionByText returns s when it is a PARTITION BY method (RANGE, LIST,
// HASH, KEY, LINEAR HASH, LINEAR KEY; any case) and "" otherwise. Renderers
// then write "PARTITION BY  (cols)", which does not parse.
func PartitionByText(s string) string { return keywordOneOf(s, partitionByKeywords) }

// AlterTableActionText returns s when it is an ALTER TABLE action keyword
// (see alterTableActionKeywords; any case) and "" otherwise; an unknown
// action is dropped, leaving an ALTER TABLE that does not parse.
func AlterTableActionText(s string) string { return keywordOneOf(s, alterTableActionKeywords) }

// TableOptionNameText returns s when it is a table option name (ENGINE,
// CHARSET, COLLATE, COMMENT, ...; any case) and "" otherwise; an option with
// an unknown name is dropped.
func TableOptionNameText(s string) string { return keywordOneOf(s, tableOptionNames) }

// ViewWithOptionText returns s when it is a view WITH option (CHECK OPTION,
// CASCADED CHECK OPTION, LOCAL CHECK OPTION; any case) and "" otherwise; an
// unknown option is dropped.
func ViewWithOptionText(s string) string { return keywordOneOf(s, viewWithOptionKeywords) }

// MergeWhenText returns s when it is a spelled-out MERGE WHEN kind (MATCHED,
// NOT MATCHED [BY SOURCE|BY TARGET]; any case) and "" otherwise. Renderers
// write the parser's NOT_MATCHED forms themselves; for an unknown kind they
// write "WHEN  THEN", which does not parse.
func MergeWhenText(s string) string { return keywordOneOf(s, mergeWhenKeywords) }

// MergeActionText returns s when it is a MERGE action written as bare
// keyword text (DELETE, DO NOTHING; any case) and "" otherwise; renderers
// write UPDATE and INSERT themselves, and for an unknown action leave "THEN"
// without one, which does not parse.
func MergeActionText(s string) string { return keywordOneOf(s, mergeActionKeywords) }

// isShowWord reports whether s is one bare word: an ASCII letter or '_'
// followed by letters, digits and '_'.
func isShowWord(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c|0x20 < 'a' || c|0x20 > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// IsShowTypeText reports whether a SHOW statement kind can be written bare:
// it is one word (TABLES, PROCESSLIST) or CREATE followed by one word (CREATE
// TABLE). The parser stores the upper-cased text of any single token after
// SHOW (or SHOW CREATE), so the kind is not a closed set, but it never holds
// more than one word after the optional CREATE; SHOW and SHOW CREATE consume
// exactly that word, so a bare word cannot start another statement.
func IsShowTypeText(s string) bool {
	if isShowWord(s) {
		return true
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "CREATE ") {
		return isShowWord(s[7:])
	}
	return false
}

// keywordOneOf returns s when it equals one of allowed, ignoring ASCII case,
// and "" otherwise.
func keywordOneOf(s string, allowed []string) string {
	for _, a := range allowed {
		if len(s) == len(a) && strings.EqualFold(s, a) {
			return s
		}
	}
	return ""
}

// The keyword sets of fields whose parser values form a small fixed set; the
// renderers write such a field only when it is one of these (see the *Text
// functions below), so even plain words outside the set are dropped.
var (
	cascadeKeywords           = []string{"CASCADE", "RESTRICT", "CASCADE CONSTRAINTS"}
	sortDirectionKeywords     = []string{"ASC", "DESC"}
	fetchTypeKeywords         = []string{"FIRST", "NEXT"}
	lockTypeKeywords          = []string{"UPDATE", "SHARE", "NO KEY UPDATE", "KEY SHARE"}
	referentialActionKeywords = []string{"CASCADE", "RESTRICT", "SET NULL", "SET DEFAULT", "NO ACTION"}
	frameUnitKeywords         = []string{"ROWS", "RANGE", "GROUPS"}
	frameBoundKeywords        = []string{"UNBOUNDED PRECEDING", "UNBOUNDED FOLLOWING", "CURRENT ROW", "PRECEDING", "FOLLOWING"}
	frameOffsetKeywords       = []string{"PRECEDING", "FOLLOWING"}
	frameExcludeKeywords      = []string{"CURRENT ROW", "GROUP", "TIES", "NO OTHERS"}
)

// CascadeText returns s when it is CASCADE or RESTRICT (any case), the drop
// behavior of DROP and TRUNCATE, and "" otherwise.
func CascadeText(s string) string { return keywordOneOf(s, cascadeKeywords) }

// SortDirectionText returns s when it is ASC or DESC (any case), and ""
// otherwise.
func SortDirectionText(s string) string { return keywordOneOf(s, sortDirectionKeywords) }

// FetchTypeText returns s when it is FIRST or NEXT (any case), and FIRST
// otherwise: FETCH FIRST and FETCH NEXT mean the same.
func FetchTypeText(s string) string {
	if t := keywordOneOf(s, fetchTypeKeywords); t != "" {
		return t
	}
	return "FIRST"
}

// LockTypeText returns s when it is a row-locking strength (UPDATE, SHARE,
// NO KEY UPDATE, KEY SHARE; any case), and "" otherwise.
func LockTypeText(s string) string { return keywordOneOf(s, lockTypeKeywords) }

// ReferentialActionText returns s when it is a foreign-key ON DELETE / ON
// UPDATE action (CASCADE, RESTRICT, SET NULL, SET DEFAULT, NO ACTION; any
// case), and "" otherwise.
func ReferentialActionText(s string) string { return keywordOneOf(s, referentialActionKeywords) }

// FrameUnitText returns s when it is a window frame unit (ROWS, RANGE,
// GROUPS; any case), and "" otherwise.
func FrameUnitText(s string) string { return keywordOneOf(s, frameUnitKeywords) }

// FrameBoundText returns s when it is a window frame bound kind (UNBOUNDED
// PRECEDING / FOLLOWING, CURRENT ROW, PRECEDING, FOLLOWING; any case) or a
// hand-built numeric bound that carries its offset in the kind ("1
// PRECEDING"), and "" otherwise.
func FrameBoundText(s string) string {
	if t := keywordOneOf(s, frameBoundKeywords); t != "" {
		return t
	}
	if n, kind, ok := strings.Cut(s, " "); ok && IsPlainNumberText(n) &&
		keywordOneOf(kind, frameOffsetKeywords) != "" {
		return s
	}
	return ""
}

// FrameExcludeText returns s when it is a window frame exclusion (CURRENT
// ROW, GROUP, TIES, NO OTHERS; any case), and "" otherwise.
func FrameExcludeText(s string) string { return keywordOneOf(s, frameExcludeKeywords) }

// IsPlainNumberText reports whether s is a bare numeric literal as the
// tokenizer stores it (digits, '.', an exponent with an optional sign), such
// as the ClickHouse SAMPLE ratio 0.1 or 1/10's parts.
func IsPlainNumberText(s string) bool {
	if s == "" {
		return false
	}
	digits := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits = true
		case c == '.':
		case (c == 'e' || c == 'E') && digits && i+1 < len(s):
			if s[i+1] == '+' || s[i+1] == '-' {
				i++
			}
		default:
			return false
		}
	}
	return digits
}

// writeShowType writes the SHOW statement kind. A bare word or CREATE plus
// a bare word (TABLES, CREATE TABLE, see IsShowTypeText) is written as is;
// the parser also stores the upper-cased text of a quoted kind (SHOW "x",
// SHOW CREATE "x" name), and any other text can only come from a hand-built
// AST: both are written as one double-quoted token, which SHOW consumes as
// the kind, so the text cannot start another statement.
func writeShowType(buf *bytes.Buffer, t string) {
	if t == "" || IsShowTypeText(t) {
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

// writeDottedIdentifierStyle is writeDottedIdentifier quoting with the
// delimiters of style (see writeDelimitedIdentifier).
func writeDottedIdentifierStyle(buf *bytes.Buffer, name string, style rune) {
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		if isReservedName(part, true) || identifierNeedsQuoting(part) {
			writeDelimitedIdentifier(buf, part, style)
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

// writeDelimitedIdentifier writes name as a delimited identifier using the
// delimiters of style: `name` for '`', [name] for '[', and ANSI "name"
// otherwise. The closing delimiter is doubled inside the name.
func writeDelimitedIdentifier(buf *bytes.Buffer, name string, style rune) {
	var open, closing byte
	switch style {
	case '`':
		open, closing = '`', '`'
	case '[':
		open, closing = '[', ']'
	default:
		writeQuotedIdentifier(buf, name)
		return
	}
	buf.WriteByte(open)
	for i := 0; i < len(name); i++ {
		if name[i] == closing {
			buf.WriteByte(closing)
		}
		buf.WriteByte(name[i])
	}
	buf.WriteByte(closing)
}

// isVariableName reports whether name is a session or system variable
// reference that is written bare: '@' or '@@' followed by letters, digits,
// '_', '$' and '.' (@x, @@VERSION, @@session.sql_mode). Quoting it would
// turn the variable into an identifier.
func isVariableName(name string) bool {
	i := 0
	for i < len(name) && i < 2 && name[i] == '@' {
		i++
	}
	if i == 0 || i == len(name) || name[i] == '.' {
		return false
	}
	for ; i < len(name); i++ {
		c := name[i]
		if c != '_' && c != '$' && c != '.' && (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'z') {
			return false
		}
	}
	return true
}
