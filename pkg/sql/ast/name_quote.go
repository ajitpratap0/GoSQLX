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

package ast

import (
	"bytes"
	"strings"
	"unicode"
)

// NameQuote records how a name was delimited in the source, for the names
// the AST keeps as plain strings (aliases, table, function and CTE names) and
// for the parts of an Identifier. It packs three facts into one byte:
//
//   - which dot-separated parts of the name were written as delimited
//     identifiers that must stay delimited to keep their meaning (a name
//     quoted for its letter case, such as "CreatedAt", or a keyword such as
//     "table"). Part 0 is the last part of the name, part 1 the one before
//     it, and so on; up to five parts are recorded.
//   - the delimiter the source used: ANSI double quotes, MySQL backticks or
//     SQL Server brackets. Renderers use it both for the recorded parts and
//     for parts that need delimiters because of their content (a space, a
//     reserved word), so a MySQL `exists` alias is written back with
//     backticks rather than in double quotes, which MySQL reads as a string.
//   - BareHash: the name was written bare in Oracle, where '#' may appear in
//     an identifier after its first character (s.serial#). Such a part is
//     written bare again; delimiting it would make it case-sensitive.
//
// The zero value means "nothing recorded": names are then quoted only when
// their content requires it, in ANSI double quotes. Parts that were
// delimited in the source but read the same bare (a lowercase "users" in
// PostgreSQL) are not recorded, so formatting still drops those quotes.
type NameQuote uint8

const (
	nameQuoteMaxParts                = 5
	nameQuotePartsMask     NameQuote = 1<<nameQuoteMaxParts - 1
	nameQuoteStyleShift              = nameQuoteMaxParts
	nameQuoteStyleMask     NameQuote = 3 << nameQuoteStyleShift
	nameQuoteBareHash      NameQuote = 1 << 7
	nameQuoteStyleANSI     NameQuote = 1 << nameQuoteStyleShift
	nameQuoteStyleBacktick NameQuote = 2 << nameQuoteStyleShift
	nameQuoteStyleBracket  NameQuote = 3 << nameQuoteStyleShift
)

// NameQuoteOf returns a NameQuote that records the delimiter style ('"',
// '`' or '[') and marks no part. Any other rune records no style.
func NameQuoteOf(style rune) NameQuote {
	return NameQuote(0).WithStyle(style)
}

// QuotedName returns a NameQuote for a single-part name that was written
// delimited with style and must stay delimited.
func QuotedName(style rune) NameQuote {
	return NameQuoteOf(style).WithPart(0)
}

// WithStyle returns q with its delimiter set to style ('"', '`' or '[').
// Any other rune clears the recorded style.
func (q NameQuote) WithStyle(style rune) NameQuote {
	q &^= nameQuoteStyleMask
	switch style {
	case '"':
		q |= nameQuoteStyleANSI
	case '`':
		q |= nameQuoteStyleBacktick
	case '[':
		q |= nameQuoteStyleBracket
	}
	return q
}

// WithPart returns q with part i (0 = the last part) marked as delimited.
// Parts beyond the fifth are ignored.
func (q NameQuote) WithPart(i int) NameQuote {
	if i < 0 || i >= nameQuoteMaxParts {
		return q
	}
	return q | 1<<uint(i)
}

// AppendPart returns q extended by one more trailing part: the parts already
// recorded move one position towards the front of the name, and the new last
// part is marked when keep is true. Parsers build the NameQuote of a dotted
// name by calling it once per part, left to right.
func (q NameQuote) AppendPart(keep bool) NameQuote {
	parts := (q << 1) & nameQuotePartsMask
	if keep {
		parts |= 1
	}
	return q&^nameQuotePartsMask | parts
}

// WithParts returns q with the part marks of other added; the style of
// other is used when q records none.
func (q NameQuote) WithParts(other NameQuote) NameQuote {
	q |= other & nameQuotePartsMask
	if q&nameQuoteStyleMask == 0 {
		q |= other & nameQuoteStyleMask
	}
	return q
}

// Part reports whether part i (0 = the last part) must stay delimited.
func (q NameQuote) Part(i int) bool {
	if i < 0 || i >= nameQuoteMaxParts {
		return false
	}
	return q&(1<<uint(i)) != 0
}

// HasParts reports whether any part must stay delimited.
func (q NameQuote) HasParts() bool { return q&nameQuotePartsMask != 0 }

// HasStyle reports whether q records a delimiter style.
func (q NameQuote) HasStyle() bool { return q&nameQuoteStyleMask != 0 }

// Style returns the recorded delimiter: '"', '`' or '['. It is '"' when no
// style is recorded.
func (q NameQuote) Style() rune {
	switch q & nameQuoteStyleMask {
	case nameQuoteStyleBacktick:
		return '`'
	case nameQuoteStyleBracket:
		return '['
	}
	return '"'
}

// WithDefaultStyle returns q with its delimiter set to style when q records
// none. Renderers that know the target dialect use it so names that need
// delimiters only because of their content use the dialect's delimiter.
func (q NameQuote) WithDefaultStyle(style rune) NameQuote {
	if q.HasStyle() {
		return q
	}
	return q.WithStyle(style)
}

// BareHash reports whether the name was written bare in Oracle and may
// contain '#' after its first character (see NameQuote).
func (q NameQuote) BareHash() bool { return q&nameQuoteBareHash != 0 }

// WithBareHash returns q with the BareHash mark set to on.
func (q NameQuote) WithBareHash(on bool) NameQuote {
	if on {
		return q | nameQuoteBareHash
	}
	return q &^ nameQuoteBareHash
}

// IdentifierCaseFolding describes how a dialect matches the letter case of
// unquoted identifiers, which decides whether a name quoted only for its
// case needs its quotes.
type IdentifierCaseFolding uint8

const (
	// FoldNone: quoting does not change how a name's case is matched
	// (MySQL, MariaDB, SQL Server, SQLite, ClickHouse, BigQuery).
	FoldNone IdentifierCaseFolding = iota
	// FoldLower: unquoted names fold to lower case (PostgreSQL, Redshift,
	// generic SQL), so a quoted name with an upper-case letter differs.
	FoldLower
	// FoldUpper: unquoted names fold to upper case (Oracle, Snowflake), so
	// a quoted name with a lower-case letter differs.
	FoldUpper
)

// DelimitedNameMustStayQuoted reports whether a name that the source wrote as
// a delimited identifier must keep its delimiters to mean the same name: it
// contains a character a bare identifier cannot, it is a word the parser
// rejects bare in some name position, or the dialect would fold it bare to a
// different name (see IdentifierCaseFolding). Keywords outside the parser's
// reserved-name lists are the caller's to check.
func DelimitedNameMustStayQuoted(name string, fold IdentifierCaseFolding) bool {
	if name == "" || !isBareNameChars(name, false) || isReservedName(name, false) {
		return true
	}
	if fold == FoldNone {
		return false
	}
	upper := fold == FoldUpper
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
			if !upper {
				return true
			}
		case c >= 'a' && c <= 'z':
			if upper {
				return true
			}
		case c >= 0x80:
			for _, r := range name[i:] {
				if (!upper && unicode.IsUpper(r)) || (upper && unicode.IsLower(r)) {
					return true
				}
			}
			return false
		}
	}
	return false
}

// isOracleBareName reports whether name can be written bare in Oracle: a
// letter followed by letters, digits, '_', '$' and '#'.
func isOracleBareName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case unicode.IsLetter(r):
		case i > 0 && (r == '_' || r == '$' || r == '#' || unicode.IsDigit(r)):
		case i > 0 && r >= 0x80 && (unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r)):
		default:
			return false
		}
	}
	return true
}

// partDelimited reports whether one part of a name is written delimited:
// it is recorded as kept, or its content needs delimiters (need) and it is
// not an Oracle bare name with '#' recorded as such.
func partDelimited(part string, keep, need bool, q NameQuote) bool {
	if keep {
		return true
	}
	if need && q.BareHash() && strings.IndexByte(part, '#') > 0 && isOracleBareName(part) && !isReservedName(part, true) {
		return false
	}
	return need
}

// writeNamePart writes part delimited with style when delimited is true and
// bare otherwise.
func writeNamePart(buf *bytes.Buffer, part string, delimited bool, style rune) {
	if delimited {
		writeDelimitedIdentifier(buf, part, style)
		return
	}
	buf.WriteString(part)
}

// writeNameQ writes a CTE name, a column-list entry or a select-item alias
// like writeName, honouring the delimiters recorded in q.
func writeNameQ(buf *bytes.Buffer, name string, q NameQuote) {
	if q == 0 {
		writeName(buf, name)
		return
	}
	writeNamePart(buf, name, partDelimited(name, q.Part(0), nameNeedsQuoting(name, false), q), q.Style())
}

// writeTableAliasQ writes a table alias like writeTableAlias, honouring the
// delimiters recorded in q.
func writeTableAliasQ(buf *bytes.Buffer, name string, q NameQuote) {
	if q == 0 {
		writeTableAlias(buf, name)
		return
	}
	writeNamePart(buf, name, partDelimited(name, q.Part(0), tableAliasNeedsQuoting(name), q), q.Style())
}

// writeNameListQ writes names separated by ", " like writeNameList; qs, when
// not nil, holds the NameQuote of each name by index.
func writeNameListQ(buf *bytes.Buffer, names []string, qs []NameQuote) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeNameQ(buf, n, nameQuoteAt(qs, i))
	}
}

// writeColumnNameListQ writes names separated by ", " like
// writeColumnNameList; qs, when not nil, holds the NameQuote of each name.
func writeColumnNameListQ(buf *bytes.Buffer, names []string, qs []NameQuote) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeTableAliasQ(buf, n, nameQuoteAt(qs, i))
	}
}

// nameQuoteAt returns qs[i], or the zero NameQuote when qs is too short.
func nameQuoteAt(qs []NameQuote, i int) NameQuote {
	if i < len(qs) {
		return qs[i]
	}
	return 0
}

// countNameParts returns the number of dot-separated parts of name.
func countNameParts(name string) int {
	return strings.Count(name, ".") + 1
}

// writeQualifiedNameQ writes a possibly dotted table or view name like
// writeQualifiedName, honouring the delimiters recorded in q.
func writeQualifiedNameQ(buf *bytes.Buffer, name string, q NameQuote) {
	if q == 0 || name == "" || isStageReference(name) {
		writeQualifiedName(buf, name)
		return
	}
	style := q.Style()
	idx := countNameParts(name) - 1
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		need := part == "" || nameNeedsQuoting(part, true)
		writeNamePart(buf, part, partDelimited(part, q.Part(idx), need, q), style)
		if dot < 0 {
			return
		}
		buf.WriteByte('.')
		name = name[dot+1:]
		idx--
	}
}

// writeFunctionNameQ writes a possibly schema-qualified function name like
// writeFunctionName, honouring the delimiters recorded in q: a part written
// delimited in the source (s."select", "MySchema"."MyFunc") keeps its
// delimiters, while bare keyword parts (DBMS_RANDOM.VALUE) stay bare.
func writeFunctionNameQ(buf *bytes.Buffer, name string, q NameQuote) {
	if q == 0 || name == "" {
		writeFunctionName(buf, name)
		return
	}
	style := q.Style()
	multi := strings.IndexByte(name, '.') >= 0
	idx := countNameParts(name) - 1
	for {
		dot := strings.IndexByte(name, '.')
		part := name
		if dot >= 0 {
			part = name[:dot]
		}
		need := functionNamePartNeedsQuoting(part, !multi)
		writeNamePart(buf, part, partDelimited(part, q.Part(idx), need, q), style)
		if dot < 0 {
			return
		}
		buf.WriteByte('.')
		name = name[dot+1:]
		idx--
	}
}

// writeIdentifierQualifier writes the Table qualifier of an Identifier,
// quoting each part like writeDottedIdentifierStyle and additionally every
// part recorded in q. The qualifier's last part is part 1 of the whole
// reference (the column name is part 0).
func writeIdentifierQualifier(buf *bytes.Buffer, table string, style rune, q NameQuote) {
	idx := countNameParts(table)
	for {
		dot := strings.IndexByte(table, '.')
		part := table
		if dot >= 0 {
			part = table[:dot]
		}
		need := isReservedName(part, true) || identifierNeedsQuoting(part)
		writeNamePart(buf, part, partDelimited(part, q.Part(idx), need, q), style)
		if dot < 0 {
			return
		}
		buf.WriteByte('.')
		table = table[dot+1:]
		idx--
	}
}

// quoteWith renders name through write into a pooled buffer.
func quoteWith(name string, q NameQuote, write func(*bytes.Buffer, string, NameQuote)) string {
	buf := getBuf()
	defer putBuf(buf)
	write(buf, name, q)
	return buf.String()
}

// QuoteNameWith returns a single-part name (a CTE name, a CTE/view
// column-list entry, a select-item alias) as QuoteName does, honouring the
// delimiters recorded in q: a part recorded as delimited keeps its
// delimiters, and any delimiters are written in q's style.
func QuoteNameWith(name string, q NameQuote) string {
	if q == 0 || (!q.HasParts() && !nameNeedsQuoting(name, false)) {
		return QuoteName(name)
	}
	return quoteWith(name, q, writeNameQ)
}

// QuoteTableAliasWith returns a table alias as QuoteTableAlias does,
// honouring the delimiters recorded in q.
func QuoteTableAliasWith(name string, q NameQuote) string {
	if q == 0 || (!q.HasParts() && !tableAliasNeedsQuoting(name)) {
		return QuoteTableAlias(name)
	}
	return quoteWith(name, q, writeTableAliasQ)
}

// QuoteColumnNameWith returns a single-part DDL column name or column-list
// entry as QuoteColumnName does, honouring the delimiters recorded in q.
func QuoteColumnNameWith(name string, q NameQuote) string {
	return QuoteTableAliasWith(name, q)
}

// QuoteQualifiedNameWith returns a dotted table or view name as
// QuoteQualifiedName does, honouring the delimiters recorded in q.
func QuoteQualifiedNameWith(name string, q NameQuote) string {
	if q == 0 || name == "" || (!q.HasParts() && !qualifiedNameNeedsQuoting(name)) {
		return QuoteQualifiedName(name)
	}
	return quoteWith(name, q, writeQualifiedNameQ)
}

// QuoteFunctionNameWith returns a possibly qualified function name as the
// SQL() of a FunctionCall writes it, honouring the delimiters recorded in q.
func QuoteFunctionNameWith(name string, q NameQuote) string {
	return quoteWith(name, q, writeFunctionNameQ)
}

// writeQualifiedNameListQ writes names separated by ", " like
// writeQualifiedNameList; qs, when not nil, holds each name's NameQuote.
func writeQualifiedNameListQ(buf *bytes.Buffer, names []string, qs []NameQuote) {
	for i, n := range names {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeQualifiedNameQ(buf, n, nameQuoteAt(qs, i))
	}
}

// writeConstraintNameQ writes a table constraint name like
// writeConstraintName, honouring the delimiters recorded in q.
func writeConstraintNameQ(buf *bytes.Buffer, name string, q NameQuote) {
	if q == 0 {
		writeConstraintName(buf, name)
		return
	}
	writeNamePart(buf, name, partDelimited(name, q.Part(0), constraintNameNeedsQuoting(name), q), q.Style())
}

// QuoteConstraintNameWith returns a table constraint name as
// QuoteConstraintName does, honouring the delimiters recorded in q.
func QuoteConstraintNameWith(name string, q NameQuote) string {
	if q == 0 || (!q.HasParts() && !constraintNameNeedsQuoting(name)) {
		return QuoteConstraintName(name)
	}
	return quoteWith(name, q, writeConstraintNameQ)
}
