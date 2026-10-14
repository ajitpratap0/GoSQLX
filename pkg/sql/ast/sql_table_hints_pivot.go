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
	"unicode"
	"unicode/utf8"
)

// isBareTableHint reports whether h is a bare word ([A-Za-z_][A-Za-z0-9_]*),
// the only table-hint form the parser accepts and the only one written
// verbatim.
func isBareTableHint(h string) bool {
	if h == "" {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// QuoteTableHint returns a SQL Server table hint ready to write inside
// WITH (...): a bare word is returned unchanged, anything else (only possible
// in a hand-built AST) is double-quoted with embedded quotes doubled so it
// cannot end the hint list or the statement.
func QuoteTableHint(h string) string {
	if isBareTableHint(h) {
		return h
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, h)
	return buf.String()
}

// writeTableHints writes SQL Server table hints as " WITH (h1, h2)". Bare-word
// hints (the parser upper-cases them) are written verbatim; any other hint is
// double-quoted (see QuoteTableHint).
func writeTableHints(buf *bytes.Buffer, hints []string) {
	if len(hints) == 0 {
		return
	}
	buf.WriteString(" WITH (")
	for i, h := range hints {
		if i > 0 {
			buf.WriteString(", ")
		}
		if isBareTableHint(h) {
			buf.WriteString(h)
		} else {
			writeQuotedIdentifier(buf, h)
		}
	}
	buf.WriteByte(')')
}

// QuotePivotColumn returns a PIVOT/UNPIVOT column name (PivotColumn,
// ValueColumn or NameColumn) ready to write: a name made only of letters,
// digits, '_', '*' and '.' (and not starting a part with a digit) is returned
// unchanged, except that a dot-separated part that is a word the parser
// rejects bare in every name position ("select") is double-quoted; anything
// else is double-quoted as a whole with embedded quotes doubled.
func QuotePivotColumn(name string) string {
	if !pivotColumnNeedsQuoting(name) {
		return name
	}
	buf := getBuf()
	defer putBuf(buf)
	writePivotColumn(buf, name)
	return buf.String()
}

// pivotColumnNeedsQuoting reports whether writePivotColumn would quote some
// part of name.
func pivotColumnNeedsQuoting(name string) bool {
	return identifierNeedsQuoting(name) || qualifierNeedsQuoting(name)
}

// writePivotColumn writes a PIVOT/UNPIVOT column name (see QuotePivotColumn).
func writePivotColumn(buf *bytes.Buffer, name string) {
	if identifierNeedsQuoting(name) {
		writeQuotedIdentifier(buf, name)
		return
	}
	writeDottedIdentifier(buf, name)
}

// QuotePivotItem returns a PIVOT IN value or UNPIVOT IN column ready to
// write. The parser stores each entry in its source form, "atom" or
// "atom AS atom", where an atom is a bare word or number, a 'string', or a
// "double-quoted", [bracketed] or `backticked` identifier, with delimiters
// escaped by doubling. Such an entry is returned unchanged. Anything else
// (only possible in a hand-built AST) is double-quoted as a whole so it cannot
// close the IN list, the clause or the statement.
func QuotePivotItem(item string) string {
	if isWellFormedPivotItem(item) {
		return item
	}
	buf := getBuf()
	defer putBuf(buf)
	writeQuotedIdentifier(buf, item)
	return buf.String()
}

func writePivotItem(buf *bytes.Buffer, item string) {
	if isWellFormedPivotItem(item) {
		buf.WriteString(item)
		return
	}
	writeQuotedIdentifier(buf, item)
}

// isWellFormedPivotItem reports whether item is "atom" or "atom AS atom"
// (see QuotePivotItem).
func isWellFormedPivotItem(item string) bool {
	n := pivotAtomLen(item)
	if n == 0 {
		return false
	}
	rest := item[n:]
	if rest == "" {
		return true
	}
	const as = " AS "
	if len(rest) <= len(as) || rest[:len(as)] != as {
		return false
	}
	rest = rest[len(as):]
	return pivotAtomLen(rest) == len(rest)
}

// pivotAtomLen returns the length of the atom at the start of s, or 0 if s
// does not start with a well-formed atom. A delimited atom must close with
// its delimiter; a delimiter inside it must be doubled. In a 'string' a
// backslash must not precede a quote, so the string ends at the same place
// whether or not the reader treats backslash as an escape.
func pivotAtomLen(s string) int {
	if s == "" {
		return 0
	}
	switch s[0] {
	case '\'':
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if i+1 >= len(s) || s[i+1] == '\'' {
					return 0
				}
				i++
			case '\'':
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				return i + 1
			}
		}
		return 0
	case '"', '`', '[':
		closer := s[0]
		if closer == '[' {
			closer = ']'
		}
		for i := 1; i < len(s); i++ {
			if s[i] != closer {
				continue
			}
			if i+1 < len(s) && s[i+1] == closer {
				i++
				continue
			}
			return i + 1
		}
		return 0
	}
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		ok := r == '_' || r == '.' || r == '$' || r == '#' || r == '@' ||
			unicode.IsLetter(r) || unicode.IsDigit(r) ||
			(i > 0 && r >= utf8.RuneSelf && (unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r)))
		if !ok || r == utf8.RuneError {
			break
		}
		i += size
	}
	return i
}

// writePivotClause writes " PIVOT (agg FOR col IN (v1, v2))". The pivot
// column is quoted when it is not a plain name, and each IN value is written
// in its stored source form (e.g. [Q1], 'JAN', 1 AS one) when well formed,
// otherwise double-quoted (see QuotePivotItem).
func writePivotClause(buf *bytes.Buffer, p *PivotClause) {
	if p == nil {
		return
	}
	buf.WriteString(" PIVOT (")
	writeExpr(buf, p.AggregateFunction)
	buf.WriteString(" FOR ")
	writePivotColumn(buf, p.PivotColumn)
	buf.WriteString(" IN (")
	for i, v := range p.InValues {
		if i > 0 {
			buf.WriteString(", ")
		}
		writePivotItem(buf, v)
	}
	buf.WriteString("))")
}

// writeUnpivotClause writes " UNPIVOT (val FOR name IN (c1, c2))", quoting
// names and IN columns the same way as writePivotClause.
func writeUnpivotClause(buf *bytes.Buffer, u *UnpivotClause) {
	if u == nil {
		return
	}
	buf.WriteString(" UNPIVOT (")
	writePivotColumn(buf, u.ValueColumn)
	buf.WriteString(" FOR ")
	writePivotColumn(buf, u.NameColumn)
	buf.WriteString(" IN (")
	for i, c := range u.InColumns {
		if i > 0 {
			buf.WriteString(", ")
		}
		writePivotItem(buf, c)
	}
	buf.WriteString("))")
}
