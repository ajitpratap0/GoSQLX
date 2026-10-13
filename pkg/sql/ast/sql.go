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

// This file implements SQL() string methods on all AST node types,
// enabling AST→SQL roundtrip serialization.
package ast

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// bufPool reuses bytes.Buffer instances for SQL serialization.
//
// bytes.Buffer is used instead of strings.Builder because Reset() truncates
// the buffer to length 0 but keeps its backing array, so a pooled buffer
// actually carries its grown capacity into the next call. strings.Builder's
// Reset() sets its slice to nil, which meant the previous pool only reused
// the 32-byte header. buf.String() copies the bytes, so a returned string
// never aliases the pooled array; a pooled buffer carries capacity only,
// never content, and no AST node retains one.
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// getBuf retrieves an empty bytes.Buffer from the pool.
// Always pair with putBuf (normally via defer).
func getBuf() *bytes.Buffer {
	b, ok := bufPool.Get().(*bytes.Buffer)
	if !ok {
		b = new(bytes.Buffer)
	}
	b.Reset()
	return b
}

// putBuf resets b and returns it to the pool. Buffers that grew beyond
// 64 KiB are dropped to avoid pinning excess memory.
func putBuf(b *bytes.Buffer) {
	if b == nil {
		return
	}
	if b.Cap() > 64*1024 {
		return
	}
	b.Reset()
	bufPool.Put(b)
}

// SQL returns the SQL string representation of the AST.
func (a AST) SQL() string {
	buf := getBuf()
	defer putBuf(buf)
	first := true
	for _, stmt := range a.Statements {
		if _, ok := stmt.(interface{ SQL() string }); !ok {
			continue
		}
		if !first {
			buf.WriteString(";\n")
		}
		first = false
		writeStmt(buf, stmt)
	}
	return buf.String()
}

// ============================================================
// Expressions
// ============================================================

// SQL returns the SQL representation of the identifier.
// Identifiers are emitted unescaped because they have already been validated
// during parsing - the tokenizer and parser only accept syntactically valid
// identifiers (or quoted identifiers whose quotes are preserved in the AST).
// Re-escaping here would be redundant and could introduce double-quoting bugs.
func (i *Identifier) SQL() string {
	if i == nil {
		return ""
	}
	if !identifierNeedsQuoting(i.Name) && (i.Table == "" || !qualifierNeedsQuoting(i.Table)) {
		if i.Table == "" {
			return i.Name
		}
		return i.Table + "." + i.Name
	}
	buf := getBuf()
	defer putBuf(buf)
	i.writeSQL(buf)
	return buf.String()
}

func (i *Identifier) writeSQL(buf *bytes.Buffer) {
	if i == nil {
		return
	}
	if i.Table != "" {
		writeDottedIdentifier(buf, i.Table)
		buf.WriteByte('.')
	}
	writeSafeIdentifier(buf, i.Name)
}

// qualifierNeedsQuoting reports whether some dot-separated part of the
// non-empty qualifier name would be quoted by writeDottedIdentifier.
func qualifierNeedsQuoting(name string) bool {
	return identifierNeedsQuoting(name) || name[0] == '.' || name[len(name)-1] == '.' ||
		strings.Contains(name, "..")
}

// writeDottedIdentifier writes a possibly multi-part qualifier such as
// "db.t" or "c.s.t", quoting each dot-separated part on its own so that
// "my-db.t" renders as "my-db".t (two identifiers) rather than "my-db.t"
// (one). A dot is always treated as a part separator; see Identifier.Table.
func writeDottedIdentifier(buf *bytes.Buffer, name string) {
	for {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			writeSafeIdentifier(buf, name)
			return
		}
		writeSafeIdentifier(buf, name[:dot])
		buf.WriteByte('.')
		name = name[dot+1:]
	}
}

// identifierNeedsQuoting reports whether name must be double-quoted: it is
// empty or contains a character other than letters, digits, '_', '*' and '.'.
func identifierNeedsQuoting(name string) bool {
	if name == "" {
		return true
	}
	for _, r := range name {
		if r != '_' && r != '*' && r != '.' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// writeSafeIdentifier writes name unchanged if it contains only safe
// characters (letters, digits, underscores, dots, *). Otherwise it writes it
// double-quoted with embedded quotes doubled, to prevent SQL identifier
// injection. An empty name is written as "".
func writeSafeIdentifier(buf *bytes.Buffer, name string) {
	if !identifierNeedsQuoting(name) {
		buf.WriteString(name)
		return
	}
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

// stringLiteralNeedsEscape reports whether s contains a byte that
// writeEscapedStringLiteral would rewrite: a quote, backslash, NUL, CR, LF,
// Ctrl-Z, or any non-ASCII byte (which goes through the rune loop so invalid
// UTF-8 is replaced with U+FFFD).
func stringLiteralNeedsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= utf8.RuneSelf, c == '\'', c == '\\', c == 0, c == '\n', c == '\r', c == 0x1a:
			return true
		}
	}
	return false
}

// writeEscapedStringLiteral escapes s for safe inclusion in a single-quoted
// SQL literal, handling characters that can lead to SQL injection.
func writeEscapedStringLiteral(buf *bytes.Buffer, s string) {
	if !stringLiteralNeedsEscape(s) {
		buf.WriteString(s)
		return
	}
	for _, r := range s {
		switch r {
		case '\'':
			buf.WriteString("''")
		case '\\':
			buf.WriteString(`\\`)
		case '\x00':
			// Drop null bytes - invalid in SQL string literals.
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\x1a': // Ctrl-Z (EOF on Windows)
			buf.WriteString(`\Z`)
		default:
			buf.WriteRune(r)
		}
	}
}

// literalText renders a literal's Value as text; string Values are returned
// as-is (no allocation), anything else is formatted with %v.
func literalText(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// writeInt writes n in base 10, byte-identical to fmt's %d.
func writeInt(buf *bytes.Buffer, n int64) {
	var tmp [20]byte
	buf.Write(strconv.AppendInt(tmp[:0], n, 10))
}

// SQL returns the SQL literal representation of this value.
// Strings are single-quoted with proper escaping; NULLs are returned as "NULL";
// booleans are returned in uppercase (TRUE/FALSE); numbers are returned as-is.
func (l *LiteralValue) SQL() string {
	if l == nil {
		return ""
	}
	if l.Value == nil || strings.EqualFold(l.Type, "NULL") {
		return "NULL"
	}
	switch {
	case strings.EqualFold(l.Type, "STRING"):
		text := literalText(l.Value)
		if !stringLiteralNeedsEscape(text) {
			return "'" + text + "'"
		}
		buf := getBuf()
		defer putBuf(buf)
		buf.WriteByte('\'')
		writeEscapedStringLiteral(buf, text)
		buf.WriteByte('\'')
		return buf.String()
	case strings.EqualFold(l.Type, "BOOLEAN"):
		return strings.ToUpper(literalText(l.Value))
	default:
		return literalText(l.Value)
	}
}

func (l *LiteralValue) writeSQL(buf *bytes.Buffer) {
	if l == nil {
		return
	}
	if l.Value == nil || strings.EqualFold(l.Type, "NULL") {
		buf.WriteString("NULL")
		return
	}
	switch {
	case strings.EqualFold(l.Type, "STRING"):
		buf.WriteByte('\'')
		writeEscapedStringLiteral(buf, literalText(l.Value))
		buf.WriteByte('\'')
	case strings.EqualFold(l.Type, "BOOLEAN"):
		buf.WriteString(strings.ToUpper(literalText(l.Value)))
	default:
		buf.WriteString(literalText(l.Value))
	}
}

// SQL returns the unquoted identifier name. Used for round-trip serialization.
func (i *Ident) SQL() string {
	if i == nil {
		return ""
	}
	return i.Name
}

func (i *Ident) writeSQL(buf *bytes.Buffer) {
	if i == nil {
		return
	}
	buf.WriteString(i.Name)
}

// SQL returns the SQL representation of this binary expression.
// The operator, left, and right sub-expressions are serialized in infix notation.
// NOT-qualified operators (LIKE, ILIKE, SIMILAR TO) are rendered as "x NOT OP y".
func (b *BinaryExpression) SQL() string {
	if b == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	b.writeSQL(buf)
	return buf.String()
}

func (b *BinaryExpression) writeSQL(buf *bytes.Buffer) {
	if b == nil {
		return
	}
	op := b.Operator
	if b.CustomOp != nil {
		op = b.CustomOp.String()
	}

	// Handle IS NULL / IS NOT NULL (right side is NULL literal).
	// The parser stores the operator as "IS NULL" and uses the Not flag to
	// disambiguate `IS NOT NULL`, so honour it here to avoid dropping NOT.
	if strings.EqualFold(op, "IS NULL") {
		writeExpr(buf, b.Left)
		if b.Not {
			buf.WriteString(" IS NOT NULL")
		} else {
			buf.WriteString(" IS NULL")
		}
		return
	}

	// Handle special operators like LIKE, ILIKE, SIMILAR TO
	if b.Not {
		if canon, ok := notQualifiedOperator(op); ok {
			writeExpr(buf, b.Left)
			buf.WriteString(" NOT ")
			buf.WriteString(canon)
			buf.WriteByte(' ')
			writeExpr(buf, b.Right)
			return
		}
		buf.WriteString("NOT (")
		writeExpr(buf, b.Left)
		buf.WriteByte(' ')
		buf.WriteString(op)
		buf.WriteByte(' ')
		writeExpr(buf, b.Right)
		buf.WriteByte(')')
		return
	}

	writeExpr(buf, b.Left)
	buf.WriteByte(' ')
	buf.WriteString(op)
	buf.WriteByte(' ')
	writeExpr(buf, b.Right)
}

// notQualifiedOperator reports whether op (case-insensitively) is one of the
// operators rendered as "x NOT OP y", returning its upper-case spelling.
func notQualifiedOperator(op string) (string, bool) {
	switch {
	case strings.EqualFold(op, "LIKE"):
		return "LIKE", true
	case strings.EqualFold(op, "ILIKE"):
		return "ILIKE", true
	case strings.EqualFold(op, "SIMILAR TO"):
		return "SIMILAR TO", true
	}
	return "", false
}

// SQL returns the SQL representation of this unary expression.
// Prefix operators (NOT, +, -, etc.) are prepended; the PostgreSQL
// postfix factorial operator (!) is appended.
func (u *UnaryExpression) SQL() string {
	if u == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	u.writeSQL(buf)
	return buf.String()
}

func (u *UnaryExpression) writeSQL(buf *bytes.Buffer) {
	if u == nil {
		return
	}
	switch u.Operator {
	case Not:
		buf.WriteString("NOT ")
		writeExpr(buf, u.Expr)
	case PGPostfixFactorial:
		writeExpr(buf, u.Expr)
		buf.WriteByte('!')
	case Plus:
		buf.WriteByte('+')
		writeExpr(buf, u.Expr)
	case Minus:
		buf.WriteByte('-')
		writeExpr(buf, u.Expr)
	case Prior:
		buf.WriteString("PRIOR ")
		writeExpr(buf, u.Expr)
	default:
		buf.WriteString(u.Operator.String())
		writeExpr(buf, u.Expr)
	}
}

// SQL returns the SQL representation of this aliased expression in the form
// "expr AS alias".
func (a *AliasedExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AliasedExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Expr)
	buf.WriteString(" AS ")
	buf.WriteString(a.Alias)
}

// SQL returns the SQL representation of this CAST expression in the form
// "CAST(expr AS type)".
func (c *CastExpression) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *CastExpression) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	buf.WriteString("CAST(")
	writeExpr(buf, c.Expr)
	buf.WriteString(" AS ")
	buf.WriteString(c.Type)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this CASE expression including all
// WHEN/THEN clauses and an optional ELSE clause.
func (c *CaseExpression) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *CaseExpression) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	buf.WriteString("CASE")
	if c.Value != nil {
		buf.WriteByte(' ')
		writeExpr(buf, c.Value)
	}
	for i := range c.WhenClauses {
		buf.WriteByte(' ')
		c.WhenClauses[i].writeSQL(buf)
	}
	if c.ElseClause != nil {
		buf.WriteString(" ELSE ")
		writeExpr(buf, c.ElseClause)
	}
	buf.WriteString(" END")
}

// SQL returns the SQL representation of this WHEN clause in the form
// "WHEN condition THEN result".
func (w *WhenClause) SQL() string {
	if w == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	w.writeSQL(buf)
	return buf.String()
}

func (w *WhenClause) writeSQL(buf *bytes.Buffer) {
	if w == nil {
		return
	}
	buf.WriteString("WHEN ")
	writeExpr(buf, w.Condition)
	buf.WriteString(" THEN ")
	writeExpr(buf, w.Result)
}

// SQL returns the SQL representation of this BETWEEN expression.
// The NOT modifier is included when BetweenExpression.Not is true.
func (b *BetweenExpression) SQL() string {
	if b == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	b.writeSQL(buf)
	return buf.String()
}

func (b *BetweenExpression) writeSQL(buf *bytes.Buffer) {
	if b == nil {
		return
	}
	writeExpr(buf, b.Expr)
	if b.Not {
		buf.WriteString(" NOT BETWEEN ")
	} else {
		buf.WriteString(" BETWEEN ")
	}
	writeExpr(buf, b.Lower)
	buf.WriteString(" AND ")
	writeExpr(buf, b.Upper)
}

// SQL returns the SQL representation of this IN expression.
// The NOT modifier is included when InExpression.Not is true.
// Supports both value lists "x IN (1, 2, 3)" and subqueries "x IN (SELECT ...)".
func (i *InExpression) SQL() string {
	if i == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	i.writeSQL(buf)
	return buf.String()
}

func (i *InExpression) writeSQL(buf *bytes.Buffer) {
	if i == nil {
		return
	}
	writeExpr(buf, i.Expr)
	if i.Not {
		buf.WriteString(" NOT IN (")
	} else {
		buf.WriteString(" IN (")
	}
	if i.Subquery != nil {
		writeStmt(buf, i.Subquery)
	} else {
		writeExprList(buf, i.List)
	}
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this EXISTS expression as "EXISTS (subquery)".
func (e *ExistsExpression) SQL() string {
	if e == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	e.writeSQL(buf)
	return buf.String()
}

func (e *ExistsExpression) writeSQL(buf *bytes.Buffer) {
	if e == nil {
		return
	}
	buf.WriteString("EXISTS (")
	writeStmt(buf, e.Subquery)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this scalar subquery as "(SELECT ...)".
func (s *SubqueryExpression) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *SubqueryExpression) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}
	buf.WriteByte('(')
	writeStmt(buf, s.Subquery)
	buf.WriteByte(')')
}

// SQL returns the parenthesized expression as "(expr)". The parentheses are
// preserved so that AND/OR grouping survives a round-trip (see #519).
func (p *ParenthesizedExpression) SQL() string {
	if p == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	p.writeSQL(buf)
	return buf.String()
}

func (p *ParenthesizedExpression) writeSQL(buf *bytes.Buffer) {
	if p == nil {
		return
	}
	buf.WriteByte('(')
	writeExpr(buf, p.Expr)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this ANY expression as "expr op ANY (subquery)".
func (a *AnyExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AnyExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Expr)
	buf.WriteByte(' ')
	buf.WriteString(a.Operator)
	buf.WriteString(" ANY (")
	writeStmt(buf, a.Subquery)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this ALL expression as "expr op ALL (subquery)".
func (a *AllExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AllExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Expr)
	buf.WriteByte(' ')
	buf.WriteString(a.Operator)
	buf.WriteString(" ALL (")
	writeStmt(buf, a.Subquery)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this function call including arguments,
// optional DISTINCT modifier, ORDER BY clause (for aggregates like STRING_AGG),
// WITHIN GROUP (for ordered-set aggregates), FILTER (WHERE ...) clause, and
// OVER (...) window specification.
func (f *FunctionCall) SQL() string {
	if f == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	f.writeSQL(buf)
	return buf.String()
}

func (f *FunctionCall) writeSQL(buf *bytes.Buffer) {
	if f == nil {
		return
	}
	buf.WriteString(f.Name)
	if len(f.Parameters) > 0 {
		// ClickHouse parametric aggregates: quantile(0.5)(x).
		// Parameters are rendered in their own parenthesis group before args.
		buf.WriteByte('(')
		writeExprList(buf, f.Parameters)
		buf.WriteByte(')')
	}
	buf.WriteByte('(')
	if f.Distinct {
		buf.WriteString("DISTINCT ")
	}
	writeExprList(buf, f.Arguments)
	if len(f.OrderBy) > 0 {
		buf.WriteString(" ORDER BY ")
		writeOrderBy(buf, f.OrderBy)
	}
	buf.WriteByte(')')
	if len(f.WithinGroup) > 0 {
		buf.WriteString(" WITHIN GROUP (ORDER BY ")
		writeOrderBy(buf, f.WithinGroup)
		buf.WriteByte(')')
	}
	if f.Filter != nil {
		buf.WriteString(" FILTER (WHERE ")
		writeExpr(buf, f.Filter)
		buf.WriteByte(')')
	}
	if o := f.Over; o != nil {
		if o.Name != "" && o.BaseWindow == "" && len(o.PartitionBy) == 0 && len(o.OrderBy) == 0 && o.FrameClause == nil {
			// Bare named-window reference: OVER w.
			buf.WriteString(" OVER ")
			buf.WriteString(o.Name)
		} else {
			// Hand-built specs may carry the referenced window in Name alongside
			// other parts; render it as the base window, as before.
			base := o.BaseWindow
			if base == "" {
				base = o.Name
			}
			buf.WriteString(" OVER (")
			writeWindowSpec(buf, base, o)
			buf.WriteByte(')')
		}
	}
}

// SQL returns "EXTRACT(field FROM source)" as a SQL string.
func (e *ExtractExpression) SQL() string {
	if e == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	e.writeSQL(buf)
	return buf.String()
}

func (e *ExtractExpression) writeSQL(buf *bytes.Buffer) {
	if e == nil {
		return
	}
	buf.WriteString("EXTRACT(")
	buf.WriteString(e.Field)
	buf.WriteString(" FROM ")
	writeExpr(buf, e.Source)
	buf.WriteByte(')')
}

// SQL returns "POSITION(substr IN str)" as a SQL string.
func (p *PositionExpression) SQL() string {
	if p == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	p.writeSQL(buf)
	return buf.String()
}

func (p *PositionExpression) writeSQL(buf *bytes.Buffer) {
	if p == nil {
		return
	}
	buf.WriteString("POSITION(")
	writeExpr(buf, p.Substr)
	buf.WriteString(" IN ")
	writeExpr(buf, p.Str)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this SUBSTRING expression.
// With a length: "SUBSTRING(str FROM start FOR length)".
// Without a length: "SUBSTRING(str FROM start)".
func (s *SubstringExpression) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *SubstringExpression) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}
	buf.WriteString("SUBSTRING(")
	writeExpr(buf, s.Str)
	buf.WriteString(" FROM ")
	writeExpr(buf, s.Start)
	if s.Length != nil {
		buf.WriteString(" FOR ")
		writeExpr(buf, s.Length)
	}
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this interval as "INTERVAL 'value'".
func (i *IntervalExpression) SQL() string {
	if i == nil {
		return ""
	}
	return "INTERVAL '" + i.Value + "'"
}

func (i *IntervalExpression) writeSQL(buf *bytes.Buffer) {
	if i == nil {
		return
	}
	buf.WriteString("INTERVAL '")
	buf.WriteString(i.Value)
	buf.WriteByte('\'')
}

// SQL returns the SQL representation of this list expression as a
// comma-separated parenthesized list: "(v1, v2, v3)".
func (l *ListExpression) SQL() string {
	if l == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	l.writeSQL(buf)
	return buf.String()
}

func (l *ListExpression) writeSQL(buf *bytes.Buffer) {
	if l == nil {
		return
	}
	writeExprList(buf, l.Values)
}

// SQL returns the SQL representation of this tuple expression as a
// parenthesized comma-separated list: "(v1, v2, v3)".
func (t *TupleExpression) SQL() string {
	if t == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	t.writeSQL(buf)
	return buf.String()
}

func (t *TupleExpression) writeSQL(buf *bytes.Buffer) {
	if t == nil {
		return
	}
	buf.WriteByte('(')
	writeExprList(buf, t.Expressions)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this ARRAY constructor.
// From a subquery: "ARRAY(SELECT ...)".
// From an element list: "ARRAY[e1, e2, e3]".
func (a *ArrayConstructorExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *ArrayConstructorExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	if a.Subquery != nil {
		buf.WriteString("ARRAY(")
		writeStmt(buf, a.Subquery)
		buf.WriteByte(')')
		return
	}
	buf.WriteString("ARRAY[")
	writeExprList(buf, a.Elements)
	buf.WriteByte(']')
}

// SQL returns the SQL representation of this array subscript expression,
// e.g. "arr[1]" or "matrix[i][j]" for multi-dimensional subscripts.
func (a *ArraySubscriptExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *ArraySubscriptExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Array)
	for _, idx := range a.Indices {
		buf.WriteByte('[')
		writeExpr(buf, idx)
		buf.WriteByte(']')
	}
}

// SQL returns the SQL representation of this array slice expression,
// e.g. "arr[1:3]", "arr[2:]", "arr[:5]", or "arr[:]".
func (a *ArraySliceExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *ArraySliceExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Array)
	buf.WriteByte('[')
	writeExpr(buf, a.Start)
	buf.WriteByte(':')
	writeExpr(buf, a.End)
	buf.WriteByte(']')
}

// GROUP BY advanced expressions

// SQL returns the SQL representation of this ROLLUP expression as
// "ROLLUP(col1, col2, ...)".
func (r *RollupExpression) SQL() string {
	if r == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	r.writeSQL(buf)
	return buf.String()
}

func (r *RollupExpression) writeSQL(buf *bytes.Buffer) {
	if r == nil {
		return
	}
	buf.WriteString("ROLLUP(")
	writeExprList(buf, r.Expressions)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this CUBE expression as
// "CUBE(col1, col2, ...)".
func (c *CubeExpression) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *CubeExpression) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	buf.WriteString("CUBE(")
	writeExprList(buf, c.Expressions)
	buf.WriteByte(')')
}

// SQL returns the SQL representation of this GROUPING SETS expression as
// "GROUPING SETS((a, b), (a), ())".
func (g *GroupingSetsExpression) SQL() string {
	if g == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	g.writeSQL(buf)
	return buf.String()
}

func (g *GroupingSetsExpression) writeSQL(buf *bytes.Buffer) {
	if g == nil {
		return
	}
	buf.WriteString("GROUPING SETS(")
	for i, set := range g.Sets {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteByte('(')
		writeExprList(buf, set)
		buf.WriteByte(')')
	}
	buf.WriteByte(')')
}

// ============================================================
// Statements
// ============================================================

// SQL returns the full SQL string for this SELECT statement, including all
// clauses: WITH, DISTINCT ON/DISTINCT, SELECT list, FROM, JOIN, WHERE,
// GROUP BY, HAVING, WINDOW, ORDER BY, LIMIT, OFFSET, FETCH, and FOR.
// This enables round-trip serialization of parsed queries.
func (s *SelectStatement) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *SelectStatement) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}

	if s.With != nil {
		s.With.writeSQL(buf)
		buf.WriteByte(' ')
	}

	buf.WriteString("SELECT ")

	if len(s.DistinctOnColumns) > 0 {
		buf.WriteString("DISTINCT ON (")
		writeExprList(buf, s.DistinctOnColumns)
		buf.WriteString(") ")
	} else if s.Distinct {
		buf.WriteString("DISTINCT ")
	}

	writeExprList(buf, s.Columns)

	if len(s.From) > 0 {
		buf.WriteString(" FROM ")
		writeTableRefList(buf, s.From)
	}

	for i := range s.Joins {
		buf.WriteByte(' ')
		writeJoin(buf, &s.Joins[i])
	}

	if s.ArrayJoin != nil {
		if s.ArrayJoin.Left {
			buf.WriteString(" LEFT ARRAY JOIN ")
		} else {
			buf.WriteString(" ARRAY JOIN ")
		}
		for i, e := range s.ArrayJoin.Elements {
			if i > 0 {
				buf.WriteString(", ")
			}
			writeExpr(buf, e.Expr)
			if e.Alias != "" {
				buf.WriteString(" AS ")
				buf.WriteString(e.Alias)
			}
		}
	}

	if s.Sample != nil {
		buf.WriteByte(' ')
		buf.WriteString(s.Sample.SQL())
	}

	if s.PrewhereClause != nil {
		buf.WriteString(" PREWHERE ")
		writeExpr(buf, s.PrewhereClause)
	}

	if s.Where != nil {
		buf.WriteString(" WHERE ")
		writeExpr(buf, s.Where)
	}

	if len(s.GroupBy) > 0 {
		buf.WriteString(" GROUP BY ")
		writeExprList(buf, s.GroupBy)
	}

	if s.Having != nil {
		buf.WriteString(" HAVING ")
		writeExpr(buf, s.Having)
	}

	// MariaDB hierarchical query clauses (10.2+): START WITH ... CONNECT BY ...
	// These must appear after HAVING and before ORDER BY per MariaDB grammar.
	if s.StartWith != nil {
		buf.WriteString(" START WITH ")
		writeExpr(buf, s.StartWith)
	}
	if s.ConnectBy != nil {
		buf.WriteByte(' ')
		buf.WriteString(s.ConnectBy.ToSQL())
	}

	if len(s.Windows) > 0 {
		buf.WriteString(" WINDOW ")
		for i := range s.Windows {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(s.Windows[i].Name)
			buf.WriteString(" AS (")
			writeWindowSpec(buf, s.Windows[i].BaseWindow, &s.Windows[i])
			buf.WriteByte(')')
		}
	}

	if len(s.OrderBy) > 0 {
		buf.WriteString(" ORDER BY ")
		writeOrderBy(buf, s.OrderBy)
	}

	if s.Limit != nil {
		buf.WriteString(" LIMIT ")
		writeInt(buf, int64(*s.Limit))
	}

	if s.Offset != nil {
		buf.WriteString(" OFFSET ")
		writeInt(buf, int64(*s.Offset))
	}

	if s.Fetch != nil {
		writeFetch(buf, s.Fetch)
	}

	if s.For != nil {
		writeFor(buf, s.For)
	}
}

// SQL returns the full SQL string for this INSERT statement, including the
// optional WITH clause, column list, VALUES rows or SELECT subquery, ON CONFLICT
// clause, and RETURNING clause.
func (i *InsertStatement) SQL() string {
	if i == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	i.writeSQL(buf)
	return buf.String()
}

func (i *InsertStatement) writeSQL(buf *bytes.Buffer) {
	if i == nil {
		return
	}

	if i.With != nil {
		i.With.writeSQL(buf)
		buf.WriteByte(' ')
	}

	buf.WriteString("INSERT INTO ")
	buf.WriteString(i.TableName)

	if len(i.Columns) > 0 {
		buf.WriteString(" (")
		writeExprList(buf, i.Columns)
		buf.WriteByte(')')
	}

	if i.Query != nil {
		buf.WriteByte(' ')
		writeStmt(buf, i.Query)
	} else if len(i.Values) > 0 {
		buf.WriteString(" VALUES ")
		writeValueRows(buf, i.Values)
	}

	if i.OnConflict != nil {
		writeOnConflict(buf, i.OnConflict)
	}

	if len(i.Returning) > 0 {
		buf.WriteString(" RETURNING ")
		writeExprList(buf, i.Returning)
	}
}

// SQL returns the full SQL string for this UPDATE statement, including the
// optional WITH clause, SET assignments, FROM clause, WHERE condition, and
// RETURNING clause.
func (u *UpdateStatement) SQL() string {
	if u == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	u.writeSQL(buf)
	return buf.String()
}

func (u *UpdateStatement) writeSQL(buf *bytes.Buffer) {
	if u == nil {
		return
	}

	if u.With != nil {
		u.With.writeSQL(buf)
		buf.WriteByte(' ')
	}

	buf.WriteString("UPDATE ")
	buf.WriteString(u.TableName)
	if u.Alias != "" {
		buf.WriteByte(' ')
		buf.WriteString(u.Alias)
	}

	buf.WriteString(" SET ")
	writeAssignments(buf, u.Assignments)

	if len(u.From) > 0 {
		buf.WriteString(" FROM ")
		writeTableRefList(buf, u.From)
	}

	if u.Where != nil {
		buf.WriteString(" WHERE ")
		writeExpr(buf, u.Where)
	}

	if len(u.Returning) > 0 {
		buf.WriteString(" RETURNING ")
		writeExprList(buf, u.Returning)
	}
}

// SQL returns the full SQL string for this DELETE statement, including the
// optional WITH clause, USING clause, WHERE condition, and RETURNING clause.
func (d *DeleteStatement) SQL() string {
	if d == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	d.writeSQL(buf)
	return buf.String()
}

func (d *DeleteStatement) writeSQL(buf *bytes.Buffer) {
	if d == nil {
		return
	}

	if d.With != nil {
		d.With.writeSQL(buf)
		buf.WriteByte(' ')
	}

	buf.WriteString("DELETE FROM ")
	buf.WriteString(d.TableName)
	if d.Alias != "" {
		buf.WriteByte(' ')
		buf.WriteString(d.Alias)
	}

	if len(d.Using) > 0 {
		buf.WriteString(" USING ")
		writeTableRefList(buf, d.Using)
	}

	if d.Where != nil {
		buf.WriteString(" WHERE ")
		writeExpr(buf, d.Where)
	}

	if len(d.Returning) > 0 {
		buf.WriteString(" RETURNING ")
		writeExprList(buf, d.Returning)
	}
}

// SQL returns the full SQL string for this CREATE TABLE statement including
// column definitions, table constraints, INHERITS, PARTITION BY, and table options.
func (c *CreateTableStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("CREATE ")
	if c.Temporary {
		sb.WriteString("TEMPORARY ")
	}
	sb.WriteString("TABLE ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	sb.WriteString(" (")

	parts := make([]string, 0, len(c.Columns)+len(c.Constraints))
	for _, col := range c.Columns {
		col := col // G601: Create local copy to avoid memory aliasing
		parts = append(parts, columnDefSQL(&col))
	}
	for _, con := range c.Constraints {
		con := con // G601: Create local copy to avoid memory aliasing
		parts = append(parts, tableConstraintSQL(&con))
	}
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString(")")

	if len(c.Inherits) > 0 {
		sb.WriteString(" INHERITS (")
		sb.WriteString(strings.Join(c.Inherits, ", "))
		sb.WriteString(")")
	}

	if c.PartitionBy != nil {
		fmt.Fprintf(sb, " PARTITION BY %s (%s)", c.PartitionBy.Type, strings.Join(c.PartitionBy.Columns, ", "))
	}

	for _, opt := range c.Options {
		fmt.Fprintf(sb, " %s=%s", opt.Name, opt.Value)
	}

	return sb.String()
}

// SQL returns the full SQL string for this CREATE INDEX statement including
// the UNIQUE modifier, IF NOT EXISTS, USING method, column list, and WHERE predicate.
func (c *CreateIndexStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("CREATE ")
	if c.Unique {
		sb.WriteString("UNIQUE ")
	}
	sb.WriteString("INDEX ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	sb.WriteString(" ON ")
	sb.WriteString(c.Table)

	if c.Using != "" {
		sb.WriteString(" USING ")
		sb.WriteString(c.Using)
	}

	sb.WriteString(" (")
	cols := make([]string, len(c.Columns))
	for i, col := range c.Columns {
		s := col.Column
		if col.Direction != "" {
			s += " " + col.Direction
		}
		cols[i] = s
	}
	sb.WriteString(strings.Join(cols, ", "))
	sb.WriteString(")")

	if c.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(c.Where))
	}

	return sb.String()
}

// SQL returns the SQL representation of this ALTER TABLE statement.
// Note: the parser returns AlterStatement (in alter.go); this method
// is for manually-constructed AlterTableStatement values.
func (a *AlterTableStatement) SQL() string {
	if a == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("ALTER TABLE ")
	sb.WriteString(a.Table)
	for _, action := range a.Actions {
		action := action // G601: Create local copy to avoid memory aliasing
		sb.WriteString(" ")
		sb.WriteString(alterActionSQL(&action))
	}
	return sb.String()
}

// SQL returns the SQL representation of this DROP statement, including the
// object type, optional IF EXISTS, object names, and CASCADE/RESTRICT behavior.
func (d *DropStatement) SQL() string {
	if d == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("DROP ")
	sb.WriteString(d.ObjectType)
	sb.WriteString(" ")
	if d.IfExists {
		sb.WriteString("IF EXISTS ")
	}
	sb.WriteString(strings.Join(d.Names, ", "))
	if d.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(d.CascadeType)
	}
	return sb.String()
}

// SQL returns the SQL representation of this TRUNCATE statement, including
// table names, RESTART/CONTINUE IDENTITY options, and CASCADE/RESTRICT behavior.
func (t *TruncateStatement) SQL() string {
	if t == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("TRUNCATE TABLE ")
	sb.WriteString(strings.Join(t.Tables, ", "))
	if t.RestartIdentity {
		sb.WriteString(" RESTART IDENTITY")
	} else if t.ContinueIdentity {
		sb.WriteString(" CONTINUE IDENTITY")
	}
	if t.CascadeType != "" {
		sb.WriteString(" ")
		sb.WriteString(t.CascadeType)
	}
	return sb.String()
}

// SQL returns the SQL representation of this WITH clause including any RECURSIVE
// modifier and all CTE definitions.
func (w *WithClause) SQL() string {
	if w == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	w.writeSQL(buf)
	return buf.String()
}

func (w *WithClause) writeSQL(buf *bytes.Buffer) {
	if w == nil {
		return
	}
	buf.WriteString("WITH ")
	if w.Recursive {
		buf.WriteString("RECURSIVE ")
	}
	for i, cte := range w.CTEs {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeCTE(buf, cte)
	}
}

// SQL returns the SQL representation of this set operation as
// "left UNION|EXCEPT|INTERSECT [ALL] right".
func (s *SetOperation) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *SetOperation) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}
	writeStmt(buf, s.Left)
	buf.WriteByte(' ')
	buf.WriteString(s.Operator)
	if s.All {
		buf.WriteString(" ALL")
	}
	buf.WriteByte(' ')
	writeStmt(buf, s.Right)
}

// SQL returns the SQL representation of this VALUES clause as
// "VALUES (v1, v2), (v3, v4), ...".
func (v *Values) SQL() string {
	if v == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	v.writeSQL(buf)
	return buf.String()
}

func (v *Values) writeSQL(buf *bytes.Buffer) {
	if v == nil {
		return
	}
	buf.WriteString("VALUES ")
	writeValueRows(buf, v.Rows)
}

// SQL returns the full SQL string for this CREATE VIEW statement including the
// optional OR REPLACE, TEMPORARY, IF NOT EXISTS, column list, SELECT query,
// and WITH CHECK OPTION clause.
func (c *CreateViewStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("CREATE ")
	if c.OrReplace {
		sb.WriteString("OR REPLACE ")
	}
	if c.Temporary {
		sb.WriteString("TEMPORARY ")
	}
	sb.WriteString("VIEW ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" AS ")
	sb.WriteString(stmtSQL(c.Query))
	if c.WithOption != "" {
		sb.WriteString(" WITH ")
		sb.WriteString(c.WithOption)
	}
	return sb.String()
}

// SQL returns the full SQL string for this CREATE MATERIALIZED VIEW statement.
func (c *CreateMaterializedViewStatement) SQL() string {
	if c == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("CREATE MATERIALIZED VIEW ")
	if c.IfNotExists {
		sb.WriteString("IF NOT EXISTS ")
	}
	sb.WriteString(c.Name)
	if len(c.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(c.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" AS ")
	sb.WriteString(stmtSQL(c.Query))
	if c.WithData != nil {
		if *c.WithData {
			sb.WriteString(" WITH DATA")
		} else {
			sb.WriteString(" WITH NO DATA")
		}
	}
	return sb.String()
}

// SQL returns the SQL string for this REFRESH MATERIALIZED VIEW statement.
func (r *RefreshMaterializedViewStatement) SQL() string {
	if r == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("REFRESH MATERIALIZED VIEW ")
	if r.Concurrently {
		sb.WriteString("CONCURRENTLY ")
	}
	sb.WriteString(r.Name)
	if r.WithData != nil {
		if *r.WithData {
			sb.WriteString(" WITH DATA")
		} else {
			sb.WriteString(" WITH NO DATA")
		}
	}
	return sb.String()
}

// SQL returns the full SQL string for this MERGE statement including the target,
// source, ON condition, and all WHEN MATCHED/NOT MATCHED clauses.
func (m *MergeStatement) SQL() string {
	if m == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("MERGE INTO ")
	sb.WriteString(tableRefSQL(&m.TargetTable))
	if m.TargetAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.TargetAlias)
	}
	sb.WriteString(" USING ")
	sb.WriteString(tableRefSQL(&m.SourceTable))
	if m.SourceAlias != "" {
		sb.WriteString(" ")
		sb.WriteString(m.SourceAlias)
	}
	sb.WriteString(" ON ")
	sb.WriteString(exprSQL(m.OnCondition))

	for _, when := range m.WhenClauses {
		sb.WriteString(" WHEN ")
		switch when.Type {
		case "MATCHED":
			sb.WriteString("MATCHED")
		case "NOT_MATCHED":
			sb.WriteString("NOT MATCHED")
		case "NOT_MATCHED_BY_SOURCE":
			sb.WriteString("NOT MATCHED BY SOURCE")
		default:
			sb.WriteString(when.Type)
		}
		if when.Condition != nil {
			sb.WriteString(" AND ")
			sb.WriteString(exprSQL(when.Condition))
		}
		sb.WriteString(" THEN ")
		if when.Action != nil {
			sb.WriteString(mergeActionSQL(when.Action))
		}
	}

	return sb.String()
}

// DML types from dml.go

// SQL returns the SQL representation of this Select node (dml.go type), which
// is a simplified SELECT structure used in compatibility code paths.
// For full-featured SELECT parsing use SelectStatement.SQL() instead.
func (s *Select) SQL() string {
	if s == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("SELECT ")
	if s.Distinct {
		sb.WriteString("DISTINCT ")
	}
	sb.WriteString(exprListSQL(s.Columns))
	if len(s.From) > 0 {
		sb.WriteString(" FROM ")
		froms := make([]string, len(s.From))
		for i := range s.From {
			froms[i] = tableRefSQL(&s.From[i])
		}
		sb.WriteString(strings.Join(froms, ", "))
	}
	if s.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(s.Where))
	}
	if len(s.GroupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		sb.WriteString(exprListSQL(s.GroupBy))
	}
	if s.Having != nil {
		sb.WriteString(" HAVING ")
		sb.WriteString(exprSQL(s.Having))
	}
	if len(s.OrderBy) > 0 {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(orderBySQL(s.OrderBy))
	}
	if s.Limit != nil {
		fmt.Fprintf(sb, " LIMIT %d", *s.Limit)
	}
	if s.Offset != nil {
		fmt.Fprintf(sb, " OFFSET %d", *s.Offset)
	}
	return sb.String()
}

// SQL returns the SQL representation of this Insert node (dml.go type).
// For the full-featured INSERT use InsertStatement.SQL() instead.
func (i *Insert) SQL() string {
	if i == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("INSERT INTO ")
	sb.WriteString(tableRefSQL(&i.Table))
	if len(i.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(i.Columns))
		sb.WriteString(")")
	}
	if len(i.Values) > 0 {
		sb.WriteString(" VALUES ")
		rows := make([]string, len(i.Values))
		for idx, row := range i.Values {
			vals := make([]string, len(row))
			for j, v := range row {
				vals[j] = exprSQL(v)
			}
			rows[idx] = "(" + strings.Join(vals, ", ") + ")"
		}
		sb.WriteString(strings.Join(rows, ", "))
	}
	if len(i.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(i.ReturningClause))
	}
	return sb.String()
}

// SQL returns the SQL representation of this Update node (dml.go type).
// For the full-featured UPDATE use UpdateStatement.SQL() instead.
func (u *Update) SQL() string {
	if u == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("UPDATE ")
	sb.WriteString(tableRefSQL(&u.Table))
	sb.WriteString(" SET ")
	upds := make([]string, len(u.Updates))
	for i, upd := range u.Updates {
		upds[i] = exprSQL(upd.Column) + " = " + exprSQL(upd.Value)
	}
	sb.WriteString(strings.Join(upds, ", "))
	if u.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(u.Where))
	}
	if len(u.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(u.ReturningClause))
	}
	return sb.String()
}

// SQL returns the SQL representation of this Delete node (dml.go type).
// For the full-featured DELETE use DeleteStatement.SQL() instead.
func (d *Delete) SQL() string {
	if d == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("DELETE FROM ")
	sb.WriteString(tableRefSQL(&d.Table))
	if d.Where != nil {
		sb.WriteString(" WHERE ")
		sb.WriteString(exprSQL(d.Where))
	}
	if len(d.ReturningClause) > 0 {
		sb.WriteString(" RETURNING ")
		sb.WriteString(exprListSQL(d.ReturningClause))
	}
	return sb.String()
}

// ============================================================
// Helper functions
// ============================================================

// sqlWriter is implemented by nodes that can render themselves directly into
// a shared buffer, avoiding an intermediate string per node.
type sqlWriter interface {
	writeSQL(buf *bytes.Buffer)
}

// writeExpr renders e into buf, using writeSQL when available and falling
// back to SQL() and then TokenLiteral(), mirroring exprSQL.
func writeExpr(buf *bytes.Buffer, e Expression) {
	if e == nil {
		return
	}
	if w, ok := e.(sqlWriter); ok {
		w.writeSQL(buf)
		return
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		buf.WriteString(s.SQL())
		return
	}
	buf.WriteString(e.TokenLiteral())
}

// writeStmt renders s into buf, using writeSQL when available and falling
// back to SQL() and then TokenLiteral(), mirroring stmtSQL.
func writeStmt(buf *bytes.Buffer, s Statement) {
	if s == nil {
		return
	}
	if w, ok := s.(sqlWriter); ok {
		w.writeSQL(buf)
		return
	}
	if sq, ok := s.(interface{ SQL() string }); ok {
		buf.WriteString(sq.SQL())
		return
	}
	buf.WriteString(s.TokenLiteral())
}

// exprSQL dispatches to the SQL() method of any expression
func exprSQL(e Expression) string {
	if e == nil {
		return ""
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}

// stmtSQL dispatches to the SQL() method of any statement
func stmtSQL(s Statement) string {
	if s == nil {
		return ""
	}
	if sq, ok := s.(interface{ SQL() string }); ok {
		return sq.SQL()
	}
	return s.TokenLiteral()
}

func exprListSQL(exprs []Expression) string {
	buf := getBuf()
	defer putBuf(buf)
	writeExprList(buf, exprs)
	return buf.String()
}

// writeExprList writes exprs separated by ", " (strings.Join semantics: a
// separator is written between every pair, even around empty renderings).
func writeExprList(buf *bytes.Buffer, exprs []Expression) {
	for i, e := range exprs {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeExpr(buf, e)
	}
}

// writeValueRows writes "(v1, v2), (v3, v4)" for VALUES rows.
func writeValueRows(buf *bytes.Buffer, rows [][]Expression) {
	for i, row := range rows {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteByte('(')
		writeExprList(buf, row)
		buf.WriteByte(')')
	}
}

// writeAssignments writes "col = value, ..." for SET clauses.
func writeAssignments(buf *bytes.Buffer, upds []UpdateExpression) {
	for i := range upds {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeExpr(buf, upds[i].Column)
		buf.WriteString(" = ")
		writeExpr(buf, upds[i].Value)
	}
}

// writeStringList writes items separated by sep.
func writeStringList(buf *bytes.Buffer, items []string, sep string) {
	for i, s := range items {
		if i > 0 {
			buf.WriteString(sep)
		}
		buf.WriteString(s)
	}
}

func orderBySQL(orders []OrderByExpression) string {
	buf := getBuf()
	defer putBuf(buf)
	writeOrderBy(buf, orders)
	return buf.String()
}

func writeOrderBy(buf *bytes.Buffer, orders []OrderByExpression) {
	for i := range orders {
		o := &orders[i]
		if i > 0 {
			buf.WriteString(", ")
		}
		writeExpr(buf, o.Expression)
		if !o.Ascending {
			buf.WriteString(" DESC")
		}
		if o.NullsFirst != nil {
			if *o.NullsFirst {
				buf.WriteString(" NULLS FIRST")
			} else {
				buf.WriteString(" NULLS LAST")
			}
		}
		if o.WithFill != nil {
			writeWithFill(buf, o.WithFill)
		}
	}
}

// writeWithFill renders a ClickHouse "WITH FILL [FROM x] [TO y] [STEP z]" modifier.
func writeWithFill(buf *bytes.Buffer, w *WithFillClause) {
	if w == nil {
		return
	}
	buf.WriteString(" WITH FILL")
	if w.From != nil {
		buf.WriteString(" FROM ")
		writeExpr(buf, w.From)
	}
	if w.To != nil {
		buf.WriteString(" TO ")
		writeExpr(buf, w.To)
	}
	if w.Step != nil {
		buf.WriteString(" STEP ")
		writeExpr(buf, w.Step)
	}
}

func tableRefSQL(t *TableReference) string {
	buf := getBuf()
	defer putBuf(buf)
	writeTableRef(buf, t)
	return buf.String()
}

func writeTableRef(buf *bytes.Buffer, t *TableReference) {
	if t.Lateral {
		buf.WriteString("LATERAL ")
	}
	if t.Subquery != nil {
		buf.WriteByte('(')
		t.Subquery.writeSQL(buf)
		buf.WriteByte(')')
	} else {
		buf.WriteString(t.Name)
	}
	if t.Alias != "" {
		buf.WriteByte(' ')
		buf.WriteString(t.Alias)
	}
	if t.Final {
		buf.WriteString(" FINAL")
	}
	if t.ForSystemTime != nil {
		buf.WriteByte(' ')
		buf.WriteString(t.ForSystemTime.ToSQL())
	}
}

// writeTableRefList writes refs separated by ", ".
func writeTableRefList(buf *bytes.Buffer, refs []TableReference) {
	for i := range refs {
		if i > 0 {
			buf.WriteString(", ")
		}
		writeTableRef(buf, &refs[i])
	}
}

func writeJoin(buf *bytes.Buffer, j *JoinClause) {
	buf.WriteString(j.Type)
	buf.WriteString(" JOIN ")
	writeTableRef(buf, &j.Right)
	if j.Condition != nil {
		buf.WriteString(" ON ")
		writeExpr(buf, j.Condition)
	}
}

// writeWindowSpec writes the inside of a window spec's parentheses: the
// space-separated base (existing) window name, PARTITION BY, ORDER BY and
// frame parts that are present. w.Name is never written here; callers write
// it outside the parentheses (OVER w, WINDOW w AS (...)).
func writeWindowSpec(buf *bytes.Buffer, base string, w *WindowSpec) {
	first := true
	sep := func() {
		if !first {
			buf.WriteByte(' ')
		}
		first = false
	}
	if base != "" {
		sep()
		buf.WriteString(base)
	}
	if len(w.PartitionBy) > 0 {
		sep()
		buf.WriteString("PARTITION BY ")
		writeExprList(buf, w.PartitionBy)
	}
	if len(w.OrderBy) > 0 {
		sep()
		buf.WriteString("ORDER BY ")
		writeOrderBy(buf, w.OrderBy)
	}
	if w.FrameClause != nil {
		sep()
		writeWindowFrame(buf, w.FrameClause)
	}
}

func writeWindowFrame(buf *bytes.Buffer, f *WindowFrame) {
	buf.WriteString(f.Type)
	if f.End != nil {
		buf.WriteString(" BETWEEN ")
		writeFrameBound(buf, &f.Start)
		buf.WriteString(" AND ")
		writeFrameBound(buf, f.End)
		return
	}
	buf.WriteByte(' ')
	writeFrameBound(buf, &f.Start)
}

// writeFrameBound renders a single window frame bound. A numeric bound keeps
// its offset in Value (e.g. Value=2, Type="PRECEDING"); CURRENT ROW and the
// UNBOUNDED forms carry no Value.
func writeFrameBound(buf *bytes.Buffer, b *WindowFrameBound) {
	if b.Value != nil {
		writeExpr(buf, b.Value)
		buf.WriteByte(' ')
	}
	buf.WriteString(b.Type)
}

func writeFetch(buf *bytes.Buffer, f *FetchClause) {
	if f.OffsetValue != nil {
		buf.WriteString(" OFFSET ")
		writeInt(buf, *f.OffsetValue)
		buf.WriteString(" ROWS")
	}
	buf.WriteString(" FETCH ")
	buf.WriteString(f.FetchType)
	if f.FetchValue != nil {
		buf.WriteByte(' ')
		writeInt(buf, *f.FetchValue)
	}
	if f.IsPercent {
		buf.WriteString(" PERCENT")
	}
	buf.WriteString(" ROWS")
	if f.WithTies {
		buf.WriteString(" WITH TIES")
	} else {
		buf.WriteString(" ONLY")
	}
}

func writeFor(buf *bytes.Buffer, f *ForClause) {
	buf.WriteString(" FOR ")
	buf.WriteString(f.LockType)
	if len(f.Tables) > 0 {
		buf.WriteString(" OF ")
		writeStringList(buf, f.Tables, ", ")
	}
	if f.NoWait {
		buf.WriteString(" NOWAIT")
	}
	if f.SkipLocked {
		buf.WriteString(" SKIP LOCKED")
	}
}

func writeCTE(buf *bytes.Buffer, cte *CommonTableExpr) {
	// ClickHouse scalar CTE: WITH <expr> AS <name>
	if cte.ScalarExpr != nil {
		writeExpr(buf, cte.ScalarExpr)
		buf.WriteString(" AS ")
		buf.WriteString(cte.Name)
		return
	}
	buf.WriteString(cte.Name)
	if len(cte.Columns) > 0 {
		buf.WriteString(" (")
		writeStringList(buf, cte.Columns, ", ")
		buf.WriteByte(')')
	}
	buf.WriteString(" AS ")
	if cte.Materialized != nil {
		if *cte.Materialized {
			buf.WriteString("MATERIALIZED ")
		} else {
			buf.WriteString("NOT MATERIALIZED ")
		}
	}
	buf.WriteByte('(')
	writeStmt(buf, cte.Statement)
	buf.WriteByte(')')
}

func writeOnConflict(buf *bytes.Buffer, oc *OnConflict) {
	buf.WriteString(" ON CONFLICT")
	if len(oc.Target) > 0 {
		buf.WriteString(" (")
		writeExprList(buf, oc.Target)
		buf.WriteByte(')')
	}
	if oc.Constraint != "" {
		buf.WriteString(" ON CONSTRAINT ")
		buf.WriteString(oc.Constraint)
	}
	if oc.Action.DoNothing {
		buf.WriteString(" DO NOTHING")
	} else if len(oc.Action.DoUpdate) > 0 {
		buf.WriteString(" DO UPDATE SET ")
		writeAssignments(buf, oc.Action.DoUpdate)
		if oc.Action.Where != nil {
			buf.WriteString(" WHERE ")
			writeExpr(buf, oc.Action.Where)
		}
	}
}

func columnDefSQL(c *ColumnDef) string {
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString(c.Name)
	sb.WriteString(" ")
	sb.WriteString(c.Type)
	for _, con := range c.Constraints {
		con := con // G601: Create local copy to avoid memory aliasing
		sb.WriteString(" ")
		sb.WriteString(columnConstraintSQL(&con))
	}
	return sb.String()
}

func columnConstraintSQL(c *ColumnConstraint) string {
	switch c.Type {
	case "NOT NULL", "UNIQUE", "PRIMARY KEY":
		return c.Type
	case "DEFAULT":
		return "DEFAULT " + exprSQL(c.Default)
	case "REFERENCES":
		if c.References != nil {
			return referenceSQL(c.References)
		}
		return "REFERENCES"
	case "CHECK":
		return "CHECK (" + exprSQL(c.Check) + ")"
	default:
		if c.AutoIncrement {
			return "AUTO_INCREMENT"
		}
		return c.Type
	}
}

func tableConstraintSQL(tc *TableConstraint) string {
	sb := getBuf()
	defer putBuf(sb)
	if tc.Name != "" {
		sb.WriteString("CONSTRAINT ")
		sb.WriteString(tc.Name)
		sb.WriteString(" ")
	}
	switch tc.Type {
	case "PRIMARY KEY":
		sb.WriteString("PRIMARY KEY (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "UNIQUE":
		sb.WriteString("UNIQUE (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "FOREIGN KEY":
		sb.WriteString("FOREIGN KEY (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(") ")
		if tc.References != nil {
			sb.WriteString(referenceSQL(tc.References))
		}
	case "CHECK":
		sb.WriteString("CHECK (")
		sb.WriteString(exprSQL(tc.Check))
		sb.WriteString(")")
	default:
		sb.WriteString(tc.Type)
	}
	return sb.String()
}

func referenceSQL(r *ReferenceDefinition) string {
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("REFERENCES ")
	sb.WriteString(r.Table)
	if len(r.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(r.Columns, ", "))
		sb.WriteString(")")
	}
	if r.OnDelete != "" {
		sb.WriteString(" ON DELETE ")
		sb.WriteString(r.OnDelete)
	}
	if r.OnUpdate != "" {
		sb.WriteString(" ON UPDATE ")
		sb.WriteString(r.OnUpdate)
	}
	return sb.String()
}

func alterActionSQL(a *AlterTableAction) string {
	switch a.Type {
	case "ADD COLUMN":
		s := "ADD COLUMN "
		if a.ColumnDef != nil {
			s += columnDefSQL(a.ColumnDef)
		}
		return s
	case "DROP COLUMN":
		return "DROP COLUMN " + a.ColumnName
	case "ADD CONSTRAINT":
		if a.Constraint != nil {
			return "ADD " + tableConstraintSQL(a.Constraint)
		}
		return "ADD CONSTRAINT"
	default:
		return a.Type
	}
}

func mergeActionSQL(a *MergeAction) string {
	switch a.ActionType {
	case "UPDATE":
		sets := make([]string, len(a.SetClauses))
		for i, s := range a.SetClauses {
			sets[i] = s.Column + " = " + exprSQL(s.Value)
		}
		return "UPDATE SET " + strings.Join(sets, ", ")
	case "INSERT":
		var sb strings.Builder
		sb.WriteString("INSERT")
		if a.DefaultValues {
			sb.WriteString(" DEFAULT VALUES")
		} else {
			if len(a.Columns) > 0 {
				sb.WriteString(" (")
				sb.WriteString(strings.Join(a.Columns, ", "))
				sb.WriteString(")")
			}
			if len(a.Values) > 0 {
				sb.WriteString(" VALUES (")
				vals := make([]string, len(a.Values))
				for i, v := range a.Values {
					vals[i] = exprSQL(v)
				}
				sb.WriteString(strings.Join(vals, ", "))
				sb.WriteString(")")
			}
		}
		return sb.String()
	case "DELETE":
		return "DELETE"
	default:
		return a.ActionType
	}
}

// ToSQL returns the SQL string for CREATE SEQUENCE.
func (s *CreateSequenceStatement) ToSQL() string {
	var b strings.Builder
	b.WriteString("CREATE ")
	if s.OrReplace {
		b.WriteString("OR REPLACE ")
	}
	b.WriteString("SEQUENCE ")
	if s.IfNotExists {
		b.WriteString("IF NOT EXISTS ")
	}
	if s.Name != nil {
		b.WriteString(s.Name.Name)
	}
	writeSequenceOptions(&b, s.Options)
	return b.String()
}

// ToSQL returns the SQL string for DROP SEQUENCE.
func (s *DropSequenceStatement) ToSQL() string {
	var b strings.Builder
	b.WriteString("DROP SEQUENCE ")
	if s.IfExists {
		b.WriteString("IF EXISTS ")
	}
	if s.Name != nil {
		b.WriteString(s.Name.Name)
	}
	return b.String()
}

// ToSQL returns the SQL string for ALTER SEQUENCE.
func (s *AlterSequenceStatement) ToSQL() string {
	var b strings.Builder
	b.WriteString("ALTER SEQUENCE ")
	if s.IfExists {
		b.WriteString("IF EXISTS ")
	}
	if s.Name != nil {
		b.WriteString(s.Name.Name)
	}
	writeSequenceOptions(&b, s.Options)
	return b.String()
}

// writeSequenceOptions is a shared helper for CREATE/ALTER SEQUENCE serialization.
func writeSequenceOptions(b *strings.Builder, opts SequenceOptions) {
	if opts.StartWith != nil {
		b.WriteString(" START WITH ")
		b.WriteString(opts.StartWith.TokenLiteral())
	}
	if opts.IncrementBy != nil {
		b.WriteString(" INCREMENT BY ")
		b.WriteString(opts.IncrementBy.TokenLiteral())
	}
	if opts.MinValue != nil {
		b.WriteString(" MINVALUE ")
		b.WriteString(opts.MinValue.TokenLiteral())
	}
	if opts.MaxValue != nil {
		b.WriteString(" MAXVALUE ")
		b.WriteString(opts.MaxValue.TokenLiteral())
	}
	if opts.Cache != nil {
		b.WriteString(" CACHE ")
		b.WriteString(opts.Cache.TokenLiteral())
	} else if opts.NoCache {
		b.WriteString(" NOCACHE")
	}
	switch opts.CycleMode {
	case CycleBehavior:
		b.WriteString(" CYCLE")
	case NoCycleBehavior:
		b.WriteString(" NOCYCLE")
	}
	if opts.RestartWith != nil {
		b.WriteString(" RESTART WITH ")
		b.WriteString(opts.RestartWith.TokenLiteral())
	} else if opts.Restart {
		b.WriteString(" RESTART")
	}
}

// SQL implements the Expression interface for ForSystemTimeClause.
func (c *ForSystemTimeClause) SQL() string { return c.ToSQL() }

// ToSQL returns the SQL string for a FOR SYSTEM_TIME clause (MariaDB 10.3.4+).
func (c *ForSystemTimeClause) ToSQL() string {
	var b strings.Builder
	b.WriteString("FOR SYSTEM_TIME ")
	switch c.Type {
	case SystemTimeAsOf:
		b.WriteString("AS OF ")
		b.WriteString(exprSQL(c.Point))
	case SystemTimeBetween:
		b.WriteString("BETWEEN ")
		b.WriteString(exprSQL(c.Start))
		b.WriteString(" AND ")
		b.WriteString(exprSQL(c.End))
	case SystemTimeFromTo:
		b.WriteString("FROM ")
		b.WriteString(exprSQL(c.Start))
		b.WriteString(" TO ")
		b.WriteString(exprSQL(c.End))
	case SystemTimeAll:
		b.WriteString("ALL")
	}
	return b.String()
}

// SQL implements the Expression interface for ConnectByClause.
func (c *ConnectByClause) SQL() string { return c.ToSQL() }

// SQL implements the Expression interface for PeriodDefinition (stub; not used as a standalone expression).
// SQL returns the SQL string for a PERIOD FOR clause in CREATE TABLE.
// Example: PERIOD FOR app_time (valid_from, valid_to)
func (p *PeriodDefinition) SQL() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("PERIOD FOR ")
	if p.Name != nil {
		b.WriteString(p.Name.Name)
	}
	b.WriteString(" (")
	if p.StartCol != nil {
		b.WriteString(p.StartCol.Name)
	}
	b.WriteString(", ")
	if p.EndCol != nil {
		b.WriteString(p.EndCol.Name)
	}
	b.WriteString(")")
	return b.String()
}

// SQL returns the SQL string for a PRAGMA statement (SQLite).
func (p *PragmaStatement) SQL() string {
	if p == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("PRAGMA ")
	sb.WriteString(p.Name)
	if p.Arg != "" {
		sb.WriteString("(")
		sb.WriteString(p.Arg)
		sb.WriteString(")")
	} else if p.Value != "" {
		sb.WriteString(" = ")
		sb.WriteString(p.Value)
	}
	return sb.String()
}

// SQL returns the SQL string for a SHOW statement (MySQL).
func (s *ShowStatement) SQL() string {
	if s == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("SHOW ")
	sb.WriteString(s.ShowType)
	if s.ObjectName != "" {
		sb.WriteString(" ")
		sb.WriteString(s.ObjectName)
	}
	if s.From != "" {
		sb.WriteString(" FROM ")
		sb.WriteString(s.From)
	}
	return sb.String()
}

// SQL returns the SQL string for a DESCRIBE statement (MySQL).
func (d *DescribeStatement) SQL() string {
	if d == nil {
		return ""
	}
	return "DESCRIBE " + d.TableName
}

// SQL returns the SQL string for a REPLACE statement (MySQL).
func (r *ReplaceStatement) SQL() string {
	if r == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("REPLACE INTO ")
	sb.WriteString(r.TableName)
	if len(r.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(exprListSQL(r.Columns))
		sb.WriteString(")")
	}
	if len(r.Values) > 0 {
		sb.WriteString(" VALUES ")
		rows := make([]string, len(r.Values))
		for idx, row := range r.Values {
			vals := make([]string, len(row))
			for j, v := range row {
				vals[j] = exprSQL(v)
			}
			rows[idx] = "(" + strings.Join(vals, ", ") + ")"
		}
		sb.WriteString(strings.Join(rows, ", "))
	}
	return sb.String()
}

// ToSQL returns the SQL string for a CONNECT BY clause (MariaDB 10.2+).
func (c *ConnectByClause) ToSQL() string {
	var b strings.Builder
	b.WriteString("CONNECT BY ")
	if c.NoCycle {
		b.WriteString("NOCYCLE ")
	}
	b.WriteString(exprSQL(c.Condition))
	return b.String()
}

// SQL renders a ClickHouse SAMPLE clause, e.g. "SAMPLE 0.1" or
// "SAMPLE 1/10 OFFSET 2/10".
func (s *SampleClause) SQL() string {
	if s == nil {
		return ""
	}
	sb := getBuf()
	defer putBuf(sb)
	sb.WriteString("SAMPLE ")
	v := s.Value
	if s.Value != "" && s.Denominator != "" {
		v = s.Value + "/" + s.Denominator
	}
	sb.WriteString(v)
	if s.Offset != "" {
		sb.WriteString(" OFFSET ")
		o := s.Offset
		if s.OffsetDenominator != "" {
			o = s.Offset + "/" + s.OffsetDenominator
		}
		sb.WriteString(o)
	}
	return sb.String()
}
