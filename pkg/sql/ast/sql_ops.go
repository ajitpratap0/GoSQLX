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
)

// SQL returns "expr AT TIME ZONE zone".
func (a *AtTimeZoneExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AtTimeZoneExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writePostfixOperand(buf, a.Expr)
	buf.WriteString(" AT TIME ZONE ")
	writePostfixOperand(buf, a.Zone)
}

// SQL returns "expr COLLATE name".
func (c *CollateExpression) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *CollateExpression) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	writePostfixOperand(buf, c.Expr)
	buf.WriteString(" COLLATE ")
	if c.Literal {
		writeStringLiteral(buf, c.Collation)
		return
	}
	name := c.Collation
	if dot := strings.LastIndexByte(name, '.'); dot > 0 && dot < len(name)-1 {
		writeQualifiedName(buf, name[:dot])
		buf.WriteByte('.')
		name = name[dot+1:]
	}
	if c.Quoted {
		writeQuotedIdentifier(buf, name)
		return
	}
	writeName(buf, name)
}

// writePostfixOperand writes the operand of a postfix operator (AT TIME ZONE,
// COLLATE), which binds tighter than the arithmetic and comparison operators:
// an operand that is itself an infix expression keeps its parentheses so the
// operator still applies to all of it.
func writePostfixOperand(buf *bytes.Buffer, e Expression) {
	switch e.(type) {
	case *BinaryExpression, *BetweenExpression, *InExpression,
		*AnyExpression, *AllExpression, *AnyAllExpression, *TernaryExpression:
		buf.WriteByte('(')
		writeExpr(buf, e)
		buf.WriteByte(')')
	default:
		writeExpr(buf, e)
	}
}

// SQL returns "expr op ANY (array)" for a quantified comparison over an
// array-valued expression.
func (a *AnyAllExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AnyAllExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Expr)
	buf.WriteByte(' ')
	writeOperator(buf, a.Operator)
	buf.WriteByte(' ')
	switch {
	case strings.EqualFold(a.Quantifier, "ALL"):
		buf.WriteString("ALL")
	case strings.EqualFold(a.Quantifier, "SOME"):
		buf.WriteString("SOME")
	default:
		buf.WriteString("ANY")
	}
	buf.WriteString(" (")
	if sq, ok := a.Array.(*SubqueryExpression); ok && sq != nil {
		// SOME (SELECT ...): the subquery brings the parentheses.
		writeStmt(buf, sq.Subquery)
	} else {
		writeExpr(buf, a.Array)
	}
	buf.WriteByte(')')
}

// SQL returns "cond ? then : else".
func (t *TernaryExpression) SQL() string {
	if t == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	t.writeSQL(buf)
	return buf.String()
}

func (t *TernaryExpression) writeSQL(buf *bytes.Buffer) {
	if t == nil {
		return
	}
	writeExpr(buf, t.Cond)
	buf.WriteString(" ? ")
	writeExpr(buf, t.Then)
	buf.WriteString(" : ")
	writeExpr(buf, t.Else)
}

// inKeywords returns the keyword run that precedes an IN list, with the
// leading space: " IN", " NOT IN", " GLOBAL IN" or " GLOBAL NOT IN".
func inKeywords(global, not bool) string {
	switch {
	case global && not:
		return " GLOBAL NOT IN"
	case global:
		return " GLOBAL IN"
	case not:
		return " NOT IN"
	}
	return " IN"
}

// writeEscape writes the " ESCAPE expr" tail of a LIKE-style pattern match.
func writeEscape(buf *bytes.Buffer, esc Expression) {
	if esc == nil {
		return
	}
	buf.WriteString(" ESCAPE ")
	writeExpr(buf, esc)
}
