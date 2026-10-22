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

// Package ast - expressions_primary.go
// Primary-expression nodes for dialect forms that are not ordinary
// comma-separated function calls: keyword-introduced function arguments
// (SUBSTRING(s FROM 1 FOR 2), TRIM(BOTH ' ' FROM s), CONVERT(x USING utf8)),
// typed literals (DATE '2024-01-01'), the Oracle (+) outer-join marker,
// MySQL MATCH ... AGAINST, @@system variables and := assignment, NEXT VALUE
// FOR, CONNECT_BY_ROOT, and the Oracle KEEP (DENSE_RANK ...) clause.

package ast

import (
	"bytes"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// KeywordArgument is a function argument introduced by a keyword instead of
// a comma, as in the SQL-standard special forms:
//
//	SUBSTRING(s FROM 2 FOR 3)          FROM 2, FOR 3
//	POSITION('a' IN s)                 IN s
//	TRIM(BOTH ' ' FROM s)              BOTH ' ', FROM s
//	OVERLAY(s PLACING 'x' FROM 2)      PLACING 'x', FROM 2
//	CONVERT(x USING utf8mb4)           USING utf8mb4 (TypeName)
//	TRY_PARSE('1' AS INT)              AS INT (TypeName)
//	LISTAGG(a, ',' ON OVERFLOW TRUNCATE '...' WITH COUNT)
//
// Inside FunctionCall.Arguments a KeywordArgument is separated from the
// previous argument by a space rather than a comma. Exactly one of Value and
// TypeName is normally set; both are empty for keyword-only parts such as
// TRIM(LEADING FROM s) or WITH COUNT.
type KeywordArgument struct {
	// Keyword is the upper-case introducing keyword(s), e.g. "FROM" or
	// "ON OVERFLOW TRUNCATE". SQL() writes it only when it is one of the
	// keywords the parser produces (see KeywordArgumentText).
	Keyword string
	// Value is the argument expression, or nil.
	Value Expression
	// TypeName is a data type or character set name written after the
	// keyword (AS INT, USING utf8mb4) instead of an expression.
	TypeName string
	Pos      models.Location
}

func (k *KeywordArgument) expressionNode()     {}
func (k KeywordArgument) TokenLiteral() string { return k.Keyword }
func (k KeywordArgument) Children() []Node {
	if k.Value == nil {
		return nil
	}
	return []Node{k.Value}
}

// keywordArgumentKeywords lists the keywords a KeywordArgument may carry.
var keywordArgumentKeywords = []string{
	"FROM", "FOR", "IN", "PLACING", "USING", "AS",
	"BOTH", "LEADING", "TRAILING",
	"ON OVERFLOW ERROR", "ON OVERFLOW TRUNCATE", "WITH COUNT", "WITHOUT COUNT",
}

// KeywordArgumentText returns s when it is a keyword the parser produces for
// a KeywordArgument (any case) and "" otherwise; an unknown keyword is
// dropped by SQL().
func KeywordArgumentText(s string) string { return keywordOneOf(s, keywordArgumentKeywords) }

// SQL returns the argument as "KEYWORD value", "KEYWORD type" or "KEYWORD".
func (k *KeywordArgument) SQL() string {
	if k == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	k.writeSQL(buf)
	return buf.String()
}

func (k *KeywordArgument) writeSQL(buf *bytes.Buffer) {
	if k == nil {
		return
	}
	sep := false
	if kw := KeywordArgumentText(k.Keyword); kw != "" {
		buf.WriteString(kw)
		sep = true
	}
	if k.Value != nil {
		if sep {
			buf.WriteByte(' ')
		}
		writeExpr(buf, k.Value)
	} else if k.TypeName != "" {
		if sep {
			buf.WriteByte(' ')
		}
		writeDataType(buf, k.TypeName)
	}
}

// writeFunctionArgs writes a function argument list: arguments are separated
// by ", " except that a KeywordArgument follows the previous argument after a
// single space (SUBSTRING(s FROM 2 FOR 3)).
func writeFunctionArgs(buf *bytes.Buffer, args []Expression) {
	for i, e := range args {
		if i > 0 {
			if _, ok := e.(*KeywordArgument); ok {
				buf.WriteByte(' ')
			} else {
				buf.WriteString(", ")
			}
		}
		writeExpr(buf, e)
	}
}

// KeepClause is the Oracle aggregate modifier
// KEEP (DENSE_RANK FIRST|LAST ORDER BY ...), as in
// MIN(salary) KEEP (DENSE_RANK FIRST ORDER BY hire_date).
type KeepClause struct {
	// Last is true for DENSE_RANK LAST and false for DENSE_RANK FIRST.
	Last    bool
	OrderBy []OrderByExpression
}

// TokenLiteral implements Node.
func (k *KeepClause) TokenLiteral() string { return "KEEP" }

// Children implements Node and returns the ORDER BY items.
func (k *KeepClause) Children() []Node {
	if k == nil {
		return nil
	}
	children := make([]Node, 0, len(k.OrderBy))
	for i := range k.OrderBy {
		children = append(children, &k.OrderBy[i])
	}
	return children
}

func (k *KeepClause) writeSQL(buf *bytes.Buffer) {
	if k == nil {
		return
	}
	buf.WriteString(" KEEP (DENSE_RANK ")
	if k.Last {
		buf.WriteString("LAST")
	} else {
		buf.WriteString("FIRST")
	}
	buf.WriteString(" ORDER BY ")
	writeOrderBy(buf, k.OrderBy)
	buf.WriteByte(')')
}

// TypedLiteral is a literal written as a type name followed by a string,
// such as DATE '2024-01-01', TIMESTAMP '2024-01-01 00:00:00', TIME '12:00'
// or the PostgreSQL form inet '10.0.0.1'.
type TypedLiteral struct {
	// TypeName is the type as written (DATE, TIMESTAMP, inet).
	TypeName string
	// Value is the unquoted string value.
	Value string
	Pos   models.Location
}

func (t *TypedLiteral) expressionNode()     {}
func (t TypedLiteral) TokenLiteral() string { return t.TypeName }
func (t TypedLiteral) Children() []Node     { return nil }

// SQL returns "TYPE 'value'".
func (t *TypedLiteral) SQL() string {
	if t == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	t.writeSQL(buf)
	return buf.String()
}

func (t *TypedLiteral) writeSQL(buf *bytes.Buffer) {
	if t == nil {
		return
	}
	writeDataType(buf, t.TypeName)
	buf.WriteByte(' ')
	writeStringLiteral(buf, t.Value)
}

// OuterJoinMarker is the Oracle legacy outer-join operator written after a
// column in a WHERE condition: a.id = b.id(+).
type OuterJoinMarker struct {
	Expr Expression
}

func (o *OuterJoinMarker) expressionNode()     {}
func (o OuterJoinMarker) TokenLiteral() string { return "(+)" }
func (o OuterJoinMarker) Children() []Node {
	if o.Expr == nil {
		return nil
	}
	return []Node{o.Expr}
}

// SQL returns "expr(+)".
func (o *OuterJoinMarker) SQL() string {
	if o == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	o.writeSQL(buf)
	return buf.String()
}

func (o *OuterJoinMarker) writeSQL(buf *bytes.Buffer) {
	if o == nil {
		return
	}
	writeExpr(buf, o.Expr)
	buf.WriteString("(+)")
}

// MatchAgainstExpression is the MySQL/MariaDB full-text search predicate
// MATCH (col, ...) AGAINST (expr [modifier]).
type MatchAgainstExpression struct {
	Columns []Expression
	Query   Expression
	// Modifier is the search modifier, upper-cased, e.g. "IN BOOLEAN MODE",
	// "IN NATURAL LANGUAGE MODE WITH QUERY EXPANSION" or "WITH QUERY
	// EXPANSION"; empty when absent. See MatchModifierText.
	Modifier string
	Pos      models.Location
}

func (m *MatchAgainstExpression) expressionNode()     {}
func (m MatchAgainstExpression) TokenLiteral() string { return "MATCH" }
func (m MatchAgainstExpression) Children() []Node {
	children := make([]Node, 0, len(m.Columns)+1)
	for _, c := range m.Columns {
		if c != nil {
			children = append(children, c)
		}
	}
	if m.Query != nil {
		children = append(children, m.Query)
	}
	return children
}

var matchModifierKeywords = []string{
	"IN NATURAL LANGUAGE MODE",
	"IN NATURAL LANGUAGE MODE WITH QUERY EXPANSION",
	"IN BOOLEAN MODE",
	"WITH QUERY EXPANSION",
}

// MatchModifierText returns s when it is a MATCH ... AGAINST search modifier
// (any case) and "" otherwise.
func MatchModifierText(s string) string { return keywordOneOf(s, matchModifierKeywords) }

// SQL returns "MATCH(cols) AGAINST(expr [modifier])".
func (m *MatchAgainstExpression) SQL() string {
	if m == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	m.writeSQL(buf)
	return buf.String()
}

func (m *MatchAgainstExpression) writeSQL(buf *bytes.Buffer) {
	if m == nil {
		return
	}
	buf.WriteString("MATCH(")
	writeExprList(buf, m.Columns)
	buf.WriteString(") AGAINST(")
	writeExpr(buf, m.Query)
	if mod := MatchModifierText(m.Modifier); mod != "" {
		buf.WriteByte(' ')
		buf.WriteString(mod)
	}
	buf.WriteByte(')')
}

// NextValueForExpression is the sequence expression NEXT VALUE FOR seq
// (SQL Server, MariaDB, SQL standard).
type NextValueForExpression struct {
	// Sequence is the possibly qualified sequence name (dbo.seq).
	Sequence string
	Pos      models.Location
}

func (n *NextValueForExpression) expressionNode()     {}
func (n NextValueForExpression) TokenLiteral() string { return "NEXT VALUE FOR" }
func (n NextValueForExpression) Children() []Node     { return nil }

// SQL returns "NEXT VALUE FOR seq".
func (n *NextValueForExpression) SQL() string {
	if n == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	n.writeSQL(buf)
	return buf.String()
}

func (n *NextValueForExpression) writeSQL(buf *bytes.Buffer) {
	if n == nil {
		return
	}
	buf.WriteString("NEXT VALUE FOR ")
	writeQualifiedName(buf, n.Sequence)
}

// SystemVariable is a MySQL/MariaDB system variable reference:
// @@version, @@global.max_connections, @@SESSION.sql_mode.
type SystemVariable struct {
	// Scope is GLOBAL, SESSION, LOCAL or empty, as written.
	Scope string
	Name  string
	Pos   models.Location
}

func (s *SystemVariable) expressionNode() {}
func (s SystemVariable) TokenLiteral() string {
	if s.Scope != "" {
		return "@@" + s.Scope + "." + s.Name
	}
	return "@@" + s.Name
}
func (s SystemVariable) Children() []Node { return nil }

// systemVariableScopes are the scope qualifiers of @@scope.name.
var systemVariableScopes = []string{"GLOBAL", "SESSION", "LOCAL", "PERSIST", "PERSIST_ONLY"}

// SQL returns "@@name" or "@@scope.name".
func (s *SystemVariable) SQL() string {
	if s == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	s.writeSQL(buf)
	return buf.String()
}

func (s *SystemVariable) writeSQL(buf *bytes.Buffer) {
	if s == nil {
		return
	}
	buf.WriteString("@@")
	if sc := keywordOneOf(s.Scope, systemVariableScopes); sc != "" {
		buf.WriteString(sc)
		buf.WriteByte('.')
	}
	if isBareNameChars(s.Name, false) {
		buf.WriteString(s.Name)
	} else {
		writeQuotedIdentifier(buf, s.Name)
	}
}

// AssignmentExpression is the MySQL/MariaDB user-variable assignment
// operator used inside expressions: @rownum := @rownum + 1.
type AssignmentExpression struct {
	Target Expression
	Value  Expression
	Pos    models.Location
}

func (a *AssignmentExpression) expressionNode()     {}
func (a AssignmentExpression) TokenLiteral() string { return ":=" }
func (a AssignmentExpression) Children() []Node {
	children := make([]Node, 0, 2)
	if a.Target != nil {
		children = append(children, a.Target)
	}
	if a.Value != nil {
		children = append(children, a.Value)
	}
	return children
}

// SQL returns "target := value".
func (a *AssignmentExpression) SQL() string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	a.writeSQL(buf)
	return buf.String()
}

func (a *AssignmentExpression) writeSQL(buf *bytes.Buffer) {
	if a == nil {
		return
	}
	writeExpr(buf, a.Target)
	buf.WriteString(" := ")
	writeExpr(buf, a.Value)
}

// ConnectByRootExpression is the Oracle hierarchical-query operator
// CONNECT_BY_ROOT expr, which returns expr evaluated at the root row.
type ConnectByRootExpression struct {
	Expr Expression
	Pos  models.Location
}

func (c *ConnectByRootExpression) expressionNode()     {}
func (c ConnectByRootExpression) TokenLiteral() string { return "CONNECT_BY_ROOT" }
func (c ConnectByRootExpression) Children() []Node {
	if c.Expr == nil {
		return nil
	}
	return []Node{c.Expr}
}

// SQL returns "CONNECT_BY_ROOT expr".
func (c *ConnectByRootExpression) SQL() string {
	if c == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	c.writeSQL(buf)
	return buf.String()
}

func (c *ConnectByRootExpression) writeSQL(buf *bytes.Buffer) {
	if c == nil {
		return
	}
	buf.WriteString("CONNECT_BY_ROOT ")
	writeExpr(buf, c.Expr)
}

// writeIntervalUnit writes an unquoted INTERVAL unit (DAY, YEAR_MONTH, or a
// plural such as DAYS) when it is a plain word, and nothing otherwise.
func writeIntervalUnit(buf *bytes.Buffer, unit string) {
	if unit == "" {
		return
	}
	if IntervalQualifierText(unit) == "" {
		for i := 0; i < len(unit); i++ {
			c := unit[i] | 0x20
			if !(c >= 'a' && c <= 'z' || unit[i] == '_') {
				return
			}
		}
	}
	buf.WriteByte(' ')
	buf.WriteString(strings.ToUpper(unit))
}

// appendClauseChildren appends the SEPARATOR expression and the KEEP ORDER BY
// items of f to children.
func (f *FunctionCall) appendClauseChildren(children []Node) []Node {
	if f.Separator != nil {
		children = append(children, f.Separator)
	}
	if f.Keep != nil {
		children = append(children, f.Keep)
	}
	return children
}

// NationalStringType is the LiteralValue.Type of a SQL Server national
// character string literal, N'abc'.
const NationalStringType = "nstring"

// SystemVariableScopeText returns s when it is a system-variable scope
// (GLOBAL, SESSION, LOCAL, PERSIST, PERSIST_ONLY; any case) and "" otherwise.
func SystemVariableScopeText(s string) string { return keywordOneOf(s, systemVariableScopes) }
