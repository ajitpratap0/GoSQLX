// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

// UnicodeEscapeExpression preserves a PostgreSQL U& quoted literal or name,
// including its optional UESCAPE clause. RawSQL is validated by the tokenizer.
// The parser produces it only for U&'...' strings: U&"..." names are decoded
// into ordinary quoted identifiers. Identifier marks a hand-built U&"..." name.
// It is an unpooled leaf so ordinary identifiers and literals stay compact.
type UnicodeEscapeExpression struct {
	RawSQL     string
	Identifier bool
}

func (*UnicodeEscapeExpression) expressionNode()       {}
func (e UnicodeEscapeExpression) SQL() string          { return e.RawSQL }
func (e UnicodeEscapeExpression) TokenLiteral() string { return e.RawSQL }
func (e UnicodeEscapeExpression) Children() []Node     { return nil }
