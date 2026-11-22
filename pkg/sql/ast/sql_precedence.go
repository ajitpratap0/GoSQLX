// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"bytes"
	"strings"
)

// expressionPrecedence describes the default (PostgreSQL) operator grammar.
func expressionPrecedence(e Expression) int {
	switch x := e.(type) {
	case *BinaryExpression:
		if x == nil {
			return 100
		}
		if x.CustomOp != nil {
			return 6
		}
		if x.Lambda {
			return 0
		}
		switch strings.ToUpper(x.Operator) {
		case "OR":
			return 1
		case "XOR":
			return 2
		case "AND":
			return 3
		case "NOT":
			return 4
		case "=", "!=", "<>", "<", ">", "<=", ">=", "==", "IS", "IS NOT", "IS NULL", "IS DISTINCT FROM", "IS NOT DISTINCT FROM", "LIKE", "ILIKE", "SIMILAR TO", "REGEXP", "RLIKE", "GLOB", "MATCH", "SOUNDS LIKE":
			return 5
		case "+", "-":
			return 7
		case "*", "/", "%", "DIV", "MOD":
			return 8
		case "^":
			if x.BitwiseXor && x.XorAtAdditive {
				return 7
			}
			return 9
		default:
			return 6
		}
	case *UnaryExpression:
		if x != nil {
			switch x.Operator {
			case Not:
				return 4
			case PGAbs, PGSquareRoot, PGCubeRoot, PGPrefixFactorial:
				return 6
			}
		}
		return 10
	case *BetweenExpression, *InExpression, *AnyExpression, *AllExpression, *AnyAllExpression:
		return 5
	case *AtTimeZoneExpression, *CollateExpression:
		return 10
	default:
		return 100
	}
}

// parsedOperand reports whether child came from the parser, whose trees keep
// the source's explicit parentheses as ParenthesizedExpression nodes and
// group operators by the source dialect's grammar, so SQL() must not add any.
// A child carrying a source position is parsed; a hand-built child (no
// position) is grouped by expressionPrecedence even inside a parsed parent.
// Child kinds without a position field follow their parent.
func parsedOperand(parentPositioned bool, child Expression) bool {
	switch x := child.(type) {
	case *BinaryExpression:
		return x.Pos.Line != 0
	case *UnaryExpression:
		return x.Pos.Line != 0
	case *BetweenExpression:
		return x.Pos.Line != 0
	case *InExpression:
		return x.Pos.Line != 0
	case *AnyAllExpression:
		return x.Pos.Line != 0
	case *AtTimeZoneExpression:
		return x.Pos.Line != 0
	case *CollateExpression:
		return x.Pos.Line != 0
	}
	return parentPositioned
}

// BinaryOperandNeedsParens preserves grouping for operands constructed
// without ParenthesizedExpression nodes; see parsedOperand.
func BinaryOperandNeedsParens(parent *BinaryExpression, child Expression, right bool) bool {
	if parent == nil || child == nil {
		return false
	}
	if _, ok := child.(*ParenthesizedExpression); ok {
		return false
	}
	if parsedOperand(parent.Pos.Line != 0, child) {
		return false
	}
	p, c := expressionPrecedence(parent), expressionPrecedence(child)
	if c != p {
		return c < p
	}
	// Comparisons are non-associative. Right operands at the same level need
	// grouping even for arithmetic: floating point arithmetic is not associative.
	return right || p == 5
}

func writeBinaryOperand(buf *bytes.Buffer, parent *BinaryExpression, child Expression, right bool) {
	parens := BinaryOperandNeedsParens(parent, child, right)
	if parens {
		buf.WriteByte('(')
	}
	writeExpr(buf, child)
	if parens {
		buf.WriteByte(')')
	}
}

func writeUnaryOperand(buf *bytes.Buffer, parent *UnaryExpression) {
	parens := expressionPrecedence(parent.Expr) < expressionPrecedence(parent)
	if _, ok := parent.Expr.(*BinaryExpression); ok && expressionPrecedence(parent) == 6 && expressionPrecedence(parent.Expr) == 6 {
		parens = true
	}
	if parens && parsedOperand(parent.Pos.Line != 0, parent.Expr) {
		parens = false
	}
	if parens {
		buf.WriteByte('(')
	}
	writeExpr(buf, parent.Expr)
	if parens {
		buf.WriteByte(')')
	}
}
