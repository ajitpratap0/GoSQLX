// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import "strings"

// OperatorNeedsRetarget reports whether an expression itself would be changed
// or rejected by RetargetOperators with an unknown source dialect. Callers must
// also inspect its children. It does not allocate or modify the expression.
func OperatorNeedsRetarget(e Expression, target string) bool {
	switch e.(type) {
	case *BinaryExpression, *UnaryExpression, *UnicodeEscapeExpression, *ObjectLiteral:
	default:
		return false
	}
	// Only these target names affect the rules below. EqualFold keeps this
	// predicate allocation-free even when the caller uses mixed case.
	switch target {
	case "", "postgresql", "mysql", "mariadb", "sqlserver", "snowflake", "clickhouse", "sqlite", "oracle", "generic":
	default:
		for _, name := range [...]string{"postgresql", "mysql", "mariadb", "sqlserver", "snowflake", "clickhouse", "sqlite", "oracle", "generic"} {
			if strings.EqualFold(target, name) {
				target = name
				break
			}
		}
	}
	if target == "generic" {
		target = ""
	}
	switch x := e.(type) {
	case *BinaryExpression:
		if x == nil || x.CustomOp != nil || x.Not {
			return false
		}
		if x.Operator == "^" {
			if x.BitwiseXor {
				source := "mysql"
				if x.XorAtAdditive {
					source = "sqlserver"
				}
				if xorFamily(source) != xorFamily(target) {
					return true
				}
			} else if target != "" && target != "postgresql" {
				return true
			}
		} else if form, _ := binaryTargetForm(x.Operator, x.PipesOr, x.Lambda, target); form != formKeep {
			return true
		} else if retargetExpressionPrecedence(x) < 6 {
			return false
		}
		return targetOperandNeedsParens(x, x.Left, false, target) || targetOperandNeedsParens(x, x.Right, true, target)
	case *UnaryExpression:
		if x == nil || target == "postgresql" {
			return false
		}
		switch x.Operator {
		case PGAbs, PGSquareRoot, PGCubeRoot, PGPrefixFactorial, PGPostfixFactorial:
			return true
		case PGBitwiseNot:
			return target == "snowflake" || target == "clickhouse" || target == "oracle"
		}
	case *UnicodeEscapeExpression:
		return x != nil && target != "postgresql"
	case *ObjectLiteral:
		return x != nil && target != "snowflake"
	}
	return false
}

// retargetExpressionPrecedence avoids case-conversion allocations on manually
// constructed binary nodes whose keyword operators are lower case.
func retargetExpressionPrecedence(e Expression) int {
	x, ok := e.(*BinaryExpression)
	if !ok || x == nil || x.CustomOp != nil {
		return expressionPrecedence(e)
	}
	switch x.Operator {
	case "=", "!=", "<>", "<", ">", "<=", ">=", "==":
		return 5
	case "+", "-":
		return 7
	case "*", "/", "%":
		return 8
	case "^":
		if x.BitwiseXor && x.XorAtAdditive {
			return 7
		}
		return 9
	}
	if x.Operator == "" || x.Operator[0] < 'A' || x.Operator[0] > 'z' {
		return 6
	}
	for _, entry := range [...]struct {
		op   string
		prec int
	}{
		{"OR", 1}, {"XOR", 2}, {"AND", 3}, {"NOT", 4},
		{"IS", 5}, {"IS NOT", 5}, {"IS NULL", 5}, {"IS DISTINCT FROM", 5}, {"IS NOT DISTINCT FROM", 5},
		{"LIKE", 5}, {"ILIKE", 5}, {"SIMILAR TO", 5}, {"REGEXP", 5}, {"RLIKE", 5}, {"GLOB", 5}, {"MATCH", 5}, {"SOUNDS LIKE", 5},
		{"DIV", 8}, {"MOD", 8},
	} {
		if strings.EqualFold(x.Operator, entry.op) {
			return entry.prec
		}
	}
	return 6
}
