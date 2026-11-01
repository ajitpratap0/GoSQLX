// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import "fmt"

// binaryForm says how a binary operator is written in a target dialect.
type binaryForm uint8

const (
	formKeep   binaryForm = iota // the operator is written unchanged
	formFunc                     // a two-argument function call
	formXorOp                    // PostgreSQL # written as the target's ^
	formConcat                   // || concatenation written as CONCAT()
	formRefuse                   // no equivalent: RetargetOperators fails
)

// binaryTargetForm returns how the bitwise, concatenation and PostgreSQL-only
// operator op is written for target (normalized: "" is generic). It covers
// only operators whose spelling is the same in every source dialect that
// parses them, so it needs no source dialect:
//
//   - # is PostgreSQL's bitwise XOR (# starts a comment in MySQL): ^ in the
//     MySQL family and SQL Server, BITXOR() in Snowflake, bitXor() in
//     ClickHouse; Oracle, SQLite and the generic dialect have no XOR.
//   - << >> & | become Snowflake/ClickHouse functions, SQL Server
//     LEFT_SHIFT()/RIGHT_SHIFT() and Oracle BITAND(); Oracle has no |, << or >>.
//   - || concatenation becomes CONCAT() in MySQL and MariaDB, where || is OR.
//   - PostgreSQL containment, JSON key, text search, overlap, distance and
//     regular-expression operators are refused in the other known dialects.
//   - A lambda (lambda is BinaryExpression.Lambda) is refused in every known
//     dialect without lambdas, where -> is JSON field access. JSON -> and ->>
//     are refused in ClickHouse and Snowflake, where -> is the lambda operator
//     and ->> is Snowflake's flow operator. The generic dialect keeps both.
func binaryTargetForm(op string, pipesOr, lambda bool, target string) (binaryForm, string) {
	if lambda {
		if target == "" || lambdaTarget(target) {
			return formKeep, ""
		}
		return formRefuse, ""
	}
	switch op {
	case "->", "->>":
		if lambdaTarget(target) {
			return formRefuse, ""
		}
	case "#":
		switch target {
		case "postgresql":
			return formKeep, ""
		case "mysql", "mariadb", "sqlserver":
			return formXorOp, ""
		case "snowflake":
			return formFunc, "BITXOR"
		case "clickhouse":
			return formFunc, "bitXor"
		}
		return formRefuse, ""
	case "<<", ">>":
		left := op == "<<"
		switch target {
		case "sqlserver":
			return formFunc, pick(left, "LEFT_SHIFT", "RIGHT_SHIFT")
		case "snowflake":
			return formFunc, pick(left, "BITSHIFTLEFT", "BITSHIFTRIGHT")
		case "clickhouse":
			return formFunc, pick(left, "bitShiftLeft", "bitShiftRight")
		case "oracle":
			return formRefuse, ""
		}
	case "&":
		switch target {
		case "snowflake", "oracle":
			return formFunc, "BITAND"
		case "clickhouse":
			return formFunc, "bitAnd"
		}
	case "|":
		switch target {
		case "snowflake":
			return formFunc, "BITOR"
		case "clickhouse":
			return formFunc, "bitOr"
		case "oracle":
			return formRefuse, ""
		}
	case "||":
		if !pipesOr && (target == "mysql" || target == "mariadb") {
			return formConcat, ""
		}
	case "@>", "<@", "?", "?|", "?&", "#>", "#>>", "#-", "@@", "&&", "<->", "~", "~*", "!~", "!~*":
		switch target {
		case "mysql", "mariadb", "sqlserver", "oracle", "sqlite", "snowflake", "clickhouse":
			return formRefuse, ""
		}
	}
	return formKeep, ""
}

func pick(first bool, a, b string) string {
	if first {
		return a
	}
	return b
}

// rewriteBitwise applies binaryTargetForm to x. handled is false when x keeps
// its operator.
func (r *operatorRetargeter) rewriteBitwise(x *BinaryExpression, inOperator bool) (repl Expression, handled bool, err error) {
	form, name := binaryTargetForm(x.Operator, x.PipesOr, x.Lambda, r.to)
	switch form {
	case formFunc:
		return &FunctionCall{Name: name, Arguments: []Expression{x.Left, x.Right}}, true, nil
	case formXorOp:
		return groupOperator(x, "^", inOperator, r.to == "sqlserver"), true, nil
	case formConcat:
		call := &FunctionCall{Name: "CONCAT", Arguments: r.concatArgs(x.Right, r.concatArgs(x.Left, nil))}
		if r.concats == nil {
			r.concats = map[*FunctionCall]struct{}{}
		}
		r.concats[call] = struct{}{}
		return call, true, nil
	case formRefuse:
		what := "the PostgreSQL operator " + x.Operator
		switch {
		case x.Lambda:
			what = "the lambda operator ->"
		case x.Operator == "->" || x.Operator == "->>":
			what = "the JSON operator " + x.Operator
		case x.Operator == "#":
			what = "the PostgreSQL bitwise XOR operator #"
		}
		return nil, true, fmt.Errorf("%s has no equivalent in %s", what, r.target())
	}
	return nil, false, nil
}

// concatArgs appends the operands of e, splicing in the arguments of a
// CONCAT() this retargeter already made for a nested || chain (operands are
// rewritten before their parent), so a || b || c becomes CONCAT(a, b, c).
func (r *operatorRetargeter) concatArgs(e Expression, out []Expression) []Expression {
	if p, ok := e.(*ParenthesizedExpression); ok && p != nil {
		if call, ok := p.Expr.(*FunctionCall); ok {
			if _, made := r.concats[call]; made {
				return append(out, call.Arguments...)
			}
		}
	}
	if call, ok := e.(*FunctionCall); ok {
		if _, made := r.concats[call]; made {
			return append(out, call.Arguments...)
		}
	}
	return append(out, e)
}
