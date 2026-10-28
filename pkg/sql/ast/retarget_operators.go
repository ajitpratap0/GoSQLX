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
	"fmt"
	"reflect"
	"strings"
)

// RetargetOperators rewrites stmt in place for a target dialect. An empty
// source uses expression metadata when the original dialect is unknown.
// It rewrites operators and literals whose meaning or existence depends on
// the dialect, or fails when the target has no
// equivalent; none of them is ever emitted unchanged where it would mean
// something else or not parse:
//
//   - ^ is exponentiation in PostgreSQL (and the generic dialect) and
//     bitwise XOR in MySQL and MariaDB (binding tighter than *) and SQL
//     Server (at the + - level). Exponentiation becomes POWER(a, b) outside
//     PostgreSQL. XOR keeps ^ within its family, becomes ^ with explicit
//     parentheses between the MySQL family and SQL Server, # in PostgreSQL,
//     BITXOR() in Snowflake and bitXor() in ClickHouse, and is refused
//     elsewhere.
//   - The PostgreSQL prefix operators @, |/ and ||/ become ABS(), SQRT() and
//     CBRT() (where it exists); the factorial operators are refused. ~ becomes
//     BITNOT()/bitNot() in Snowflake/ClickHouse and is refused in Oracle.
//   - PostgreSQL # (XOR), the bitwise and shift operators, || concatenation
//     and PostgreSQL-only operators follow binaryTargetForm.
//   - SQL Server money literals ($5.00, $5) and Snowflake object constants
//     ({'a': 1}) are refused in other dialects.
//   - PostgreSQL U& escaped literals and identifiers are refused outside
//     PostgreSQL because their source spelling cannot be copied safely.
func RetargetOperators(stmt Statement, from, to string) error {
	if (from != "" && from == to) || stmt == nil {
		return nil
	}
	r := operatorRetargeter{from: normalDialect(from), to: normalDialect(to), seen: map[uintptr]struct{}{}}
	r.walk(reflect.ValueOf(stmt), false)
	return r.err
}

// normalDialect maps the generic dialect to "" and lower-cases the name.
func normalDialect(d string) string {
	s := strings.ToLower(d)
	if s == "generic" {
		return ""
	}
	return s
}

type operatorRetargeter struct {
	from, to string
	seen     map[uintptr]struct{}
	// concats holds the CONCAT() calls made for || so an enclosing ||
	// splices their arguments instead of nesting calls.
	concats map[*FunctionCall]struct{}
	err     error
}

var (
	binaryExprType = reflect.TypeOf(BinaryExpression{})
	unaryExprType  = reflect.TypeOf(UnaryExpression{})
)

// walk visits every exported field reachable from v. inOperator reports that
// v is an operand of a binary or unary operator expression.
func (r *operatorRetargeter) walk(v reflect.Value, inOperator bool) {
	if r.err != nil {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		ptr := v.Pointer()
		if _, ok := r.seen[ptr]; ok {
			return
		}
		r.seen[ptr] = struct{}{}
		r.walk(v.Elem(), inOperator)
	case reflect.Interface:
		if !v.IsNil() {
			r.walk(v.Elem(), inOperator)
		}
	case reflect.Struct:
		t := v.Type()
		operands := t == binaryExprType || t == unaryExprType
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				r.slot(v.Field(i), operands)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			r.slot(v.Index(i), false)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			value := reflect.New(v.Type().Elem()).Elem()
			value.Set(iter.Value())
			r.slot(value, false)
			if r.err != nil {
				return
			}
			v.SetMapIndex(iter.Key(), value)
		}
	}
}

// slot rewrites the expression held by a settable interface slot after
// rewriting its subtree.
func (r *operatorRetargeter) slot(slot reflect.Value, inOperator bool) {
	r.walk(slot, inOperator)
	if r.err != nil || slot.Kind() != reflect.Interface || slot.IsNil() || !slot.CanSet() {
		return
	}
	e, ok := slot.Interface().(Expression)
	if !ok {
		return
	}
	repl, err := r.rewrite(e, inOperator)
	if err != nil {
		r.err = err
		return
	}
	if repl != nil && reflect.TypeOf(repl).AssignableTo(slot.Type()) {
		slot.Set(reflect.ValueOf(repl))
	}
}

// rewrite returns the replacement for e, or nil to keep it.
func (r *operatorRetargeter) rewrite(e Expression, inOperator bool) (Expression, error) {
	switch x := e.(type) {
	case *BinaryExpression:
		if x == nil || x.CustomOp != nil || x.Not {
			return nil, nil
		}
		if x.Operator == "^" {
			if x.BitwiseXor {
				return r.rewriteXor(x, inOperator)
			}
			return r.rewritePower(x)
		}
		if repl, handled, err := r.rewriteBitwise(x, inOperator); handled {
			return repl, err
		}
		if retargetExpressionPrecedence(x) >= 6 {
			return groupTargetOperands(x, r.to), nil
		}
	case *UnaryExpression:
		if x == nil {
			return nil, nil
		}
		return r.rewritePGPrefix(x)
	case *LiteralValue:
		if x != nil && r.from == "sqlserver" && r.to != r.from && isMoneyLiteral(x) {
			return nil, fmt.Errorf("the SQL Server money literal %v has no equivalent in %s", x.Value, r.target())
		}
	case *UnicodeEscapeExpression:
		if x != nil && r.to != "postgresql" && (r.from == "" || r.from != r.to) {
			return nil, fmt.Errorf("the PostgreSQL Unicode escape syntax U& has no equivalent in %s", r.target())
		}
	case *ObjectLiteral:
		if x != nil && r.to != "snowflake" {
			return nil, fmt.Errorf("the Snowflake object constant {...} has no equivalent in %s", r.target())
		}
	}
	return nil, nil
}

func (r *operatorRetargeter) target() string {
	if r.to == "" {
		return "the generic dialect"
	}
	return r.to
}

// rewritePower handles ^ as exponentiation (PostgreSQL, generic).
func (r *operatorRetargeter) rewritePower(x *BinaryExpression) (Expression, error) {
	if r.to == "postgresql" {
		return groupTargetOperands(x, r.to), nil
	}
	if r.to == "" {
		return groupTargetOperands(x, r.to), nil
	}
	return &FunctionCall{Name: "POWER", Arguments: []Expression{x.Left, x.Right}}, nil
}

// groupTargetOperands preserves a source tree when the target gives its
// operators different precedence. Source positions remain on the copied node.
func groupTargetOperands(x *BinaryExpression, target string) Expression {
	out := *x
	changed := false
	if targetOperandNeedsParens(x, x.Left, false, target) {
		out.Left = &ParenthesizedExpression{Expr: x.Left, Pos: x.Pos}
		changed = true
	}
	if targetOperandNeedsParens(x, x.Right, true, target) {
		out.Right = &ParenthesizedExpression{Expr: x.Right, Pos: x.Pos}
		changed = true
	}
	if changed {
		return &out
	}
	return nil
}

func targetOperandNeedsParens(parent *BinaryExpression, child Expression, right bool, target string) bool {
	if child == nil {
		return false
	}
	if _, ok := child.(*ParenthesizedExpression); ok {
		return false
	}
	p, c := targetExpressionPrecedence(parent, target), targetExpressionPrecedence(child, target)
	if p != c {
		return c < p
	}
	return right
}

func targetExpressionPrecedence(e Expression, target string) int {
	binary, ok := e.(*BinaryExpression)
	if !ok || binary == nil || binary.CustomOp != nil {
		return retargetExpressionPrecedence(e) * 10
	}
	switch binary.Operator {
	case "->", "->>", "#>", "#>>", "@>", "<@", "#-", "?", "?|", "?&":
		switch target {
		case "", "mysql", "mariadb":
			return 110
		case "sqlite":
			return 90
		}
	case "||":
		if target == "sqlite" && !binary.PipesOr {
			return 90
		}
		if target == "" || target == "mysql" || target == "mariadb" {
			if binary.PipesOr {
				return 10
			}
			return 65
		}
	case "^", "&", "|":
		if target == "sqlserver" {
			return 70
		}
		if target == "" || target == "mysql" || target == "mariadb" {
			switch binary.Operator {
			case "|":
				return 60
			case "&":
				return 61
			}
		}
	case "<<", ">>":
		if target == "" || target == "mysql" || target == "mariadb" {
			return 62
		}
	}
	return retargetExpressionPrecedence(e) * 10
}

// rewriteXor handles ^ as bitwise XOR (MySQL, MariaDB, SQL Server).
func (r *operatorRetargeter) rewriteXor(x *BinaryExpression, inOperator bool) (Expression, error) {
	from := r.from
	if from == "" {
		from = "mysql"
		if x.XorAtAdditive {
			from = "sqlserver"
		}
	}
	if xorFamily(from) == xorFamily(r.to) {
		return groupTargetOperands(x, r.to), nil
	}
	switch r.to {
	case "mysql", "mariadb", "sqlserver":
		return groupOperator(x, "^", inOperator, r.to == "sqlserver"), nil
	case "postgresql":
		return groupOperator(x, "#", inOperator, false), nil
	case "snowflake":
		return &FunctionCall{Name: "BITXOR", Arguments: []Expression{x.Left, x.Right}}, nil
	case "clickhouse":
		return &FunctionCall{Name: "bitXor", Arguments: []Expression{x.Left, x.Right}}, nil
	}
	return nil, fmt.Errorf("the bitwise XOR operator ^ has no equivalent in %s", r.target())
}

// xorFamily groups the dialects whose ^ is XOR at the same precedence.
func xorFamily(d string) string {
	switch d {
	case "mysql", "mariadb":
		return "mysql"
	}
	return d
}

// groupOperator returns x written with op and explicit parentheses around
// binary operands and, inside another operator, around itself, so the
// grouping of the source survives the target's precedence rules.
func groupOperator(x *BinaryExpression, op string, inOperator, xorAtAdditive bool) Expression {
	out := *x
	out.Operator = op
	out.BitwiseXor = op == "^"
	out.XorAtAdditive = out.BitwiseXor && xorAtAdditive
	out.Left = parenthesizeBinary(out.Left)
	out.Right = parenthesizeBinary(out.Right)
	if inOperator {
		return &ParenthesizedExpression{Expr: &out, Pos: x.Pos}
	}
	return &out
}

func parenthesizeBinary(e Expression) Expression {
	if b, ok := e.(*BinaryExpression); ok && b != nil {
		return &ParenthesizedExpression{Expr: b, Pos: b.Pos}
	}
	return e
}

// rewritePGPrefix handles the PostgreSQL-only prefix and postfix operators.
func (r *operatorRetargeter) rewritePGPrefix(x *UnaryExpression) (Expression, error) {
	if r.to == "postgresql" {
		return nil, nil
	}
	call := func(name string) Expression {
		return &FunctionCall{Name: name, Arguments: []Expression{x.Expr}}
	}
	switch x.Operator {
	case PGAbs:
		return call("ABS"), nil
	case PGSquareRoot:
		return call("SQRT"), nil
	case PGCubeRoot:
		switch r.to {
		case "snowflake", "clickhouse":
			return call("CBRT"), nil
		}
		return nil, fmt.Errorf("the PostgreSQL cube root operator ||/ has no equivalent in %s", r.target())
	case PGBitwiseNot:
		switch r.to {
		case "snowflake":
			return call("BITNOT"), nil
		case "clickhouse":
			return call("bitNot"), nil
		case "oracle":
			return nil, fmt.Errorf("the bitwise NOT operator ~ has no equivalent in %s", r.target())
		}
	case PGPrefixFactorial:
		return nil, fmt.Errorf("the PostgreSQL factorial operator !! has no equivalent in %s", r.target())
	case PGPostfixFactorial:
		return nil, fmt.Errorf("the PostgreSQL factorial operator ! has no equivalent in %s", r.target())
	}
	return nil, nil
}

// isMoneyLiteral reports whether lit is a SQL Server money literal: $5.00,
// or $5, which the parser keeps as a placeholder.
func isMoneyLiteral(lit *LiteralValue) bool {
	if lit.Type == "money" {
		return true
	}
	v, ok := lit.Value.(string)
	if !ok || lit.Type != "placeholder" || len(v) < 2 || v[0] != '$' {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}
