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

package transpiler

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// retargetOperators rewrites operators and literals whose meaning or
// existence depends on the dialect, or fails when the target has no
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
//     CBRT() (where it exists); the factorial operators are refused.
//   - SQL Server money literals ($5.00, $5) and Snowflake object constants
//     ({'a': 1}) are refused in other dialects.
func retargetOperators(stmt ast.Statement, from, to keywords.SQLDialect) error {
	if from == to || stmt == nil {
		return nil
	}
	r := operatorRetargeter{from: normalDialect(from), to: normalDialect(to), seen: map[uintptr]struct{}{}}
	r.walk(reflect.ValueOf(stmt), false)
	return r.err
}

// normalDialect maps the generic dialect to "" and lower-cases the name.
func normalDialect(d keywords.SQLDialect) string {
	s := strings.ToLower(string(d))
	if s == string(keywords.DialectGeneric) {
		return ""
	}
	return s
}

type operatorRetargeter struct {
	from, to string
	seen     map[uintptr]struct{}
	err      error
}

var (
	binaryExprType = reflect.TypeOf(ast.BinaryExpression{})
	unaryExprType  = reflect.TypeOf(ast.UnaryExpression{})
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
	}
}

// slot rewrites the expression held by a settable interface slot after
// rewriting its subtree.
func (r *operatorRetargeter) slot(slot reflect.Value, inOperator bool) {
	r.walk(slot, inOperator)
	if r.err != nil || slot.Kind() != reflect.Interface || slot.IsNil() || !slot.CanSet() {
		return
	}
	e, ok := slot.Interface().(ast.Expression)
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
func (r *operatorRetargeter) rewrite(e ast.Expression, inOperator bool) (ast.Expression, error) {
	switch x := e.(type) {
	case *ast.BinaryExpression:
		if x == nil || x.Operator != "^" || x.CustomOp != nil || x.Not {
			return nil, nil
		}
		if x.BitwiseXor {
			return r.rewriteXor(x, inOperator)
		}
		return r.rewritePower(x)
	case *ast.UnaryExpression:
		if x == nil {
			return nil, nil
		}
		return r.rewritePGPrefix(x)
	case *ast.LiteralValue:
		if x != nil && r.from == string(keywords.DialectSQLServer) && r.to != r.from && isMoneyLiteral(x) {
			return nil, fmt.Errorf("the SQL Server money literal %v has no equivalent in %s", x.Value, r.target())
		}
	case *ast.ObjectLiteral:
		if x != nil && r.to != string(keywords.DialectSnowflake) {
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
func (r *operatorRetargeter) rewritePower(x *ast.BinaryExpression) (ast.Expression, error) {
	if r.to == "" || r.to == string(keywords.DialectPostgreSQL) {
		return nil, nil // same operator and precedence
	}
	return &ast.FunctionCall{Name: "POWER", Arguments: []ast.Expression{x.Left, x.Right}}, nil
}

// rewriteXor handles ^ as bitwise XOR (MySQL, MariaDB, SQL Server).
func (r *operatorRetargeter) rewriteXor(x *ast.BinaryExpression, inOperator bool) (ast.Expression, error) {
	if xorFamily(r.from) == xorFamily(r.to) {
		return nil, nil // same operator and precedence
	}
	switch r.to {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB), string(keywords.DialectSQLServer):
		return groupOperator(x, "^", inOperator), nil
	case string(keywords.DialectPostgreSQL):
		return groupOperator(x, "#", inOperator), nil
	case string(keywords.DialectSnowflake):
		return &ast.FunctionCall{Name: "BITXOR", Arguments: []ast.Expression{x.Left, x.Right}}, nil
	case string(keywords.DialectClickHouse):
		return &ast.FunctionCall{Name: "bitXor", Arguments: []ast.Expression{x.Left, x.Right}}, nil
	}
	return nil, fmt.Errorf("the bitwise XOR operator ^ has no equivalent in %s", r.target())
}

// xorFamily groups the dialects whose ^ is XOR at the same precedence.
func xorFamily(d string) string {
	switch d {
	case string(keywords.DialectMySQL), string(keywords.DialectMariaDB):
		return "mysql"
	}
	return d
}

// groupOperator returns x written with op and explicit parentheses around
// binary operands and, inside another operator, around itself, so the
// grouping of the source survives the target's precedence rules.
func groupOperator(x *ast.BinaryExpression, op string, inOperator bool) ast.Expression {
	out := *x
	out.Operator = op
	out.BitwiseXor = op == "^"
	out.Left = parenthesizeBinary(out.Left)
	out.Right = parenthesizeBinary(out.Right)
	if inOperator {
		return &ast.ParenthesizedExpression{Expr: &out, Pos: x.Pos}
	}
	return &out
}

func parenthesizeBinary(e ast.Expression) ast.Expression {
	if b, ok := e.(*ast.BinaryExpression); ok && b != nil {
		return &ast.ParenthesizedExpression{Expr: b, Pos: b.Pos}
	}
	return e
}

// rewritePGPrefix handles the PostgreSQL-only prefix and postfix operators.
func (r *operatorRetargeter) rewritePGPrefix(x *ast.UnaryExpression) (ast.Expression, error) {
	if r.to == string(keywords.DialectPostgreSQL) {
		return nil, nil
	}
	call := func(name string) ast.Expression {
		return &ast.FunctionCall{Name: name, Arguments: []ast.Expression{x.Expr}}
	}
	switch x.Operator {
	case ast.PGAbs:
		return call("ABS"), nil
	case ast.PGSquareRoot:
		return call("SQRT"), nil
	case ast.PGCubeRoot:
		switch r.to {
		case string(keywords.DialectSnowflake), string(keywords.DialectClickHouse):
			return call("CBRT"), nil
		}
		return nil, fmt.Errorf("the PostgreSQL cube root operator ||/ has no equivalent in %s", r.target())
	case ast.PGPrefixFactorial:
		return nil, fmt.Errorf("the PostgreSQL factorial operator !! has no equivalent in %s", r.target())
	case ast.PGPostfixFactorial:
		return nil, fmt.Errorf("the PostgreSQL factorial operator ! has no equivalent in %s", r.target())
	}
	return nil, nil
}

// isMoneyLiteral reports whether lit is a SQL Server money literal: $5.00,
// or $5, which the parser keeps as a placeholder.
func isMoneyLiteral(lit *ast.LiteralValue) bool {
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
