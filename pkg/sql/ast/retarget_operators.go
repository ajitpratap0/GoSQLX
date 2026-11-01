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
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/internal/reflplan"
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
//   - PostgreSQL # (XOR), the bitwise and shift operators, || concatenation,
//     PostgreSQL-only operators, lambdas and JSON -> / ->> follow
//     binaryTargetForm: a lambda is refused in dialects without lambdas and
//     JSON -> / ->> in ClickHouse and Snowflake.
//   - SQL Server money literals ($5.00, $5) and Snowflake object constants
//     ({'a': 1}) are refused in other dialects.
//   - PostgreSQL U& escaped literals and identifiers are refused outside
//     PostgreSQL because their source spelling cannot be copied safely.
func RetargetOperators(stmt Statement, from, to string) error {
	if (from != "" && from == to) || stmt == nil {
		return nil
	}
	sc, ok := retargetScratchPool.Get().(*retargetScratch)
	if !ok || sc == nil {
		sc = &retargetScratch{seen: make(map[uintptr]struct{}), stack: make([]operatorWalkFrame, 0, 16)}
	}
	// A walk that panics leaves frames in the backing array that sc.stack no
	// longer covers, so only scratch from a completed walk is reused.
	completed := false
	defer func() {
		if completed && sc.reset() {
			retargetScratchPool.Put(sc)
		}
	}()
	r := operatorRetargeter{from: normalDialect(from), to: normalDialect(to), seen: sc.seen}
	sc.stack = r.walk(reflect.ValueOf(stmt), false, sc.stack[:0])
	completed = true
	return r.err
}

type retargetScratch struct {
	seen  map[uintptr]struct{}
	stack []operatorWalkFrame
}

// reset drops AST references before reuse. Oversized scratch is discarded
// rather than retaining a huge chain in the pool.
func (sc *retargetScratch) reset() bool {
	if len(sc.seen) > 4096 || cap(sc.stack) > 4096 {
		return false
	}
	clear(sc.seen)
	// walk zeroes each frame it pops, so only frames still on the stack (an
	// early return on error) hold reflect.Values into the AST.
	clear(sc.stack)
	sc.stack = sc.stack[:0]
	return true
}

var retargetScratchPool = sync.Pool{New: func() any {
	return &retargetScratch{seen: map[uintptr]struct{}{}, stack: make([]operatorWalkFrame, 0, 16)}
}}

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
	// consumedConcats prevents reuse of a shared child backing array twice.
	consumedConcats map[*FunctionCall]struct{}
	err             error
}

var (
	binaryExprType = reflect.TypeOf(BinaryExpression{})
	unaryExprType  = reflect.TypeOf(UnaryExpression{})
	funcCallType   = reflect.TypeOf(FunctionCall{})
	parenExprType  = reflect.TypeOf(ParenthesizedExpression{})
)

// maxRetargetNesting bounds wrappers introduced by rewriting. The formatter
// renders function arguments and explicit parentheses recursively, even though
// it can render a long binary chain iteratively.
const maxRetargetNesting = 512

type operatorWalkFrame struct {
	value      reflect.Value
	plan       *reflplan.Plan
	slot       reflect.Value
	inOperator bool
	nesting    int
	entered    bool
	index      int
	iter       *reflect.MapIter
	mapValue   reflect.Value
	mapKey     reflect.Value
}

// walk visits exported fields in their original order using heap frames. Each
// settable expression slot is rewritten after its children; map copies are
// written back only after their complete subtree has been rewritten. Fields,
// elements and map values whose static type cannot hold an interface (see
// reflplan) are skipped: they hold no expression slot to rewrite. Pruning
// interface-free pointers also removes them from address-only seen sets; this
// can only visit more, never fewer, so output differs from an unpruned walk
// only if a pruned value aliased the address of a rewrite-bearing node, which
// the parser does not produce. stack is reused scratch (nil is fine); the
// returned slice is the stack for the next call.
func (r *operatorRetargeter) walk(v reflect.Value, inOperator bool, stack []operatorWalkFrame) []operatorWalkFrame {
	stack = append(stack, operatorWalkFrame{value: v, plan: reflplan.Of(v.Type()), inOperator: inOperator})
	for len(stack) > 0 && r.err == nil {
		f := &stack[len(stack)-1]
		if !f.entered {
			f.entered = true
			for f.value.Kind() == reflect.Pointer || f.value.Kind() == reflect.Interface {
				if f.value.IsNil() {
					f.value = reflect.Value{}
					break
				}
				if f.value.Kind() == reflect.Pointer {
					ptr := f.value.Pointer()
					if _, ok := r.seen[ptr]; ok {
						f.value = reflect.Value{}
						break
					}
					r.seen[ptr] = struct{}{}
					f.value = f.value.Elem()
					f.plan = f.plan.Elem
				} else {
					f.value = f.value.Elem()
					f.plan = reflplan.Of(f.value.Type())
				}
			}
			if f.value.Kind() == reflect.Struct && r.nestsOutput(f.value) {
				f.nesting++
				if f.nesting > maxRetargetNesting {
					r.err = fmt.Errorf("expression nesting too deep to transpile")
					return stack
				}
			}
		}
		var child reflect.Value
		var childPlan *reflplan.Plan
		operands := false
		switch f.value.Kind() {
		case reflect.Struct:
			if f.index < len(f.plan.Fields) {
				t := f.plan.Type
				operands = t == binaryExprType || t == unaryExprType
				fp := f.plan.Fields[f.index]
				f.index++
				child, childPlan = f.value.Field(fp.Index), fp.Plan
			}
		case reflect.Slice, reflect.Array:
			if f.plan.Elem.Reach && f.index < f.value.Len() {
				child, childPlan = f.value.Index(f.index), f.plan.Elem
				f.index++
			}
		case reflect.Map:
			if f.plan.Elem.Reach {
				if f.iter == nil {
					f.iter = f.value.MapRange()
				}
				if f.iter.Next() {
					child = reflect.New(f.value.Type().Elem()).Elem()
					child.Set(f.iter.Value())
					frame := operatorWalkFrame{value: child, plan: f.plan.Elem, slot: child, nesting: f.nesting, mapValue: f.value, mapKey: f.iter.Key()}
					stack = append(stack, frame)
					continue
				}
			}
		}
		if child.IsValid() {
			stack = append(stack, operatorWalkFrame{value: child, plan: childPlan, slot: child, inOperator: operands, nesting: f.nesting})
			continue
		}
		r.slot(f.slot, f.inOperator)
		if r.err == nil && f.mapValue.IsValid() {
			f.mapValue.SetMapIndex(f.mapKey, f.slot)
		}
		stack[len(stack)-1] = operatorWalkFrame{}
		stack = stack[:len(stack)-1]
	}
	return stack
}

// nestsOutput identifies expression boundaries rendered recursively. Ordinary
// binary chains and flattened CONCAT chains do not consume this depth budget.
func (r *operatorRetargeter) nestsOutput(v reflect.Value) bool {
	// Most visited structs are not expressions; skip the interface conversion.
	switch v.Type() {
	case funcCallType, parenExprType, unaryExprType, binaryExprType:
	default:
		return false
	}
	if !v.CanAddr() || !v.Addr().CanInterface() {
		return false
	}
	switch x := v.Addr().Interface().(type) {
	case *FunctionCall, *ParenthesizedExpression:
		return true
	case *UnaryExpression:
		return true
	case *BinaryExpression:
		if x.CustomOp != nil || x.Not {
			return false
		}
		if x.Operator == "^" {
			if !x.BitwiseXor {
				return r.to != "postgresql" && r.to != ""
			}
			from := r.from
			if from == "" {
				from = "mysql"
				if x.XorAtAdditive {
					from = "sqlserver"
				}
			}
			return xorFamily(from) != xorFamily(r.to)
		}
		form, _ := binaryTargetForm(x.Operator, x.PipesOr, x.Lambda, r.to)
		if form == formFunc || form == formXorOp {
			return true
		}
		return form == formKeep && retargetExpressionPrecedence(x) >= 6 &&
			(targetOperandNeedsParens(x, x.Left, false, r.to) || targetOperandNeedsParens(x, x.Right, true, r.to))
	}
	return false
}

// slot rewrites a settable expression interface after walk has visited its
// subtree. Keeping this separate also preserves repeated interface-slot rewrites
// when pointers are shared and their subtree has already been seen.
func (r *operatorRetargeter) slot(slot reflect.Value, inOperator bool) {
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

// rewriteConcat reuses a generated left CONCAT's argument capacity once. Each
// append preserves the child's prefix and length, and later shared uses copy,
// so flattening a left-associative chain takes linear rather than quadratic
// time without changing expressions that share the original child.
func (r *operatorRetargeter) rewriteConcat(x *BinaryExpression) Expression {
	left := x.Left
	if p, ok := left.(*ParenthesizedExpression); ok && p != nil {
		left = p.Expr
	}
	var args []Expression
	if call, ok := left.(*FunctionCall); ok && call != nil {
		if _, made := r.concats[call]; made {
			if _, used := r.consumedConcats[call]; !used {
				args = call.Arguments
				if r.consumedConcats == nil {
					r.consumedConcats = map[*FunctionCall]struct{}{}
				}
				r.consumedConcats[call] = struct{}{}
			}
		}
	}
	if args == nil {
		args = r.concatArgs(x.Left, nil)
	}
	args = r.concatArgs(x.Right, args)
	call := &FunctionCall{Name: "CONCAT", Arguments: args}
	if r.concats == nil {
		r.concats = map[*FunctionCall]struct{}{}
	}
	r.concats[call] = struct{}{}
	return call
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
		if form, _ := binaryTargetForm(x.Operator, x.PipesOr, x.Lambda, r.to); form == formConcat {
			return r.rewriteConcat(x), nil
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
	if binary.Lambda && lambdaTarget(target) {
		return 0 // looser than OR: the body is never grouped
	}
	// Elsewhere a lambda is refused (binaryTargetForm); the generic dialect
	// writes it as its -> operator, grouped as that operator.
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

// lambdaTarget reports whether -> is the lambda operator in target, as the
// parser reads it (see Parser.arrowIsLambda).
func lambdaTarget(target string) bool {
	return target == "clickhouse" || target == "snowflake"
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
