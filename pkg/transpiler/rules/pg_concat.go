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

package rules

import (
	"reflect"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PgConcatToMySQLConcat rewrites the PostgreSQL || concatenation operator to
// the MySQL CONCAT() function.
//
// MySQL and MariaDB parse || as logical OR unless the PIPES_AS_CONCAT SQL mode
// is set (#781), so emitting || unchanged would silently turn a concatenation
// into a boolean OR. A left-associative chain is flattened into one call;
// CONCAT matches || on NULL (any NULL argument yields NULL).
//
// PostgreSQL: SELECT first || ' ' || last FROM t
// MySQL:      SELECT CONCAT(first, ' ', last) FROM t
func PgConcatToMySQLConcat(stmt ast.Statement) error {
	if stmt == nil || !containsConcat(stmt) {
		return nil
	}
	rewriteConcatIn(reflect.ValueOf(stmt), make(map[uintptr]struct{}))
	return nil
}

// isConcat reports whether e is a plain || concatenation.
func isConcat(e ast.Expression) (*ast.BinaryExpression, bool) {
	bin, ok := e.(*ast.BinaryExpression)
	if !ok || bin == nil || bin.Operator != "||" || bin.CustomOp != nil || bin.Not {
		return nil, false
	}
	return bin, true
}

// containsConcat is a cheap pre-check so statements without || skip the
// reflective rewrite entirely.
func containsConcat(stmt ast.Statement) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if found {
			return false
		}
		if e, ok := n.(ast.Expression); ok {
			if _, ok := isConcat(e); ok {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

var funcCallType = reflect.TypeOf((*ast.FunctionCall)(nil))

// rewriteConcatIn walks every exported field reachable from v and replaces
// each settable expression slot that holds a || concatenation with a CONCAT()
// call. Expressions are stored in interface-typed fields, slices and value
// structs (e.g. JoinClause), which ast.Walk cannot replace in place, hence
// reflection. seen guards against revisiting shared pointers.
func rewriteConcatIn(v reflect.Value, seen map[uintptr]struct{}) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		ptr := v.Pointer()
		if _, ok := seen[ptr]; ok {
			return
		}
		seen[ptr] = struct{}{}
		rewriteConcatIn(v.Elem(), seen)
	case reflect.Interface:
		if !v.IsNil() {
			rewriteConcatIn(v.Elem(), seen)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			rewriteConcatSlot(v.Field(i), seen)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			rewriteConcatSlot(v.Index(i), seen)
		}
	}
}

// rewriteConcatSlot replaces slot with CONCAT(...) when it is a settable
// interface slot holding a concatenation; otherwise it descends into it.
func rewriteConcatSlot(slot reflect.Value, seen map[uintptr]struct{}) {
	if slot.Kind() == reflect.Interface && !slot.IsNil() && slot.CanSet() &&
		funcCallType.AssignableTo(slot.Type()) {
		if e, ok := slot.Interface().(ast.Expression); ok {
			if bin, ok := isConcat(e); ok {
				slot.Set(reflect.ValueOf(buildConcatCall(bin, seen)))
				return
			}
		}
	}
	rewriteConcatIn(slot, seen)
}

// buildConcatCall flattens a || chain into CONCAT(args...), rewriting any
// concatenation nested inside the operands as well.
func buildConcatCall(bin *ast.BinaryExpression, seen map[uintptr]struct{}) *ast.FunctionCall {
	args := flattenConcat(bin, nil)
	for i := range args {
		rewriteConcatSlot(reflect.ValueOf(&args[i]).Elem(), seen)
	}
	return &ast.FunctionCall{Name: "CONCAT", Arguments: args}
}

func flattenConcat(e ast.Expression, out []ast.Expression) []ast.Expression {
	if bin, ok := isConcat(e); ok {
		out = flattenConcat(bin.Left, out)
		return flattenConcat(bin.Right, out)
	}
	return append(out, e)
}
