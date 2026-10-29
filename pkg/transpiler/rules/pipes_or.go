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

	"github.com/ajitpratap0/GoSQLX/pkg/internal/reflplan"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// PipesOrToKeywordOr spells a MySQL / MariaDB || logical OR as the OR keyword.
//
// The parser keeps the source spelling of a || OR (BinaryExpression.PipesOr,
// #781) so formatting MySQL SQL does not change its meaning. A target dialect
// that reads || as concatenation (PostgreSQL, SQLite, Oracle, ...) must get
// OR instead; the transpiler applies this rule for those targets.
//
// MySQL:      SELECT * FROM t WHERE a = 1 || b = 2
// PostgreSQL: SELECT * FROM t WHERE a = 1 OR b = 2
func PipesOrToKeywordOr(stmt ast.Statement) error {
	if stmt == nil {
		return nil
	}
	v := reflect.ValueOf(stmt)
	clearPipesOr(v, reflplan.Of(v.Type()), make(map[uintptr]struct{}))
	return nil
}

var binaryExprType = reflect.TypeOf(ast.BinaryExpression{})

// clearPipesOr walks every exported field reachable from v and clears
// PipesOr on each BinaryExpression. Reflection reaches expressions stored in
// value structs and slices that ast.Walk does not visit; seen guards against
// revisiting shared pointers. Parts whose type cannot hold an interface are
// skipped (reflplan): a BinaryExpression is only ever reached through one.
// Pruned interface-free pointers no longer enter the address-only seen set.
// This can only visit more, never fewer; output could differ from an unpruned
// walk only if a pruned value aliased a rewrite node's address, which the
// parser does not produce. Reachable slot order is unchanged.
func clearPipesOr(v reflect.Value, p *reflplan.Plan, seen map[uintptr]struct{}) {
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
		clearPipesOr(v.Elem(), p.Elem, seen)
	case reflect.Interface:
		if !v.IsNil() {
			e := v.Elem()
			clearPipesOr(e, reflplan.Of(e.Type()), seen)
		}
	case reflect.Struct:
		if p.Type == binaryExprType && v.CanAddr() {
			if bin, ok := v.Addr().Interface().(*ast.BinaryExpression); ok {
				bin.PipesOr = false
			}
		}
		for _, f := range p.Fields {
			clearPipesOr(v.Field(f.Index), f.Plan, seen)
		}
	case reflect.Slice, reflect.Array:
		if !p.Elem.Reach {
			return
		}
		for i := 0; i < v.Len(); i++ {
			clearPipesOr(v.Index(i), p.Elem, seen)
		}
	}
}
