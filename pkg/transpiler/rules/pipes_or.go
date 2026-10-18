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
	clearPipesOr(reflect.ValueOf(stmt), make(map[uintptr]struct{}))
	return nil
}

var binaryExprType = reflect.TypeOf(ast.BinaryExpression{})

// clearPipesOr walks every exported field reachable from v and clears
// PipesOr on each BinaryExpression. Reflection reaches expressions stored in
// value structs and slices that ast.Walk does not visit; seen guards against
// revisiting shared pointers.
func clearPipesOr(v reflect.Value, seen map[uintptr]struct{}) {
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
		clearPipesOr(v.Elem(), seen)
	case reflect.Interface:
		if !v.IsNil() {
			clearPipesOr(v.Elem(), seen)
		}
	case reflect.Struct:
		if v.Type() == binaryExprType && v.CanAddr() {
			if bin, ok := v.Addr().Interface().(*ast.BinaryExpression); ok {
				bin.PipesOr = false
			}
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				clearPipesOr(v.Field(i), seen)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			clearPipesOr(v.Index(i), seen)
		}
	}
}
