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

import "testing"

// TestTableFunctionAliasSQL pins how SQL() writes the table-function
// modifiers added for #839 on hand-built references.
func TestTableFunctionAliasSQL(t *testing.T) {
	call := func() *FunctionCall {
		return &FunctionCall{Name: "unnest", Arguments: []Expression{&Identifier{Name: "arr"}}}
	}
	for _, tt := range []struct {
		name string
		ref  TableReference
		want string
	}{
		{"ordinality", TableReference{Name: "unnest", TableFunc: call(), WithOrdinality: true}, "unnest(arr) WITH ORDINALITY"},
		{"ordinality alias", TableReference{Name: "unnest", TableFunc: call(), WithOrdinality: true, Alias: "g"}, "unnest(arr) WITH ORDINALITY g"},
		{"alias list", TableReference{Name: "unnest", TableFunc: call(), Alias: "g", ColumnAliases: &ColumnAliasList{Names: []string{"a", "key"}}}, "unnest(arr) g(a, key)"},
		{"ordinality alias list", TableReference{Name: "unnest", TableFunc: call(), WithOrdinality: true, Alias: "g", ColumnAliases: &ColumnAliasList{Names: []string{"v", "n"}}}, "unnest(arr) WITH ORDINALITY g(v, n)"},
		{"quoted aliases", TableReference{Name: "unnest", TableFunc: call(), Alias: "g", ColumnAliases: &ColumnAliasList{Names: []string{"order", `x"); DROP TABLE t; --`}}}, `unnest(arr) g("order", "x""); DROP TABLE t; --")`},
		// The list belongs to an alias; without one there is nothing to attach it to.
		{"alias list without alias", TableReference{Name: "unnest", TableFunc: call(), ColumnAliases: &ColumnAliasList{Names: []string{"a"}}}, "unnest(arr)"},
		// The parser reads neither modifier for a plain table, so SQL() does
		// not write them there either.
		{"plain table", TableReference{Name: "t", Alias: "x", ColumnAliases: &ColumnAliasList{Names: []string{"a"}}, WithOrdinality: true}, "t x"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tableRefSQL(&tt.ref); got != tt.want {
				t.Fatalf("SQL = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTableFunctionAliasRelease checks that releasing a table reference
// clears the #839 fields so a pooled statement cannot leak them.
func TestTableFunctionAliasRelease(t *testing.T) {
	ref := TableReference{
		Name: "unnest", Alias: "g", WithOrdinality: true, ColumnAliases: &ColumnAliasList{Names: []string{"v", "n"}},
		TableFunc: &FunctionCall{Name: "unnest"},
	}
	releaseTableReference(&ref, releaseAll)
	if ref.WithOrdinality || ref.ColumnAliases != nil || ref.TableFunc != nil || ref.Alias != "" {
		t.Fatalf("table reference not cleared: %+v", ref)
	}
}
