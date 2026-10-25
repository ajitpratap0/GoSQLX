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

// TestReleaseASTReachesValuesAndSetOperations checks that ReleaseAST returns
// the pooled nodes under a standalone VALUES statement, a top-level set
// operation and a VALUES derived table, as it does for a SELECT.
func TestReleaseASTReachesValuesAndSetOperations(t *testing.T) {
	newTuple := func() *TupleExpression {
		tup := GetTupleExpression()
		tup.Expressions = append(tup.Expressions, &LiteralValue{Value: "1"})
		return tup
	}
	tests := []struct {
		name  string
		build func() (Statement, *TupleExpression)
	}{
		{"standalone VALUES", func() (Statement, *TupleExpression) {
			tup := newTuple()
			return &Values{Rows: [][]Expression{{tup}}}, tup
		}},
		{"top-level set operation", func() (Statement, *TupleExpression) {
			tup := newTuple()
			left := &SelectStatement{Columns: []Expression{tup}}
			right := &SelectStatement{Columns: []Expression{&LiteralValue{Value: "2"}}}
			return &SetOperation{Left: left, Right: right, Operator: "UNION"}, tup
		}},
		{"nested set operation with VALUES operand", func() (Statement, *TupleExpression) {
			tup := newTuple()
			inner := &SetOperation{Left: &SelectStatement{}, Right: &Values{Rows: [][]Expression{{tup}}}, Operator: "UNION"}
			return &SetOperation{Left: inner, Right: &SelectStatement{}, Operator: "UNION"}, tup
		}},
		{"VALUES derived table", func() (Statement, *TupleExpression) {
			tup := newTuple()
			sel := &SelectStatement{From: []TableReference{{Values: &Values{Rows: [][]Expression{{tup}}}, Alias: "v"}}}
			return sel, tup
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt, tup := tc.build()
			tree := NewAST()
			tree.Statements = append(tree.Statements, stmt)
			ReleaseAST(tree)
			if len(tup.Expressions) != 0 {
				t.Fatalf("tuple under %T was not released: %+v", stmt, tup)
			}
		})
	}
}
