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

// TestBinaryExpression_PipesOrSQL_Issue781 checks that a MySQL || OR keeps its
// spelling in SQL(), and that PipesOr only affects the OR operator.
func TestBinaryExpression_PipesOrSQL_Issue781(t *testing.T) {
	a := &Identifier{Name: "a"}
	b := &Identifier{Name: "b"}
	cases := []struct {
		name string
		expr *BinaryExpression
		want string
	}{
		{"pipes_or", &BinaryExpression{Left: a, Operator: "OR", Right: b, PipesOr: true}, "a || b"},
		{"keyword_or", &BinaryExpression{Left: a, Operator: "OR", Right: b}, "a OR b"},
		{"lowercase_or", &BinaryExpression{Left: a, Operator: "or", Right: b, PipesOr: true}, "a || b"},
		{"ignored_for_and", &BinaryExpression{Left: a, Operator: "AND", Right: b, PipesOr: true}, "a AND b"},
		{"concat", &BinaryExpression{Left: a, Operator: "||", Right: b}, "a || b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.expr.SQL(); got != tc.want {
				t.Fatalf("SQL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBinaryExpression_PipesOrPoolReset_Issue781 checks that a released
// BinaryExpression does not carry PipesOr to its next user.
func TestBinaryExpression_PipesOrPoolReset_Issue781(t *testing.T) {
	for i := 0; i < 64; i++ {
		e := GetBinaryExpression()
		if e.PipesOr {
			t.Fatal("pooled BinaryExpression has PipesOr set")
		}
		e.Operator = "OR"
		e.PipesOr = true
		PutBinaryExpression(e)
	}
}
