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
	"strings"
	"testing"
)

// TestUnaryMinusSQL_NoLineComment checks that a unary minus whose operand
// itself renders with a leading '-' is separated from it: "--" starts a SQL
// line comment and would silently comment out the rest of the line.
func TestUnaryMinusSQL_NoLineComment(t *testing.T) {
	one := func() Expression { return &LiteralValue{Value: "1", Type: "INTEGER"} }
	tests := []struct {
		name string
		expr Expression
		want string
	}{
		{
			name: "minus minus literal",
			expr: &UnaryExpression{Operator: Minus, Expr: &UnaryExpression{Operator: Minus, Expr: one()}},
			want: "- -1",
		},
		{
			name: "minus negative literal",
			expr: &UnaryExpression{Operator: Minus, Expr: &LiteralValue{Value: "-1", Type: "INTEGER"}},
			want: "- -1",
		},
		{
			name: "triple minus",
			expr: &UnaryExpression{Operator: Minus, Expr: &UnaryExpression{Operator: Minus, Expr: &UnaryExpression{Operator: Minus, Expr: one()}}},
			want: "- - -1",
		},
		{
			name: "minus identifier",
			expr: &UnaryExpression{Operator: Minus, Expr: &Identifier{Name: "x"}},
			want: "-x",
		},
		{
			name: "plus minus",
			expr: &UnaryExpression{Operator: Plus, Expr: &UnaryExpression{Operator: Minus, Expr: one()}},
			want: "+-1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.expr.(interface{ SQL() string }).SQL()
			if got != tc.want {
				t.Fatalf("SQL() = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "--") {
				t.Fatalf("SQL() = %q contains a line comment marker", got)
			}
		})
	}
}
