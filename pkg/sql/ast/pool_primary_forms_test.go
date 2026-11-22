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

// TestPutExpression_PrimaryFormChildren checks that releasing a
// primary-expression node also releases the pooled nodes under it: a pooled
// ARRAY constructor is reset once it has been returned to its pool.
func TestPutExpression_PrimaryFormChildren(t *testing.T) {
	newArray := func() *ArrayConstructorExpression {
		a := GetArrayConstructor()
		a.Bracket = true
		a.Elements = append(a.Elements, &LiteralValue{Value: "1", Type: "int"})
		return a
	}
	tests := []struct {
		name  string
		build func(child Expression) Expression
	}{
		{"KeywordArgument", func(c Expression) Expression { return &KeywordArgument{Keyword: "FROM", Value: c} }},
		{"MatchAgainstExpression column", func(c Expression) Expression {
			return &MatchAgainstExpression{Columns: []Expression{c}, Query: &LiteralValue{Value: "x", Type: "string"}}
		}},
		{"MatchAgainstExpression query", func(c Expression) Expression { return &MatchAgainstExpression{Query: c} }},
		{"OuterJoinMarker", func(c Expression) Expression { return &OuterJoinMarker{Expr: c} }},
		{"ConnectByRootExpression", func(c Expression) Expression { return &ConnectByRootExpression{Expr: c} }},
		{"AssignmentExpression", func(c Expression) Expression {
			return &AssignmentExpression{Target: &LiteralValue{Value: "@a", Type: "placeholder"}, Value: c}
		}},
		{"IntervalExpression", func(c Expression) Expression {
			return &IntervalExpression{Value: "x DAY", ValueExpr: c, Unit: "DAY"}
		}},
		{"FunctionCall KEEP", func(c Expression) Expression {
			return &FunctionCall{Name: "MAX", Extras: &FunctionExtras{Keep: &KeepClause{OrderBy: []OrderByExpression{{Expression: c}}}}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arr := newArray()
			PutExpression(tt.build(arr))
			if arr.Bracket || len(arr.Elements) != 0 {
				t.Errorf("child ARRAY constructor was not released: %+v", *arr)
			}
		})
	}
}

// TestPutExpression_ArrayQueryReleased checks that the set-operation body of
// ARRAY(SELECT ... UNION SELECT ...) has its operand statements released.
func TestPutExpression_ArrayQueryReleased(t *testing.T) {
	left, right := GetSelectStatement(), GetSelectStatement()
	left.Distinct, right.Distinct = true, true
	arr := GetArrayConstructor()
	arr.Query = &SetOperation{Left: left, Right: right, Operator: "UNION"}
	PutExpression(arr)
	if left.Distinct || right.Distinct {
		t.Errorf("ARRAY(query) operands were not released: left.Distinct=%v right.Distinct=%v", left.Distinct, right.Distinct)
	}
}
