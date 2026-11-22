// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRetargetOperatorsDeepChain(t *testing.T) {
	for _, terms := range []int{50000, 500000} {
		if terms == 500000 && (testing.Short() || raceEnabled) {
			continue
		}
		for _, op := range []string{"OR", "AND", "+", "||", "^", "#"} {
			t.Run(op+"/"+strconv.Itoa(terms), func(t *testing.T) {
				var expr Expression = &LiteralValue{Value: 1, Type: "number"}
				for range terms {
					expr = &BinaryExpression{Left: expr, Operator: op, Right: &LiteralValue{Value: 1, Type: "number"}}
				}
				tree := NewAST()
				defer ReleaseAST(tree)
				stmt := &SelectStatement{Columns: []Expression{expr}}
				tree.Statements = []Statement{stmt}
				err := RetargetOperators(stmt, "postgresql", "mysql")
				if op == "^" || op == "#" {
					if err == nil || !strings.Contains(err.Error(), "nesting too deep") {
						t.Fatalf("expected bounded nesting error, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if op == "||" {
					call, ok := stmt.Columns[0].(*FunctionCall)
					if !ok || call.Name != "CONCAT" || len(call.Arguments) != terms+1 {
						t.Fatalf("expected flat CONCAT with %d arguments", terms+1)
					}
				}
			})
		}
	}
}

func TestRetargetOperatorsPostOrderAndMap(t *testing.T) {
	a, b, c := &Identifier{Name: "a"}, &Identifier{Name: "b"}, &Identifier{Name: "c"}
	concat := &BinaryExpression{Left: &BinaryExpression{Left: a, Operator: "||", Right: b}, Operator: "||", Right: c}
	power := &BinaryExpression{Left: &BinaryExpression{Left: a, Operator: "^", Right: b}, Operator: "^", Right: c}
	values := map[string]Expression{"concat": concat, "power": power}
	r := operatorRetargeter{from: "postgresql", to: "mysql", seen: map[uintptr]struct{}{}}
	r.walk(reflect.ValueOf(values), false, nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	call, ok := values["concat"].(*FunctionCall)
	if !ok || call.Name != "CONCAT" || !reflect.DeepEqual(call.Arguments, []Expression{a, b, c}) {
		t.Fatal("CONCAT post-order flattening or map write-back changed")
	}
	outer, ok := values["power"].(*FunctionCall)
	if !ok || outer.Name != "POWER" || outer.Arguments[1] != c {
		t.Fatal("outer POWER changed")
	}
	inner, ok := outer.Arguments[0].(*FunctionCall)
	if !ok || inner.Name != "POWER" || !reflect.DeepEqual(inner.Arguments, []Expression{a, b}) {
		t.Fatal("nested POWER post-order changed")
	}
}

func TestRetargetOperatorsConcatSharedArguments(t *testing.T) {
	r := operatorRetargeter{to: "mysql"}
	a, b := &Identifier{Name: "a"}, &Identifier{Name: "b"}
	child := r.rewriteConcat(&BinaryExpression{Left: a, Operator: "||", Right: b})
	// Give a shared child spare capacity to exercise both the reuse and copy paths.
	childCall, ok := child.(*FunctionCall)
	if !ok {
		t.Fatal("expected CONCAT")
	}
	childCall.Arguments = append(make([]Expression, 0, 8), childCall.Arguments...)
	c, d := &Identifier{Name: "c"}, &Identifier{Name: "d"}
	first := r.rewriteConcat(&BinaryExpression{Left: child, Operator: "||", Right: c})
	second := r.rewriteConcat(&BinaryExpression{Left: child, Operator: "||", Right: d})
	firstCall, firstOK := first.(*FunctionCall)
	secondCall, secondOK := second.(*FunctionCall)
	if !firstOK || !secondOK {
		t.Fatal("expected parent CONCATs")
	}
	if !reflect.DeepEqual(firstCall.Arguments, []Expression{a, b, c}) || !reflect.DeepEqual(secondCall.Arguments, []Expression{a, b, d}) || len(childCall.Arguments) != 2 {
		t.Fatal("flattening changed a shared CONCAT's arguments")
	}
}
