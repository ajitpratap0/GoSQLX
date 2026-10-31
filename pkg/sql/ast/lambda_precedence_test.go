// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import "testing"

// handLambda builds x -> x > 1 without positions or parentheses, as API
// users do; the body is the whole comparison.
func handLambda(lambda bool) *BinaryExpression {
	body := &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: ">", Right: &LiteralValue{Value: "1", Type: "int"}}
	return &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: "->", Right: body, Lambda: lambda}
}

// A lambda binds looser than every operator, so SQL() never groups its body;
// the JSON arrow binds tighter than a comparison and must (#897).
func TestLambdaSQLDoesNotGroupBody(t *testing.T) {
	if got := handLambda(true).SQL(); got != "x -> x > 1" {
		t.Errorf("lambda SQL() = %q", got)
	}
	if got := handLambda(false).SQL(); got != "x -> (x > 1)" {
		t.Errorf("JSON arrow SQL() = %q", got)
	}
	// A lambda used as an operand is grouped.
	outer := &BinaryExpression{Left: handLambda(true), Operator: "=", Right: &Identifier{Name: "y"}}
	if got := outer.SQL(); got != "(x -> x > 1) = y" {
		t.Errorf("lambda operand SQL() = %q", got)
	}
}

// Retargeting keeps a lambda body ungrouped for the lambda dialects and
// groups it where -> is the tighter JSON operator.
func TestRetargetLambdaBodyGrouping(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   string
	}{
		{"clickhouse", "x -> x > 1"},
		{"snowflake", "x -> x > 1"},
		{"mysql", "x -> (x > 1)"},
		{"sqlite", "x -> (x > 1)"},
		{"postgresql", "x -> (x > 1)"},
	} {
		lambda := handLambda(true)
		body, ok := lambda.Right.(*BinaryExpression)
		if !ok {
			t.Fatalf("body %T", lambda.Right)
		}
		// Positioned like parsed nodes, so SQL() adds no parentheses itself.
		body.Pos.Line, lambda.Pos.Line = 1, 1
		stmt := &SelectStatement{Columns: []Expression{lambda}}
		if got := OperatorNeedsRetarget(lambda, tc.target); got != (tc.want != "x -> x > 1") {
			t.Errorf("%s: OperatorNeedsRetarget = %v", tc.target, got)
		}
		if err := RetargetOperators(stmt, "", tc.target); err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if got := exprSQL(stmt.Columns[0]); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.target, got, tc.want)
		}
	}
}
