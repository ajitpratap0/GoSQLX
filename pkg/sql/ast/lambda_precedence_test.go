// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"strings"
	"testing"
)

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

// Retargeting keeps a lambda body ungrouped for the lambda dialects. Every
// other known dialect reads -> as JSON field access (or not at all), so a
// lambda is refused there instead of changing meaning. The generic dialect
// keeps it, grouped like its JSON ->.
func TestRetargetLambdaBodyGrouping(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   string // "" means the retarget is refused
	}{
		{"clickhouse", "x -> x > 1"},
		{"snowflake", "x -> x > 1"},
		{"", "x -> (x > 1)"},
		{"postgresql", ""},
		{"mysql", ""},
		{"mariadb", ""},
		{"sqlite", ""},
		{"sqlserver", ""},
		{"oracle", ""},
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
			t.Errorf("%q: OperatorNeedsRetarget = %v", tc.target, got)
		}
		err := RetargetOperators(stmt, "", tc.target)
		if tc.want == "" {
			if err == nil || !strings.Contains(err.Error(), "the lambda operator -> has no equivalent in "+tc.target) {
				t.Errorf("%q: got %q, %v; want a lambda refusal", tc.target, exprSQL(stmt.Columns[0]), err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.target, err)
		}
		if got := exprSQL(stmt.Columns[0]); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.target, got, tc.want)
		}
	}
}

// JSON -> and ->> are refused in ClickHouse and Snowflake, where -> is the
// lambda operator (and ->> Snowflake's flow operator), and kept elsewhere.
func TestRetargetJSONArrowToLambdaDialects(t *testing.T) {
	for _, op := range []string{"->", "->>"} {
		for _, target := range []string{"clickhouse", "snowflake", "", "postgresql", "mysql", "mariadb", "sqlite"} {
			arrow := &BinaryExpression{Left: &Identifier{Name: "data"}, Operator: op, Right: &LiteralValue{Value: "a", Type: "string"}}
			stmt := &SelectStatement{Columns: []Expression{arrow}}
			refused := target == "clickhouse" || target == "snowflake"
			if got := OperatorNeedsRetarget(arrow, target); got != refused {
				t.Errorf("%s %q: OperatorNeedsRetarget = %v", op, target, got)
			}
			err := RetargetOperators(stmt, "", target)
			if refused {
				if err == nil || !strings.Contains(err.Error(), "the JSON operator "+op+" has no equivalent in "+target) {
					t.Errorf("%s %q: got %v; want a JSON operator refusal", op, target, err)
				}
			} else if err != nil {
				t.Errorf("%s %q: %v", op, target, err)
			}
		}
	}
}
