// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestCheckedFormattingRejectsNestedUnsupportedOperator(t *testing.T) {
	xor := func() ast.Expression {
		return &ast.BinaryExpression{Operator: "^", BitwiseXor: true,
			Left: &ast.Identifier{Name: "a"}, Right: &ast.Identifier{Name: "b"}}
	}
	query := func(e ast.Expression) *ast.SelectStatement { return &ast.SelectStatement{Columns: []ast.Expression{e}} }
	for _, tc := range []struct {
		name string
		stmt ast.Statement
	}{
		{"where", &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, Where: xor()}},
		{"cast", query(&ast.CastExpression{Expr: xor(), Type: "INT"})},
		{"case result", query(&ast.CaseExpression{WhenClauses: []ast.WhenClause{{Condition: &ast.Identifier{Name: "a"}, Result: xor()}}})},
		{"function argument", query(&ast.FunctionCall{Name: "F", Arguments: []ast.Expression{xor()}})},
		{"function parameters", query(&ast.FunctionCall{Name: "F", Parameters: []ast.Expression{xor()}})},
		{"function order", query(&ast.FunctionCall{Name: "F", OrderBy: []ast.OrderByExpression{{Expression: xor()}}})},
		{"window frame", query(&ast.FunctionCall{Name: "F", Over: &ast.WindowSpec{FrameClause: &ast.WindowFrame{End: &ast.WindowFrameBound{Value: xor()}}}})},
		{"cte", &ast.SelectStatement{With: &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", Statement: query(xor())}}}}},
		{"scalar cte", &ast.SelectStatement{With: &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", ScalarExpr: xor()}}}}},
		{"named window", &ast.SelectStatement{Windows: []ast.WindowSpec{{OrderBy: []ast.OrderByExpression{{Expression: xor()}}}}}},
		{"join condition", &ast.SelectStatement{Joins: []ast.JoinClause{{Condition: xor()}}}},
		{"join match condition", &ast.SelectStatement{Joins: []ast.JoinClause{{MatchCondition: xor()}}}},
		{"map value", &ast.SelectStatement{From: []ast.TableReference{{Name: "t", TimeTravel: &ast.TimeTravelClause{Kind: "AT", Named: map[string]ast.Expression{"OFFSET": xor()}}}}}},
		{"subquery", &ast.SelectStatement{From: []ast.TableReference{{Subquery: query(xor())}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ast.CompactStyle()
			opts.Dialect = "sqlite"
			out, err := formatter.FormatStatementChecked(tc.stmt, opts)
			if err == nil || !strings.Contains(err.Error(), "XOR") || out != "" {
				t.Fatalf("got %q, %v; expected unsupported nested XOR error", out, err)
			}
		})
	}
}
