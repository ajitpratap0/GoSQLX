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
	"testing"
)

// Tests for issue #612: SetOperation operand parentheses and derived tables
// whose body is a set operation (TableReference.SetSubquery).

func parenSel(n string) *SelectStatement {
	return &SelectStatement{Columns: []Expression{&LiteralValue{Value: n, Type: "INTEGER"}}}
}

func TestSetOperation_ParenthesizedSQL(t *testing.T) {
	tests := []struct {
		name string
		op   *SetOperation
		want string
	}{
		{"no flags", &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2")},
			"SELECT 1 UNION SELECT 2"},
		{"left", &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2"), LeftParenthesized: true},
			"(SELECT 1) UNION SELECT 2"},
		{"right", &SetOperation{Left: parenSel("1"), Operator: "UNION", All: true, Right: parenSel("2"), RightParenthesized: true},
			"SELECT 1 UNION ALL (SELECT 2)"},
		{"both", &SetOperation{Left: parenSel("1"), Operator: "EXCEPT", Right: parenSel("2"), LeftParenthesized: true, RightParenthesized: true},
			"(SELECT 1) EXCEPT (SELECT 2)"},
		{"right set operation without flag is still parenthesized", &SetOperation{
			Left: parenSel("1"), Operator: "EXCEPT",
			Right: &SetOperation{Left: parenSel("2"), Operator: "UNION", Right: parenSel("3")},
		}, "SELECT 1 EXCEPT (SELECT 2 UNION SELECT 3)"},
		{"left set operation without flag stays flat", &SetOperation{
			Left:     &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2")},
			Operator: "UNION", Right: parenSel("3"),
		}, "SELECT 1 UNION SELECT 2 UNION SELECT 3"},
		{"left set operation with flag", &SetOperation{
			Left:     &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2")},
			Operator: "INTERSECT", Right: parenSel("3"), LeftParenthesized: true,
		}, "(SELECT 1 UNION SELECT 2) INTERSECT SELECT 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTableReference_SetSubquery(t *testing.T) {
	so := &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2"), RightParenthesized: true}
	ref := TableReference{Alias: "t", SetSubquery: so, Lateral: true}

	sel := &SelectStatement{Columns: []Expression{&Identifier{Name: "*"}}, From: []TableReference{ref}}
	if got, want := sel.SQL(), "SELECT * FROM LATERAL (SELECT 1 UNION (SELECT 2)) t"; got != want {
		t.Errorf("SQL() = %q, want %q", got, want)
	}

	children := ref.Children()
	if len(children) != 1 {
		t.Fatalf("Children() = %v, want only the set operation", children)
	}
	if got, ok := children[0].(*SetOperation); !ok || got != so {
		t.Fatalf("Children()[0] = %T, want the SetSubquery", children[0])
	}

	// Walk-based tools reach the operands through Children().
	var selects int
	Inspect(sel, func(n Node) bool {
		if _, ok := n.(*SelectStatement); ok {
			selects++
		}
		return true
	})
	if selects != 3 {
		t.Errorf("Inspect visited %d SELECT statements, want 3 (outer + 2 operands)", selects)
	}

	v := &countingVisitor{}
	if err := Walk(v, sel); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if v.setOps != 1 || v.selects != 3 {
		t.Errorf("Walk visited %d set operations and %d selects, want 1 and 3", v.setOps, v.selects)
	}
}

type countingVisitor struct{ setOps, selects int }

func (c *countingVisitor) Visit(n Node) (Visitor, error) {
	switch n.(type) {
	case *SetOperation:
		c.setOps++
	case *SelectStatement:
		c.selects++
	}
	return c, nil
}

// TestReleaseTableReference_SetSubquery checks that releasing a statement whose
// FROM item and JOIN operand carry a SetSubquery releases and clears the
// operands, and that the shared JoinClause.Left copy of From[0] does not lead
// to a second release.
func TestReleaseTableReference_SetSubquery(t *testing.T) {
	fromOp := &SetOperation{
		Left:     &SetOperation{Left: parenSel("1"), Operator: "UNION", Right: parenSel("2")},
		Operator: "UNION",
		Right:    &SetOperation{Left: parenSel("3"), Operator: "EXCEPT", Right: parenSel("4")},
	}
	joinOp := &SetOperation{Left: parenSel("5"), Operator: "UNION", Right: parenSel("6"), RightParenthesized: true}
	fromLeft, ok := fromOp.Left.(*SetOperation)
	if !ok {
		t.Fatalf("fromOp.Left is %T", fromOp.Left)
	}
	fromRight, ok := fromOp.Right.(*SetOperation)
	if !ok {
		t.Fatalf("fromOp.Right is %T", fromOp.Right)
	}

	from0 := TableReference{Alias: "a", SetSubquery: fromOp}
	sel := &SelectStatement{
		Columns: []Expression{&Identifier{Name: "*"}},
		From:    []TableReference{from0},
		Joins: []JoinClause{{
			Type:  "INNER",
			Left:  from0, // value copy sharing SetSubquery, as the parser builds it
			Right: TableReference{Alias: "b", SetSubquery: joinOp},
		}},
	}

	tree := NewAST()
	tree.Statements = append(tree.Statements, sel)
	ReleaseAST(tree)

	for name, so := range map[string]*SetOperation{
		"from": fromOp, "from.left": fromLeft, "from.right": fromRight, "join": joinOp,
	} {
		if so.Left != nil || so.Right != nil {
			t.Errorf("%s: operands not cleared: %+v", name, so)
		}
	}
}

// TestReleaseSetOperationOperands_LongChain checks that a long left-deep chain
// is released iteratively.
func TestReleaseSetOperationOperands_LongChain(t *testing.T) {
	n := 100_000
	if testing.Short() {
		n = 5_000
	}
	var chain Statement = parenSel("0")
	for i := 0; i < n; i++ {
		chain = &SetOperation{Left: chain, Operator: "UNION", Right: parenSel("1")}
	}
	top, ok := chain.(*SetOperation)
	if !ok {
		t.Fatalf("chain is %T", chain)
	}
	ref := TableReference{SetSubquery: top}
	releaseTableReference(&ref, releaseAll)
	if ref.SetSubquery != nil || top.Left != nil || top.Right != nil {
		t.Fatalf("SetSubquery not released: %+v", top)
	}
}
