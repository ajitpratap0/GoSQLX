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
	"fmt"
	"testing"
)

// Tests for #557: Children() returns value-typed children as pointers into
// the parent's storage instead of heap copies, and Walk reaches the fields of
// JoinClause, WindowFrame and MergeStatement in place through childrenOf.

func ident(name string) *Identifier { return &Identifier{Name: name} }

func lit(v int) *LiteralValue { return &LiteralValue{Value: v, Type: "INTEGER"} }

func obe(name string) OrderByExpression {
	return OrderByExpression{Expression: ident(name), Ascending: true}
}

// assertAliases checks that every pointer in want appears in the result of
// children, and that a second call returns the very same pointer at the same
// position (pointer identity is stable).
func assertAliases(t *testing.T, children func() []Node, want []Node) {
	t.Helper()
	first, second := children(), children()
	if len(first) != len(second) {
		t.Fatalf("two Children() calls returned %d and %d nodes", len(first), len(second))
	}
	for wi, w := range want {
		idx := -1
		for i, c := range first {
			if c == w {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("want[%d] (%T %p) is not returned by Children(); got a copy instead", wi, w, w)
		}
		if second[idx] != w {
			t.Fatalf("want[%d] (%T): second call returned a different pointer", wi, w)
		}
	}
}

func TestChildren_AliasesStoredNodes(t *testing.T) {
	sel := &SelectStatement{
		Columns: []Expression{ident("a")},
		From:    []TableReference{{Name: "t1"}, {Name: "t2"}},
		Joins:   []JoinClause{{Type: "INNER", Right: TableReference{Name: "t3"}}},
		Windows: []WindowSpec{{Name: "w"}},
		OrderBy: []OrderByExpression{obe("a"), obe("b")},
	}
	fn := &FunctionCall{
		Name:        "F",
		Arguments:   []Expression{ident("x")},
		OrderBy:     []OrderByExpression{obe("y")},
		WithinGroup: []OrderByExpression{obe("z")},
	}
	ce := &CaseExpression{WhenClauses: []WhenClause{{Condition: ident("c"), Result: lit(1)}, {Condition: ident("d"), Result: lit(2)}}}
	ws := &WindowSpec{PartitionBy: []Expression{ident("g")}, OrderBy: []OrderByExpression{obe("o")}}
	upd := &UpdateStatement{
		Assignments: []UpdateExpression{{Column: ident("a"), Value: lit(1)}},
		From:        []TableReference{{Name: "f"}},
	}
	del := &DeleteStatement{Using: []TableReference{{Name: "u1"}, {Name: "u2"}}}
	ct := &CreateTableStatement{
		Columns:     []ColumnDef{{Name: "id"}},
		Constraints: []TableConstraint{{Type: "CHECK", Check: ident("ok")}},
		Partitions:  []PartitionDefinition{{Name: "p0"}},
	}
	at := &AlterTableStatement{Actions: []AlterTableAction{{Type: "ADD COLUMN"}, {Type: "DROP COLUMN"}}}
	ci := &CreateIndexStatement{Columns: []IndexColumn{{Column: "a"}, {Column: "b"}}}
	ma := &MergeAction{ActionType: "UPDATE", SetClauses: []SetClause{{Column: "v", Value: lit(1)}}}
	oc := &OnConflict{Action: OnConflictAction{DoUpdate: []UpdateExpression{{Column: ident("b"), Value: lit(2)}}}}
	up := &UpsertClause{Updates: []UpdateExpression{{Column: ident("b"), Value: lit(3)}}}
	cd := &ColumnDef{Name: "c", Constraints: []ColumnConstraint{{Type: "NOT NULL"}, {Type: "UNIQUE"}}}
	mr := &MatchRecognizeClause{OrderBy: []OrderByExpression{obe("ts")}}
	ls := &Select{From: []TableReference{{Name: "t"}}, OrderBy: []OrderByExpression{obe("a")}}
	lu := &Update{Updates: []UpdateExpression{{Column: ident("a"), Value: lit(1)}}}
	te := &TriggerEvent{Type: TriggerEventUpdate, Columns: []Identifier{{Name: "a"}, {Name: "b"}}}

	cases := []struct {
		name string
		node Node
		want []Node
	}{
		{"SelectStatement", sel, []Node{&sel.From[0], &sel.From[1], &sel.Joins[0], &sel.Windows[0], &sel.OrderBy[0], &sel.OrderBy[1]}},
		{"FunctionCall", fn, []Node{&fn.OrderBy[0], &fn.WithinGroup[0]}},
		{"CaseExpression", ce, []Node{&ce.WhenClauses[0], &ce.WhenClauses[1]}},
		{"WindowSpec", ws, []Node{&ws.OrderBy[0]}},
		{"UpdateStatement", upd, []Node{&upd.Assignments[0], &upd.From[0]}},
		{"DeleteStatement", del, []Node{&del.Using[0], &del.Using[1]}},
		{"CreateTableStatement", ct, []Node{&ct.Columns[0], &ct.Constraints[0], &ct.Partitions[0]}},
		{"AlterTableStatement", at, []Node{&at.Actions[0], &at.Actions[1]}},
		{"CreateIndexStatement", ci, []Node{&ci.Columns[0], &ci.Columns[1]}},
		{"MergeAction", ma, []Node{&ma.SetClauses[0]}},
		{"OnConflict", oc, []Node{&oc.Action.DoUpdate[0]}},
		{"UpsertClause", up, []Node{&up.Updates[0]}},
		{"ColumnDef", cd, []Node{&cd.Constraints[0], &cd.Constraints[1]}},
		{"MatchRecognizeClause", mr, []Node{&mr.OrderBy[0]}},
		{"LegacySelect", ls, []Node{&ls.From[0], &ls.OrderBy[0]}},
		{"LegacyUpdate", lu, []Node{&lu.Updates[0]}},
		{"TriggerEvent", te, []Node{&te.Columns[0], &te.Columns[1]}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertAliases(t, c.node.Children, c.want)
			// Walk sees the same pointers.
			assertAliases(t, func() []Node { return childrenOf(c.node) }, c.want)
		})
	}
}

// nodeSignature describes a child list by dynamic type and TokenLiteral.
func nodeSignature(nodes []Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = fmt.Sprintf("%T %q", n, n.TokenLiteral())
	}
	return out
}

// TestChildrenOf_InPlaceFastPath covers the value-receiver nodes whose fields
// Walk reaches through childrenInPlace: childrenOf must address the stored
// struct and must agree with the exported Children() in shape.
func TestChildrenOf_InPlaceFastPath(t *testing.T) {
	cond := &BinaryExpression{Left: ident("a"), Operator: "=", Right: ident("b")}
	end := &WindowFrameBound{Type: "CURRENT ROW"}
	when := &MergeWhenClause{Type: "MATCHED"}
	output := ident("out")

	join := &JoinClause{Type: "LEFT", Left: TableReference{Name: "l"}, Right: TableReference{Name: "r"}, Condition: cond}
	joinNoCond := &JoinClause{Type: "CROSS", Left: TableReference{Name: "l"}, Right: TableReference{Name: "r"}}
	frame := &WindowFrame{Type: "ROWS", Start: WindowFrameBound{Type: "UNBOUNDED PRECEDING"}, End: end}
	frameNoEnd := &WindowFrame{Type: "ROWS", Start: WindowFrameBound{Type: "CURRENT ROW"}}
	merge := &MergeStatement{
		TargetTable: TableReference{Name: "tgt"},
		SourceTable: TableReference{Name: "src"},
		OnCondition: cond,
		WhenClauses: []*MergeWhenClause{when},
		Output:      []Expression{output},
	}

	where := &BinaryExpression{Left: ident("w"), Operator: "=", Right: ident("v")}
	ret := ident("ret")
	insert := &Insert{
		Table:           TableReference{Name: "t"},
		Columns:         []Expression{ident("c")},
		Values:          [][]Expression{{ident("v1")}, {ident("v2")}},
		ReturningClause: []Expression{ret},
	}
	del := &Delete{Table: TableReference{Name: "t"}, Where: where, ReturningClause: []Expression{ret}}
	delNoWhere := &Delete{Table: TableReference{Name: "t"}}
	upd := &Update{
		Table:           TableReference{Name: "t"},
		Updates:         []UpdateExpression{{Column: ident("a"), Value: ident("b")}, {Column: ident("c"), Value: ident("d")}},
		Where:           where,
		ReturningClause: []Expression{ret},
	}

	cases := []struct {
		name     string
		node     Node
		valueRes []Node // Children() on the stored value
		inPlace  []Node // exact pointers childrenOf must return
		shared   []int  // indices of pointer-typed children both paths share
	}{
		{"JoinClause", join, join.Children(), []Node{&join.Left, &join.Right, cond}, []int{2}},
		{"JoinClauseNoCondition", joinNoCond, joinNoCond.Children(), []Node{&joinNoCond.Left, &joinNoCond.Right}, nil},
		{"WindowFrame", frame, frame.Children(), []Node{&frame.Start, end}, []int{1}},
		{"WindowFrameNoEnd", frameNoEnd, frameNoEnd.Children(), []Node{&frameNoEnd.Start}, nil},
		{"MergeStatement", merge, merge.Children(), []Node{&merge.TargetTable, &merge.SourceTable, cond, when, output}, []int{2, 3, 4}},
		{"Insert", insert, insert.Children(), []Node{&insert.Table, insert.Columns[0], insert.Values[0][0], insert.Values[1][0], ret}, []int{1, 2, 3, 4}},
		{"Delete", del, del.Children(), []Node{&del.Table, where, ret}, []int{1, 2}},
		{"DeleteNoWhere", delNoWhere, delNoWhere.Children(), []Node{&delNoWhere.Table}, nil},
		{"Update", upd, upd.Children(), []Node{&upd.Table, &upd.Updates[0], &upd.Updates[1], where, ret}, []int{3, 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := childrenOf(c.node)
			if len(got) != len(c.inPlace) {
				t.Fatalf("childrenOf returned %d nodes, want %d", len(got), len(c.inPlace))
			}
			for i := range got {
				if got[i] != c.inPlace[i] {
					t.Fatalf("childrenOf[%d] = %T %p, want the stored field %p", i, got[i], got[i], c.inPlace[i])
				}
			}
			gs, vs := nodeSignature(got), nodeSignature(c.valueRes)
			if fmt.Sprint(gs) != fmt.Sprint(vs) {
				t.Fatalf("childrenOf and Children() disagree:\n in place: %v\n    value: %v", gs, vs)
			}
			for _, i := range c.shared {
				if c.valueRes[i] != got[i] {
					t.Fatalf("pointer child %d differs between Children() and childrenOf", i)
				}
			}
		})
	}
}

var childrenSink []Node

func TestChildren_AllocBudget(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("allocation counts are not meaningful under -race")
	}
	sel := &SelectStatement{
		Columns: []Expression{ident("a"), ident("b")},
		From:    []TableReference{{Name: "t1"}, {Name: "t2"}},
		Joins: []JoinClause{
			{Type: "INNER", Right: TableReference{Name: "t3"}, Condition: ident("c1")},
			{Type: "LEFT", Right: TableReference{Name: "t4"}, Condition: ident("c2")},
		},
		Where:   &BinaryExpression{Left: ident("a"), Operator: ">", Right: lit(1)},
		GroupBy: []Expression{ident("a")},
		Windows: []WindowSpec{{Name: "w", OrderBy: []OrderByExpression{obe("a")}}},
		OrderBy: []OrderByExpression{obe("a"), obe("b")},
	}
	fn := &FunctionCall{
		Name:        "F",
		Arguments:   []Expression{ident("x"), ident("y")},
		OrderBy:     []OrderByExpression{obe("y")},
		WithinGroup: []OrderByExpression{obe("z")},
	}
	ce := &CaseExpression{
		Value: ident("v"),
		WhenClauses: []WhenClause{
			{Condition: lit(1), Result: lit(10)},
			{Condition: lit(2), Result: lit(20)},
			{Condition: lit(3), Result: lit(30)},
		},
		ElseClause: lit(0),
	}
	ws := &WindowSpec{
		PartitionBy: []Expression{ident("g")},
		OrderBy:     []OrderByExpression{obe("o")},
		FrameClause: &WindowFrame{Type: "ROWS"},
	}
	ins := &InsertStatement{
		Columns: []Expression{ident("a"), ident("b")},
		Values: [][]Expression{
			{lit(1), lit(2)},
			{lit(3), lit(4)},
			{lit(5), lit(6)},
		},
		Returning: []Expression{ident("a")},
	}
	join := &JoinClause{Type: "INNER", Right: TableReference{Name: "r"}, Condition: ident("c")}
	frame := &WindowFrame{Type: "ROWS", End: &WindowFrameBound{Type: "CURRENT ROW"}}

	cases := []struct {
		name string
		fn   func() []Node
	}{
		{"SelectStatement", func() []Node { return childrenOf(sel) }},
		{"FunctionCall", func() []Node { return childrenOf(fn) }},
		{"CaseExpression", func() []Node { return childrenOf(ce) }},
		{"WindowSpec", func() []Node { return childrenOf(ws) }},
		{"InsertStatement", func() []Node { return childrenOf(ins) }},
		{"JoinClauseInPlace", func() []Node { return childrenOf(join) }},
		{"WindowFrameInPlace", func() []Node { return childrenOf(frame) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(100, func() { childrenSink = c.fn() })
			if allocs != 1 {
				t.Fatalf("got %v allocs per call, want exactly 1 (the result slice)", allocs)
			}
		})
	}
	childrenSink = nil
}
