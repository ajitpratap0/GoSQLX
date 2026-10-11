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

package ast_test

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Tests for the ReleaseAST release policy (issue #556): ReleaseAST and
// ReleaseStatements recycle only the node types the parser draws from pools
// (Tuple, ArrayConstructor, ArraySubscript and ArraySlice expressions here),
// while the exported Put* functions keep recycling every pooled node.

// drawnNodes and undrawnNodes hold the pointers collected from one tree.
type drawnNodes struct {
	tuples    []*ast.TupleExpression
	arrays    []*ast.ArrayConstructorExpression
	subs      []*ast.ArraySubscriptExpression
	slices    []*ast.ArraySliceExpression
	idents    []*ast.Identifier
	literals  []*ast.LiteralValue
	binaries  []*ast.BinaryExpression
	funcs     []*ast.FunctionCall
	selects   []*ast.SelectStatement
	drawnSeen int
}

func collectNodes(tree *ast.AST) *drawnNodes {
	n := &drawnNodes{}
	seen := map[ast.Node]bool{}
	ast.Inspect(tree, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		// JoinClause.Left is a non-owning copy of From[0]; dedupe so a
		// node reached through it is recorded once.
		if seen[node] {
			return true
		}
		seen[node] = true
		switch x := node.(type) {
		case *ast.TupleExpression:
			n.tuples = append(n.tuples, x)
			n.drawnSeen++
		case *ast.ArrayConstructorExpression:
			n.arrays = append(n.arrays, x)
			n.drawnSeen++
		case *ast.ArraySubscriptExpression:
			n.subs = append(n.subs, x)
			n.drawnSeen++
		case *ast.ArraySliceExpression:
			n.slices = append(n.slices, x)
			n.drawnSeen++
		case *ast.Identifier:
			n.idents = append(n.idents, x)
		case *ast.LiteralValue:
			n.literals = append(n.literals, x)
		case *ast.BinaryExpression:
			n.binaries = append(n.binaries, x)
		case *ast.FunctionCall:
			n.funcs = append(n.funcs, x)
		case *ast.SelectStatement:
			n.selects = append(n.selects, x)
		}
		return true
	})
	return n
}

// assertDrawnReset fails if any drawn node still carries fields.
func assertDrawnReset(t *testing.T, n *drawnNodes) {
	t.Helper()
	for _, x := range n.tuples {
		if len(x.Expressions) != 0 {
			t.Errorf("TupleExpression %p not reset: %d expressions", x, len(x.Expressions))
		}
	}
	for _, x := range n.arrays {
		if len(x.Elements) != 0 || x.Subquery != nil {
			t.Errorf("ArrayConstructorExpression %p not reset: %+v", x, *x)
		}
	}
	for _, x := range n.subs {
		if x.Array != nil || len(x.Indices) != 0 {
			t.Errorf("ArraySubscriptExpression %p not reset: %+v", x, *x)
		}
	}
	for _, x := range n.slices {
		if x.Array != nil || x.Start != nil || x.End != nil {
			t.Errorf("ArraySliceExpression %p not reset: %+v", x, *x)
		}
	}
}

func TestReleaseAST_DrawnNodesAreResetAndUndrawnAreNot(t *testing.T) {
	cases := []struct {
		name      string
		sql       string
		wantDrawn int
	}{
		{"ArrayAndTuple", drawnTypesSQL + " AND id > 0", 5},
		{"TupleInCTE", "WITH c AS (SELECT a, b FROM t WHERE (a, b) IN ((1, 2), (3, 4))) SELECT a + b FROM c", 3},
		{"ArrayInDerivedTable", "SELECT s.x FROM (SELECT ARRAY[1, 2] AS x, arr[1] AS y FROM t WHERE id = 1) s", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree(t, tc.sql)
			n := collectNodes(tree)
			if n.drawnSeen != tc.wantDrawn {
				t.Fatalf("fixture produced %d drawn nodes, want %d", n.drawnSeen, tc.wantDrawn)
			}
			if len(n.idents) == 0 || len(n.binaries) == 0 {
				t.Fatalf("fixture must contain Identifier and BinaryExpression nodes")
			}
			names := make([]string, len(n.idents))
			for i, id := range n.idents {
				names[i] = id.Name
			}
			ops := make([]string, len(n.binaries))
			for i, b := range n.binaries {
				ops[i] = b.Operator
			}

			ast.ReleaseAST(tree)

			assertDrawnReset(t, n)
			for i, id := range n.idents {
				if id.Name != names[i] {
					t.Errorf("Identifier %p was reset (%q -> %q); ReleaseAST must leave it to the GC", id, names[i], id.Name)
				}
			}
			for i, b := range n.binaries {
				if b.Operator != ops[i] {
					t.Errorf("BinaryExpression %p was reset (%q -> %q); ReleaseAST must leave it to the GC", b, ops[i], b.Operator)
				}
			}
		})
	}
}

// pointerSet records the pointers of a released tree.
type pointerSet map[any]bool

func addAll[T any](s pointerSet, xs []*T) {
	for _, x := range xs {
		s[x] = true
	}
}

// assertNeverHandedOut draws count objects with get, fails if any of them is
// in released, and returns them with put. A node ReleaseAST never Put can
// never come back from Get, so this is deterministic.
func assertNeverHandedOut[T any](t *testing.T, kind string, count int, released pointerSet, get func() *T, put func(*T)) {
	t.Helper()
	got := make([]*T, 0, count)
	for i := 0; i < count; i++ {
		x := get()
		if released[x] {
			t.Errorf("%s %p from the released tree came back from the pool: ReleaseAST Put a type the parser never draws", kind, x)
		}
		got = append(got, x)
	}
	for _, x := range got {
		put(x)
	}
}

func TestReleaseAST_DoesNotPoolUndrawnTypes(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tree := parseTree(t, mediumCTESQL)
	n := collectNodes(tree)
	if len(n.idents) == 0 || len(n.literals) == 0 || len(n.binaries) == 0 || len(n.funcs) == 0 || len(n.selects) < 2 {
		t.Fatalf("fixture too small: %d idents, %d literals, %d binaries, %d funcs, %d selects",
			len(n.idents), len(n.literals), len(n.binaries), len(n.funcs), len(n.selects))
	}
	released := pointerSet{}
	addAll(released, n.idents)
	addAll(released, n.literals)
	addAll(released, n.binaries)
	addAll(released, n.funcs)
	addAll(released, n.selects)

	ast.ReleaseAST(tree)

	assertNeverHandedOut(t, "Identifier", 2*len(n.idents), released, ast.GetIdentifier, ast.PutIdentifier)
	assertNeverHandedOut(t, "LiteralValue", 2*len(n.literals), released, ast.GetLiteralValue, ast.PutLiteralValue)
	assertNeverHandedOut(t, "BinaryExpression", 2*len(n.binaries), released, ast.GetBinaryExpression, ast.PutBinaryExpression)
	assertNeverHandedOut(t, "FunctionCall", 2*len(n.funcs), released, ast.GetFunctionCall, ast.PutFunctionCall)
	assertNeverHandedOut(t, "SelectStatement", 2*len(n.selects), released, ast.GetSelectStatement, ast.PutSelectStatement)
}

// handBuiltSelect builds SELECT f(arr[1]) WHERE (1, 2) IN ARRAY[3] with the
// drawn types taken from their pools and the other nodes as heap literals.
func handBuiltSelect() (*ast.SelectStatement, *ast.TupleExpression, *ast.ArrayConstructorExpression, *ast.ArraySubscriptExpression, *ast.BinaryExpression, *ast.FunctionCall) {
	tuple := ast.GetTupleExpression()
	l1, l2 := ast.GetLiteralValue(), ast.GetLiteralValue()
	l1.Value, l2.Value = 1, 2
	tuple.Expressions = append(tuple.Expressions, l1, l2)

	arr := ast.GetArrayConstructor()
	l3 := ast.GetLiteralValue()
	l3.Value = 3
	arr.Elements = append(arr.Elements, l3)

	sub := ast.GetArraySubscriptExpression()
	sub.Array = &ast.Identifier{Name: "arr"}
	sub.Indices = append(sub.Indices, &ast.LiteralValue{Value: 1})

	fn := &ast.FunctionCall{Name: "f", Arguments: []ast.Expression{sub}}
	where := &ast.BinaryExpression{Left: tuple, Operator: "IN", Right: arr}
	sel := &ast.SelectStatement{Columns: []ast.Expression{fn}, Where: where, TableName: "t"}
	return sel, tuple, arr, sub, where, fn
}

func TestReleaseAST_HandBuiltTree_PolicyMatrix(t *testing.T) {
	t.Run("ReleaseAST", func(t *testing.T) {
		sel, tuple, arr, sub, where, fn := handBuiltSelect()
		tree := ast.NewAST()
		tree.Statements = append(tree.Statements, sel)

		ast.ReleaseAST(tree)

		assertDrawnReset(t, &drawnNodes{
			tuples: []*ast.TupleExpression{tuple},
			arrays: []*ast.ArrayConstructorExpression{arr},
			subs:   []*ast.ArraySubscriptExpression{sub},
		})
		if where.Operator != "IN" || where.Left == nil || where.Right == nil {
			t.Errorf("BinaryExpression was reset by ReleaseAST: %+v", *where)
		}
		if fn.Name != "f" || len(fn.Arguments) != 1 {
			t.Errorf("FunctionCall was reset by ReleaseAST: %+v", *fn)
		}
		released := pointerSet{sel: true}
		assertNeverHandedOut(t, "SelectStatement", 4, released, ast.GetSelectStatement, ast.PutSelectStatement)
	})

	t.Run("PutSelectStatement", func(t *testing.T) {
		sel, tuple, arr, sub, where, fn := handBuiltSelect()

		ast.PutSelectStatement(sel)

		assertDrawnReset(t, &drawnNodes{
			tuples: []*ast.TupleExpression{tuple},
			arrays: []*ast.ArrayConstructorExpression{arr},
			subs:   []*ast.ArraySubscriptExpression{sub},
		})
		if where.Operator != "" || where.Left != nil || where.Right != nil {
			t.Errorf("PutSelectStatement must still reset every pooled node; BinaryExpression = %+v", *where)
		}
		if fn.Name != "" || len(fn.Arguments) != 0 {
			t.Errorf("PutSelectStatement must still reset every pooled node; FunctionCall = %+v", *fn)
		}
		if sel.Where != nil || len(sel.Columns) != 0 || sel.TableName != "" {
			t.Errorf("PutSelectStatement must reset the statement: %+v", *sel)
		}
	})

	t.Run("PutExpression", func(t *testing.T) {
		_, tuple, arr, sub, where, fn := handBuiltSelect()
		ast.PutExpression(where)
		ast.PutExpression(fn)
		assertDrawnReset(t, &drawnNodes{
			tuples: []*ast.TupleExpression{tuple},
			arrays: []*ast.ArrayConstructorExpression{arr},
			subs:   []*ast.ArraySubscriptExpression{sub},
		})
		if where.Operator != "" || fn.Name != "" {
			t.Errorf("PutExpression must still reset every pooled node: where=%+v fn=%+v", *where, *fn)
		}
	})
}

func TestReleaseAST_DrawnPoolNoContamination(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cases := []struct {
		name string
		a, b string
	}{
		{"TupleArity", "SELECT * FROM t WHERE (a, b) IN ((1, 2))", "SELECT * FROM t WHERE (x, y, z) IN ((7, 8, 9), (4, 5, 6))"},
		{"TupleShrink", "SELECT * FROM t WHERE (x, y, z) IN ((7, 8, 9), (4, 5, 6))", "SELECT * FROM t WHERE (a, b) IN ((1, 2))"},
		{"ArrayConstructor", "SELECT ARRAY[1, 2] FROM t", "SELECT ARRAY[9] FROM t"},
		{"SliceThenSubscript", "SELECT arr[1:2] FROM t", "SELECT arr[5] FROM t"},
		{"SubscriptThenSlice", "SELECT arr[5], m[1] FROM t", "SELECT arr[3:4] FROM t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := parseTree(t, tc.b)
			defer ast.ReleaseAST(want)
			wantDrawn := collectNodes(want).drawnSeen

			for i := 0; i < 3; i++ {
				ast.ReleaseAST(parseTree(t, tc.a))
				got := parseTree(t, tc.b)
				if d := collectNodes(got).drawnSeen; d != wantDrawn {
					t.Errorf("iteration %d: %d drawn nodes after reuse, want %d", i, d, wantDrawn)
				}
				if !reflect.DeepEqual(got.Statements, want.Statements) {
					t.Errorf("iteration %d: parse of %q after releasing %q differs from a fresh parse", i, tc.b, tc.a)
				}
				ast.ReleaseAST(got)
			}
		})
	}
}
