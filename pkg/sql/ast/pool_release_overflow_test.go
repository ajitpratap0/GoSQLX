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
	"runtime"
	"sync/atomic"
	"testing"
)

// Tests for the work-queue overflow and depth-limit paths of the release walk
// under both release modes. None may use t.Parallel: they read the global
// leak counter and the shared pools.

var releaseModes = []struct {
	name string
	mode releaseMode
}{
	{"releaseAll", releaseAll},
	{"releaseDrawn", releaseDrawn},
}

func leakCount() uint64 { return atomic.LoadUint64(&poolLeakCount) }

// assertPoolsClean fails if a node handed out by the pools is not reset, or
// if the work-queue pool retains a queue larger than maxPooledWorkQueueCap.
func assertPoolsClean(t *testing.T) {
	t.Helper()
	const gets = 256
	gen := map[string]func() any{
		"Identifier":       func() any { return GetIdentifier() },
		"LiteralValue":     func() any { return GetLiteralValue() },
		"BinaryExpression": func() any { return GetBinaryExpression() },
		"FunctionCall":     func() any { return GetFunctionCall() },
		"InExpression":     func() any { return GetInExpression() },
		"Subquery":         func() any { return GetSubqueryExpression() },
		"Tuple":            func() any { return GetTupleExpression() },
		"ArrayConstructor": func() any { return GetArrayConstructor() },
		"ArraySubscript":   func() any { return GetArraySubscriptExpression() },
		"ArraySlice":       func() any { return GetArraySliceExpression() },
		"SelectStatement":  func() any { return GetSelectStatement() },
	}
	for name, get := range gen {
		for i := 0; i < gets; i++ {
			n := get()
			if !isReset(n) {
				t.Fatalf("pool contaminated: Get%s returned a dirty node: %+v", name, reflectElem(n))
			}
		}
	}

	// Drain a handful of queues; none may exceed the pooling cap.
	var held []*[]Expression
	for i := 0; i < 8; i++ {
		qp, ok := putExpressionWorkQueuePool.Get().(*[]Expression)
		if !ok {
			t.Fatal("work queue pool returned unexpected type")
		}
		if cap(*qp) > maxPooledWorkQueueCap {
			t.Errorf("work-queue pool retained a queue with cap %d, want <= %d", cap(*qp), maxPooledWorkQueueCap)
		}
		if len(*qp) != 0 {
			t.Errorf("work-queue pool retained a queue with len %d, want 0", len(*qp))
		}
		held = append(held, qp)
	}
	for _, qp := range held {
		putExpressionWorkQueuePool.Put(qp)
	}
}

func reflectElem(p any) any {
	return fmt.Sprintf("%+v", p)
}

// wideCall builds a FunctionCall with n literal arguments: n+1 nodes, all
// queued by the root in one go (the work queue grows to n).
func wideCall(n int) Expression {
	fc := GetFunctionCall()
	fc.Name = "f"
	for i := 0; i < n; i++ {
		fc.Arguments = append(fc.Arguments, GetLiteralValue())
	}
	return fc
}

// mixedChain builds a left-deep chain of `links` BinaryExpressions whose right
// child is a Tuple holding one literal: 4 nodes per link plus a leaf. It mixes
// types the parser draws (Tuple) with types it does not (Binary, Literal).
func mixedChain(links int) (root Expression, nodes int, tuples []*TupleExpression) {
	var cur Expression = GetLiteralValue()
	nodes = 1
	for i := 0; i < links; i++ {
		tup := GetTupleExpression()
		tup.Expressions = append(tup.Expressions, GetLiteralValue())
		be := GetBinaryExpression()
		be.Left, be.Operator, be.Right = cur, "+", tup
		cur = be
		tuples = append(tuples, tup)
		nodes += 3
	}
	return cur, nodes, tuples
}

func TestReleaseOverflow_WorkQueueBudget(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	type scenario struct {
		name  string
		build func() (root Expression, nodes int)
		// wantLeak returns the exact overflow-counter delta, or -1 when the
		// shape only guarantees 0 < delta < nodes.
		wantLeak func(nodes int) int
	}
	scenarios := []scenario{
		{"UnderBudget", func() (Expression, int) { return wideCall(100), 101 },
			func(int) int { return 0 }},
		{"ExactlyAtBudget", func() (Expression, int) { return wideCall(MaxWorkQueueSize - 1), MaxWorkQueueSize },
			func(int) int { return 0 }},
		{"OneOverBudget", func() (Expression, int) { return wideCall(MaxWorkQueueSize), MaxWorkQueueSize + 1 },
			func(nodes int) int { return nodes - MaxWorkQueueSize }},
		{"WideOverBudget", func() (Expression, int) { return wideCall(MaxWorkQueueSize + 5_000), MaxWorkQueueSize + 5_001 },
			func(nodes int) int { return nodes - MaxWorkQueueSize }},
		{"MixedChainOverBudget", func() (Expression, int) {
			root, nodes, _ := mixedChain(MaxWorkQueueSize/3 + 1_000)
			return root, nodes
		}, func(int) int { return -1 }},
	}

	for _, sc := range scenarios {
		for _, m := range releaseModes {
			t.Run(sc.name+"/"+m.name, func(t *testing.T) {
				root, nodes := sc.build()
				before := leakCount()
				releaseExpression(root, m.mode) // must not panic
				delta := int(leakCount() - before)

				switch want := sc.wantLeak(nodes); {
				case want >= 0 && delta != want:
					t.Errorf("leak counter moved by %d, want %d (%d nodes, budget %d)", delta, want, nodes, MaxWorkQueueSize)
				case want < 0 && (delta <= 0 || delta >= nodes):
					t.Errorf("leak counter moved by %d, want 0 < delta < %d", delta, nodes)
				}
				assertPoolsClean(t)
			})
		}
	}
}

// TestReleaseOverflow_DrawnNodesResetAcrossOverflow checks that every Tuple in
// a chain larger than the budget is reset, in both modes: the overflow drain
// must still reach pooled nodes that were queued when the budget ran out.
func TestReleaseOverflow_DrawnNodesResetAcrossOverflow(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, m := range releaseModes {
		t.Run(m.name, func(t *testing.T) {
			root, nodes, tuples := mixedChain(MaxWorkQueueSize/3 + 1_000)
			if nodes <= MaxWorkQueueSize {
				t.Fatalf("test bug: %d nodes does not exceed the budget", nodes)
			}
			releaseExpression(root, m.mode)
			for i, tup := range tuples {
				if !isReset(tup) {
					t.Fatalf("tuple %d of %d was not reset after overflow drain: %+v", i, len(tuples), *tup)
				}
			}
		})
	}
}

// singleChild builds a chain of n nodes alternating Tuple and Parenthesized
// expressions that ends in a literal. Every node has exactly one child, so
// when a pass runs out of budget exactly one node is left in the queue.
func singleChild(n int) (root Expression, tuples []*TupleExpression) {
	var cur Expression = GetLiteralValue()
	for p := n - 2; p >= 0; p-- { // p is the node's position from the root
		if p%2 == 0 {
			tup := GetTupleExpression()
			tup.Expressions = append(tup.Expressions, cur)
			tuples = append(tuples, tup)
			cur = tup
		} else {
			cur = &ParenthesizedExpression{Expr: cur}
		}
	}
	// Built leaf-first; return outermost first so tuples[k] is node 2k.
	for i, j := 0, len(tuples)-1; i < j; i, j = i+1, j-1 {
		tuples[i], tuples[j] = tuples[j], tuples[i]
	}
	return cur, tuples
}

// TestReleaseOverflow_DepthLimit drives the recursive overflow drain past
// MaxCleanupDepth. A real tree needs more than MaxCleanupDepth*MaxWorkQueueSize
// (10 million) nodes for that, so the test lowers the per-pass budget with
// putExpressionBounded; the logic under test is identical.
func TestReleaseOverflow_DepthLimit(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const budget = 64
	passes := MaxCleanupDepth + 1 // depths 0..MaxCleanupDepth

	cases := []struct {
		name     string
		nodes    int
		wantLeak int  // counter delta: one per pass that ran out of budget
		drained  bool // every node is reached
	}{
		{"JustWithinDepthLimit", passes*budget - 10, MaxCleanupDepth, true},
		{"ExactlyAtDepthLimit", passes * budget, MaxCleanupDepth, true},
		{"BeyondDepthLimit", passes*budget + 10, passes, false},
		{"FarBeyondDepthLimit", 3*passes*budget + 1, passes, false},
	}
	for _, tc := range cases {
		for _, m := range releaseModes {
			t.Run(tc.name+"/"+m.name, func(t *testing.T) {
				root, tuples := singleChild(tc.nodes)
				before := leakCount()
				putExpressionBounded(root, 0, m.mode, budget, MaxCleanupDepth) // must not panic
				delta := int(leakCount() - before)
				if delta != tc.wantLeak {
					t.Errorf("leak counter moved by %d, want %d", delta, tc.wantLeak)
				}

				// tuples[0] is the outermost tuple; the chain is processed in
				// order, so a prefix of it is reached when the walk truncates.
				reached := len(tuples)
				if !tc.drained {
					reached = 0
					for i := range tuples {
						if i*2 < passes*budget { // node index of tuple i is 2*i
							reached = i + 1
						}
					}
				}
				for i := 0; i < reached; i++ {
					if !isReset(tuples[i]) {
						t.Fatalf("tuple %d (node %d) should have been released: %+v", i, 2*i, *tuples[i])
					}
				}
				assertPoolsClean(t)
			})
		}
	}
}

// TestReleaseOverflow_NestedSubqueries nests SELECTs through subquery
// expressions far deeper than MaxCleanupDepth. Subquery nesting recurses
// through releaseStatement rather than the work queue, so it is not bounded
// by MaxCleanupDepth and must still release everything without touching the
// overflow counter.
func TestReleaseOverflow_NestedSubqueries(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	depth := 20 * MaxCleanupDepth
	build := func() (*SelectStatement, []*TupleExpression) {
		var tuples []*TupleExpression
		var inner *SelectStatement
		for i := 0; i < depth; i++ {
			sel := GetSelectStatement()
			tup := GetTupleExpression()
			tup.Expressions = append(tup.Expressions, GetLiteralValue())
			tuples = append(tuples, tup)
			sel.Columns = append(sel.Columns, tup)
			if inner != nil {
				sq := GetSubqueryExpression()
				sq.Subquery = inner
				sel.Where = sq
			}
			inner = sel
		}
		return inner, tuples
	}

	for _, m := range releaseModes {
		t.Run(m.name, func(t *testing.T) {
			root, tuples := build()
			before := leakCount()
			releaseStatement(root, m.mode) // must not panic
			if delta := leakCount() - before; delta != 0 {
				t.Errorf("leak counter moved by %d for nested subqueries, want 0", delta)
			}
			for i, tup := range tuples {
				if !isReset(tup) {
					t.Fatalf("tuple at nesting level %d not reset: %+v", i, *tup)
				}
			}
			assertPoolsClean(t)
		})
	}

	t.Run("ReleaseAST", func(t *testing.T) {
		root, tuples := build()
		tree := NewAST()
		tree.Statements = append(tree.Statements, root)
		ReleaseAST(tree)
		for i, tup := range tuples {
			if !isReset(tup) {
				t.Fatalf("tuple at nesting level %d not reset by ReleaseAST: %+v", i, *tup)
			}
		}
		assertPoolsClean(t)
	})
}
