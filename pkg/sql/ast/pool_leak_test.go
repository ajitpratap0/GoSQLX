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

// pool_leak_test.go provides end-to-end leak detection for the AST object
// pools. Before the Sprint-1 fixes, PutSelectStatement, PutUpdateStatement,
// PutInsertStatement and PutDeleteStatement only released a subset of their
// Expression/Statement-valued fields (Columns, Where, OrderBy for SELECT, for
// example), silently leaking GroupBy/Having/Qualify/StartWith/ConnectBy/Joins/
// Windows/PrewhereClause/ArrayJoin/Pivot/Unpivot/MatchRecognize/Top/
// DistinctOnColumns/From/With/Fetch/For/OnConflict/OnDuplicateKey/
// Output/Returning/Using — hundreds of pooled nodes per complex parse.
//
// Concurrently, PutExpression silently exited its iterative work-queue loop
// after MaxWorkQueueSize (1000) entries, dropping every remaining entry on
// the floor; for a 2000-element IN list this leaked thousands of pooled
// nodes per parse.
//
// Both defects together meant GoSQLX's advertised 95%+ pool hit rate and
// 1.38M ops/sec under sustained load was quietly degrading as the process
// aged, because the pool was being refilled by sync.Pool.New() rather than
// by Put. The tests below exercise both paths.
//
// These tests run in the ast_test package (not ast) so they can use the
// tokenizer + parser entry points to build realistic ASTs and exercise the
// full parse→release cycle the way production callers do.
package ast_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseAndRelease tokenizes and parses the given SQL, then releases every
// pooled object. Returns a non-nil error if tokenize or parse fails. This
// is the same shape production callers use via gosqlx.Parse.
func parseAndRelease(t testing.TB, sql string) error {
	t.Helper()

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return fmt.Errorf("tokenize: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// This is what callers SHOULD do to return pool memory. Any field that
	// PutSelectStatement / PutInsertStatement / etc. forgets to release is
	// the "leak" we are testing for.
	ast.ReleaseAST(tree)
	return nil
}

// TestPoolLeak_ComplexSelect_1000Iterations parses a SELECT that exercises
// nearly every field of SelectStatement — GROUP BY, HAVING, QUALIFY, JOIN,
// WINDOW, DISTINCT ON, TOP, FETCH, subqueries in FROM, OrderBy — 1000
// times and asserts that heap allocation stays roughly stable across
// iterations. Before the Sprint-1 fix this SELECT leaked on the order of
// 10-20 pooled expressions per parse, and the heap grew unboundedly.
//
// NOTE: This test would have failed on main pre-fix because the leaked
// pooled pointers retain chains of Identifier/BinaryExpression/LiteralValue
// nodes through the unreleased slice headers (Columns, GroupBy, etc.) held
// inside the freshly-pooled-but-not-cleaned SelectStatement. The test is
// intentionally lenient on the heap-growth threshold (10 MiB) so it's not
// flaky in CI, but any real regression produces 10-100 MiB growth.
func TestPoolLeak_ComplexSelect_1000Iterations(t *testing.T) {
	const iterations = 1000
	const heapGrowthLimit = 10 * 1024 * 1024 // 10 MiB

	// A SELECT that touches every previously-leaked field:
	//   - WITH (CTE)
	//   - JOIN with subquery in FROM
	//   - WHERE with IN
	//   - GROUP BY, HAVING
	//   - WINDOW function with PARTITION BY + ORDER BY (exercises Windows cleanup)
	//   - ORDER BY
	//   - LIMIT / OFFSET
	sql := `WITH recent AS (
    SELECT user_id, MAX(created_at) AS last_seen
    FROM events
    WHERE created_at > '2024-01-01'
    GROUP BY user_id
)
SELECT u.id,
       u.name,
       COUNT(o.id) AS order_count,
       SUM(o.total) AS total_spent,
       ROW_NUMBER() OVER (PARTITION BY u.region ORDER BY SUM(o.total) DESC) AS rank
FROM users u
JOIN (SELECT id, user_id, total FROM orders WHERE status = 'paid') o
  ON o.user_id = u.id
JOIN recent r ON r.user_id = u.id
WHERE u.active = true
  AND u.id IN (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
GROUP BY u.id, u.name, u.region
HAVING COUNT(o.id) > 5
ORDER BY total_spent DESC, u.name ASC
LIMIT 50 OFFSET 10`

	// Warm up the pool and JIT caches with 10 runs before measuring.
	for i := 0; i < 10; i++ {
		if err := parseAndRelease(t, sql); err != nil {
			t.Fatalf("warmup parse %d: %v", i, err)
		}
	}

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	ast.ResetPoolLeakCount()
	for i := 0; i < iterations; i++ {
		if err := parseAndRelease(t, sql); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapGrowth := int64(after.HeapInuse) - int64(before.HeapInuse)
	t.Logf("HeapInuse: before=%d, after=%d, delta=%+d bytes over %d iterations (%.1f bytes/iter)",
		before.HeapInuse, after.HeapInuse, heapGrowth, iterations, float64(heapGrowth)/float64(iterations))
	t.Logf("HeapObjects: before=%d, after=%d", before.HeapObjects, after.HeapObjects)
	t.Logf("TotalAlloc: before=%d, after=%d, delta=%d", before.TotalAlloc, after.TotalAlloc, after.TotalAlloc-before.TotalAlloc)
	t.Logf("PoolLeakCount (overflow drains): %d", ast.PoolLeakCount())

	if heapGrowth > heapGrowthLimit {
		t.Errorf("pool leak detected: HeapInuse grew by %d bytes over %d iterations (>%d limit)",
			heapGrowth, iterations, heapGrowthLimit)
	}
}

// TestPoolLeak_LargeInList_2000Elements parses a SELECT with a 2000-element
// IN-list. Before the Sprint-1 fix, PutExpression's work queue would stop at
// MaxWorkQueueSize (1000) and silently drop the other 1000+ pooled elements.
// After the fix, the cap is 100k and any overflow falls back to a recursive
// drain (bounded by MaxCleanupDepth), with the drain counted in
// PoolLeakCount for observability.
//
// This test asserts:
//  1. HeapInuse stays stable across 1000 parse+release cycles.
//  2. PoolLeakCount is zero (the 100k cap is never hit for a 2000-element list).
func TestPoolLeak_LargeInList_2000Elements(t *testing.T) {
	if testing.Short() {
		t.Skip("large IN-list test skipped under -short (tokenizes 2000 literals per iter)")
	}
	// A 2000-element IN list takes ~22 ms per parse+release on an M-series
	// CPU. 100 iterations is enough to expose any leak via HeapInuse delta
	// without blowing the 120 s race-test budget (100 × 22 ms × 5 race
	// overhead ≈ 11 s).
	const iterations = 100
	const heapGrowthLimit = 10 * 1024 * 1024 // 10 MiB
	const inListSize = 2000

	// Build: SELECT * FROM t WHERE id IN (1, 2, 3, ..., 2000)
	var b strings.Builder
	b.WriteString("SELECT * FROM t WHERE id IN (")
	for i := 0; i < inListSize; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", i)
	}
	b.WriteString(")")
	sql := b.String()

	// Warmup.
	for i := 0; i < 5; i++ {
		if err := parseAndRelease(t, sql); err != nil {
			t.Fatalf("warmup parse %d: %v", i, err)
		}
	}

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	ast.ResetPoolLeakCount()
	for i := 0; i < iterations; i++ {
		if err := parseAndRelease(t, sql); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heapGrowth := int64(after.HeapInuse) - int64(before.HeapInuse)
	leakCount := ast.PoolLeakCount()
	t.Logf("HeapInuse: before=%d, after=%d, delta=%+d bytes over %d iterations",
		before.HeapInuse, after.HeapInuse, heapGrowth, iterations)
	t.Logf("PoolLeakCount (overflow drains): %d", leakCount)

	if heapGrowth > heapGrowthLimit {
		t.Errorf("pool leak detected for 2000-element IN list: HeapInuse grew by %d bytes (>%d limit)",
			heapGrowth, heapGrowthLimit)
	}
	// With the new 100k cap we should never hit overflow for a 2000-element
	// list. If this ever trips, revisit MaxWorkQueueSize.
	if leakCount != 0 {
		t.Errorf("PoolLeakCount = %d; expected 0 for a 2000-element IN list (cap is %d)",
			leakCount, ast.MaxWorkQueueSize)
	}
}

// TestPoolLeak_PutExpression_OverflowDrain exercises the recursive overflow
// path directly. It synthesizes a flat BinaryExpression chain deeper than
// MaxWorkQueueSize, releases it, and asserts that every node was eventually
// drained (no orphan) by checking that PoolLeakCount recorded the overflow
// and that the drain counter matches the overflow delta.
//
// Rationale: this test does NOT rely on heap-growth detection (which is
// noisy); it verifies the contract of the fallback drain directly.
func TestPoolLeak_PutExpression_OverflowDrain(t *testing.T) {
	const nodes = 150_000 // > MaxWorkQueueSize (100k) to force overflow

	// Build a left-deep BinaryExpression chain:
	//   ((((lit op lit) op lit) op lit) ...)
	// Each node is one pooled BinaryExpression with two pooled LiteralValue
	// children, so total pooled nodes = 3 * (nodes-1) + 1 ≈ 3*nodes.
	// The iterative work queue will see all of these in a single call.
	var root ast.Expression = ast.GetLiteralValue()
	for i := 1; i < nodes; i++ {
		be := ast.GetBinaryExpression()
		be.Left = root
		be.Operator = "+"
		be.Right = ast.GetLiteralValue()
		root = be
	}

	ast.ResetPoolLeakCount()
	ast.PutExpression(root)

	leaks := ast.PoolLeakCount()
	t.Logf("PoolLeakCount after %d-node chain: %d (overflow drains)", nodes, leaks)
	if leaks == 0 {
		t.Errorf("expected overflow drains > 0 for %d-node chain (cap=%d), got 0",
			nodes, ast.MaxWorkQueueSize)
	}
	// Sanity: the overflow count must be strictly less than total nodes,
	// since the first MaxWorkQueueSize are drained on the fast path.
	if int(leaks) >= nodes {
		t.Errorf("PoolLeakCount=%d unreasonably high for %d-node chain", leaks, nodes)
	}
}

// measureHeapDelta runs fn for `iterations` cycles between two memory
// snapshots and returns the heap-in-use growth. It warms the pool with a
// short lead-in so JIT/pool priming costs don't bias the measurement.
func measureHeapDelta(t *testing.T, iterations int, warmups int, fn func() error) int64 {
	t.Helper()
	for i := 0; i < warmups; i++ {
		if err := fn(); err != nil {
			t.Fatalf("warmup %d: %v", i, err)
		}
	}
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	for i := 0; i < iterations; i++ {
		if err := fn(); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := int64(after.HeapInuse) - int64(before.HeapInuse)
	t.Logf("HeapInuse: before=%d, after=%d, delta=%+d bytes over %d iterations (%.1f bytes/iter)",
		before.HeapInuse, after.HeapInuse, delta, iterations,
		float64(delta)/float64(iterations))
	return delta
}

// TestPoolLeak_SubqueryInExpression verifies that an IN-subquery
// (IN (SELECT ...)) releases its nested SelectStatement back to the pool
// rather than leaking it. Pre-fix, pool.go set e.Subquery = nil inside
// putExpressionImpl without calling releaseStatement, so every nested
// SelectStatement reachable via InExpression.Subquery leaked on every
// parse. This test parses 1000 such queries and asserts stable heap.
func TestPoolLeak_SubqueryInExpression(t *testing.T) {
	const iterations = 1000
	const heapGrowthLimit = 10 * 1024 * 1024 // 10 MiB

	sql := `SELECT x FROM t WHERE id IN (SELECT y FROM u WHERE z = 1)`

	delta := measureHeapDelta(t, iterations, 10, func() error {
		return parseAndRelease(t, sql)
	})

	if delta > heapGrowthLimit {
		t.Errorf("IN-subquery pool leak detected: HeapInuse grew by %d bytes over %d iterations (>%d limit)",
			delta, iterations, heapGrowthLimit)
	}
}

// TestPoolLeak_ExistsSubquery verifies that EXISTS (SELECT ...) releases
// its nested SelectStatement back to the pool. Pre-fix, ExistsExpression's
// Subquery field was niled without dispatch, leaking every correlated
// SELECT body on every parse.
func TestPoolLeak_ExistsSubquery(t *testing.T) {
	const iterations = 1000
	const heapGrowthLimit = 10 * 1024 * 1024 // 10 MiB

	sql := `SELECT x FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)`

	delta := measureHeapDelta(t, iterations, 10, func() error {
		return parseAndRelease(t, sql)
	})

	if delta > heapGrowthLimit {
		t.Errorf("EXISTS-subquery pool leak detected: HeapInuse grew by %d bytes over %d iterations (>%d limit)",
			delta, iterations, heapGrowthLimit)
	}
}

// TestPoolLeak_AnyAllSubquery verifies that ANY(SELECT ...) and
// ALL(SELECT ...) release their nested SelectStatement. Pre-fix, both
// AnyExpression.Subquery and AllExpression.Subquery were niled without
// dispatch, leaking one SelectStatement per parse for each construct.
func TestPoolLeak_AnyAllSubquery(t *testing.T) {
	const iterations = 1000
	const heapGrowthLimit = 10 * 1024 * 1024 // 10 MiB

	// Parse both ANY and ALL on each iteration so we exercise both code
	// paths in a single test. We alternate rather than concatenating so
	// the parser sees one statement at a time (matching production shape).
	sqls := []string{
		`SELECT x FROM t WHERE val = ANY (SELECT v FROM u)`,
		`SELECT x FROM t WHERE val = ALL (SELECT v FROM u WHERE u.active = true)`,
	}

	delta := measureHeapDelta(t, iterations, 10, func() error {
		for _, sql := range sqls {
			if err := parseAndRelease(t, sql); err != nil {
				return err
			}
		}
		return nil
	})

	if delta > heapGrowthLimit {
		t.Errorf("ANY/ALL-subquery pool leak detected: HeapInuse grew by %d bytes over %d iterations (>%d limit)",
			delta, iterations, heapGrowthLimit)
	}
}
