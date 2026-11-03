// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func scanWalkerTestTree(t *testing.T, sql string, dialect keywords.SQLDialect) *ast.AST {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	return tree
}

func scanWalkerChain(terms int) string {
	return "SELECT * FROM t WHERE " + strings.Repeat("1=1 OR ", terms-1) + "1=1"
}

func TestScanWalkerReleaseInvariant(t *testing.T) {
	cases := []struct{ name, sql string }{
		{"join", "SELECT * FROM url('http://x') AS a JOIN s3('y') AS b ON a.id = b.id"},
		{"nested set operation", "SELECT a FROM t UNION (SELECT b FROM u UNION SELECT NULL, NULL FROM information_schema.tables)"},
		{"deep chain", scanWalkerChain(5000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := scanWalkerTestTree(t, tc.sql, keywords.DialectClickHouse)
			s := NewScanner()
			r := &ScanResult{Findings: make([]Finding, 0)}
			w := acquireScanWalker(s, r)
			if err := ast.Walk(w, tree); err != nil {
				t.Fatal(err)
			}
			// Inspect before release so reslicing in release cannot hide an
			// unbalanced walk, and inspect capacity so stale nodes cannot hide.
			if len(w.ancestors) != 0 {
				t.Errorf("ancestors length after walk = %d, want 0", len(w.ancestors))
			}
			for i, node := range w.ancestors[:cap(w.ancestors)] {
				if node != nil {
					t.Errorf("ancestors[%d] retains %T after walk", i, node)
					break
				}
			}
			w.release()
			if w.s != nil || w.result != nil {
				t.Error("release retained scanner or result")
			}
		})
	}
}

func TestScanWalkerDropsOversized(t *testing.T) {
	for _, tc := range []struct {
		terms int
		want  bool
	}{{5000, false}, {16, true}} {
		t.Run(fmt.Sprint(tc.terms), func(t *testing.T) {
			tree := scanWalkerTestTree(t, scanWalkerChain(tc.terms), keywords.DialectPostgreSQL)
			w := acquireScanWalker(NewScanner(), &ScanResult{})
			if err := ast.Walk(w, tree); err != nil {
				t.Fatal(err)
			}
			capacity := cap(w.ancestors)
			if got := w.release(); got != tc.want {
				t.Errorf("release() = %t for capacity %d, want %t", got, capacity, tc.want)
			}
		})
	}
}

func TestScanWalkerAcquireState(t *testing.T) {
	s, r := NewScanner(), &ScanResult{}
	w := acquireScanWalker(s, r)
	if w.s != s || w.result != r || len(w.ancestors) != 0 {
		t.Errorf("acquire did not reset state: scanner=%p result=%p len=%d", w.s, w.result, len(w.ancestors))
	}
	w.release()
}

func TestScanWalkerResetClearsDirtyState(t *testing.T) {
	w := &scanWalker{
		s: NewScanner(), result: &ScanResult{},
		ancestors: []ast.Node{&ast.SetOperation{}, &ast.JoinClause{}, &ast.SetOperation{}},
	}
	s, r := NewScanner(), &ScanResult{}
	w.reset(s, r)
	if len(w.ancestors) != 0 || w.s != s || w.result != r {
		t.Errorf("reset did not replace state: len=%d scanner=%p result=%p", len(w.ancestors), w.s, w.result)
	}
	// Deliberately dirty backing storage is not put into the shared pool.
}

type noopVisitor struct{}

func (*noopVisitor) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	return noopV, nil
}

var noopV = &noopVisitor{}

func TestScanAllocsOverWalk(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation changes sync.Pool allocation counts")
	}
	s := NewScanner()
	for _, sql := range []string{
		"SELECT a, b FROM t JOIN u ON t.id = u.id WHERE x > 1 ORDER BY a",
		"SELECT COUNT(*) FROM o GROUP BY s HAVING COUNT(*) > 2",
		"UPDATE t SET a = 1 WHERE id = 2",
	} {
		t.Run(sql, func(t *testing.T) {
			tree := scanWalkerTestTree(t, sql, keywords.DialectPostgreSQL)
			if r := s.Scan(tree); !r.IsClean() {
				t.Fatalf("allocation input has findings: %+v", r.Findings)
			}
			scanAllocs := testing.AllocsPerRun(200, func() { _ = s.Scan(tree) })
			walkAllocs := testing.AllocsPerRun(200, func() { _ = ast.Walk(noopV, tree) })
			if delta := scanAllocs - walkAllocs; delta > 1 {
				t.Errorf("Scan allocs %.0f - Walk allocs %.0f = %.0f, want <= 1", scanAllocs, walkAllocs, delta)
			}
		})
	}
}

func TestScanConcurrentPooledWalker(t *testing.T) {
	s := NewScanner()
	var trees []*ast.AST
	var names []string
	// Under -race the instrumented walk is several times slower and CI shards
	// have a fixed time budget, so the race run uses a 100-term chain, fewer
	// workers/iterations and fewer corpus statements. The 5000-deep tree is
	// still exercised concurrently in the non-race run.
	workers, iterations, corpusN := 16, 50, 50
	if raceEnabled {
		workers, iterations, corpusN = 4, 8, 10
	}
	for _, tc := range scanWalkerTargetCases() {
		if raceEnabled && tc.name == "deep chain" {
			tc.sql = "SELECT * FROM t WHERE " + strings.Repeat("1=1 OR ", 99) + "1=1"
		}
		trees = append(trees, scanWalkerTestTree(t, tc.sql, tc.dialect))
		names = append(names, tc.name)
	}
	unsupported := &ast.AST{Statements: []ast.Statement{
		&ast.UnsupportedStatement{Kind: "unsupported", RawSQL: "SELECT * FROM t WHERE 1=1"},
	}}
	t.Cleanup(func() { ast.ReleaseAST(unsupported) })
	trees = append(trees, unsupported)
	names = append(names, "unsupported text")
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	statements := set.RealWorld("postgresql")
	if len(statements) < corpusN {
		t.Fatalf("PostgreSQL corpus has %d statements, want at least %d", len(statements), corpusN)
	}
	for _, st := range statements[:corpusN] {
		tree, err := gosqlx.ParseWithDialect(st.SQL, keywords.DialectPostgreSQL)
		if err != nil {
			t.Logf("skip real-world parse error %s: %v", st.Key(), err)
			continue
		}
		t.Cleanup(func() { ast.ReleaseAST(tree) })
		trees = append(trees, tree)
		names = append(names, st.Key())
	}
	serial := make([]*ScanResult, len(trees))
	for i, tree := range trees {
		serial[i] = s.Scan(tree)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				for i, tree := range trees {
					if got := s.Scan(tree); !reflect.DeepEqual(got, serial[i]) {
						t.Errorf("iteration %d, %s: concurrent Scan differs from serial\ngot: %#v\nwant: %#v", iteration, names[i], got, serial[i])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
