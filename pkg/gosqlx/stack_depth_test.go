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

package gosqlx_test

import (
	"errors"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func nestedParens(depth int) string {
	return "SELECT " + strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth) + " FROM t"
}

func nestedSubqueries(depth int) string {
	return strings.Repeat("SELECT * FROM (", depth) + "SELECT 1" + strings.Repeat(") AS t", depth)
}

// TestParseStackDepth guards the recursive-descent stack behaviour: nesting
// within the recursion limit must parse on a fresh goroutine, and nesting far
// beyond it must fail with an error rather than overflow the stack (a stack
// overflow is fatal and cannot be recovered). Larger stack frames in the hot
// parse functions make deep nesting cost more stack, so this test is the
// functional counterpart of scripts/perf/frames.sh.
func TestParseStackDepth(t *testing.T) {
	limit := parser.MaxRecursionDepth
	cases := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{"parens_shallow", nestedParens(10), false},
		{"parens_half_limit", nestedParens(limit / 2), false},
		{"parens_beyond_limit", nestedParens(limit * 20), true},
		{"subqueries_shallow", nestedSubqueries(5), false},
		{"subqueries_beyond_limit", nestedSubqueries(limit * 5), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type result struct {
				tree *ast.AST
				err  error
			}
			ch := make(chan result, 1)
			// A new goroutine starts with the smallest stack, so the parse has
			// to grow it, as in a goroutine-per-request server.
			go func() {
				tree, err := gosqlx.Parse(tc.sql)
				ch <- result{tree, err}
			}()
			r := <-ch
			if r.tree != nil {
				defer ast.ReleaseAST(r.tree)
			}
			if tc.wantErr {
				if r.err == nil {
					t.Fatal("expected an error for nesting beyond the recursion limit, got none")
				}
				if !errors.Is(r.err, gosqlx.ErrSyntax) {
					t.Fatalf("error %v does not wrap ErrSyntax", r.err)
				}
				return
			}
			if r.err != nil {
				t.Fatalf("nesting within the limit failed to parse: %v", r.err)
			}
		})
	}
}

// TestParseStackMemory10kGoroutines reports (never asserts) the stack memory
// held by 10,000 goroutines that have each parsed a statement and are parked,
// which is the resident-stack cost of a goroutine-per-request server. GC is
// disabled for the measurement so stack shrinking does not hide the growth.
func TestParseStackMemory10kGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10k goroutine measurement in -short mode")
	}
	const n = 10000
	queries := portableQueriesForTest(t)

	runtime.GC()
	prev := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prev)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	release := make(chan struct{})
	var started, done sync.WaitGroup
	started.Add(n)
	done.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		sql := queries[i%len(queries)]
		go func() {
			defer done.Done()
			tree, err := gosqlx.Parse(sql)
			if err != nil {
				errs <- err
			} else {
				ast.ReleaseAST(tree)
			}
			started.Done()
			<-release
		}()
	}
	started.Wait()
	runtime.ReadMemStats(&after)
	close(release)
	done.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("parse failed: %v", err)
	}

	delta := int64(after.StackInuse) - int64(before.StackInuse)
	t.Logf("stack in use: %d bytes across %d goroutines = %d bytes/goroutine (report only)",
		delta, n, delta/n)
}

func portableQueriesForTest(t *testing.T) []string {
	t.Helper()
	qs := portableQueries(t)
	out := make([]string, len(qs))
	for i, q := range qs {
		out[i] = q.SQL
	}
	return out
}
