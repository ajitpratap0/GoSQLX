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
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Server-shape benchmarks (PLAN W0-04). A request-per-goroutine server pays
// for stack growth on every request (Fresh), shares the named pools across
// cores (Parallel, PoolGetPut) and often runs with metrics switched on
// (the *Metrics variants). Every shape releases the AST, as a server must.
//
// Parallel benchmarks scale with the -cpu flag: run with -cpu 1,4,10.

func portableQueries(b testing.TB) []benchcorpus.Query {
	b.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		b.Fatalf("load benchmark corpus: %v", err)
	}
	return set.Portable()
}

func parseAndRelease(sql string) error {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return err
	}
	ast.ReleaseAST(tree)
	return nil
}

// BenchmarkParseE2EMetrics is the single-goroutine end-to-end parse with
// metrics collection enabled; compare with the same query without it to see
// the cost of the advertised production-monitoring mode.
func BenchmarkParseE2EMetrics(b *testing.B) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			metrics.Enable()
			b.Cleanup(metrics.Disable)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := parseAndRelease(q.SQL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParseFresh parses on a new goroutine for every operation, so each
// parse starts on a fresh small stack and pays for stack growth, as in a
// goroutine-per-request server.
func BenchmarkParseFresh(b *testing.B) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			b.ReportAllocs()
			var wg sync.WaitGroup
			var errOnce sync.Once
			var firstErr error
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := parseAndRelease(q.SQL); err != nil {
						errOnce.Do(func() { firstErr = err })
					}
				}()
				wg.Wait()
			}
			b.StopTimer()
			if firstErr != nil {
				b.Fatal(firstErr)
			}
		})
	}
}

func benchParseParallel(b *testing.B, withMetrics bool) {
	for _, q := range portableQueries(b) {
		b.Run(q.ID, func(b *testing.B) {
			if withMetrics {
				metrics.Enable()
				b.Cleanup(metrics.Disable)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := parseAndRelease(q.SQL); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

// BenchmarkParseParallel measures throughput with every core parsing at once
// (b.RunParallel), exposing contention on the shared pools and counters.
func BenchmarkParseParallel(b *testing.B) { benchParseParallel(b, false) }

// BenchmarkParseParallelMetrics is BenchmarkParseParallel with metrics enabled.
func BenchmarkParseParallelMetrics(b *testing.B) { benchParseParallel(b, true) }

// BenchmarkPoolGetPut isolates the get/put cost of the pooled objects a
// Parse touches (tokenizer, parser, AST), serially and across all cores.
func BenchmarkPoolGetPut(b *testing.B) {
	cycle := func() {
		tkz := tokenizer.GetTokenizer()
		p := parser.GetParser()
		a := ast.NewAST()
		ast.ReleaseAST(a)
		parser.PutParser(p)
		tokenizer.PutTokenizer(tkz)
	}
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cycle()
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				cycle()
			}
		})
	})
}
