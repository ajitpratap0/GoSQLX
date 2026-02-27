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

package parser

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Generate complex token sets for comprehensive testing

func generateLargeSelectTokens(numColumns int) []models.TokenWithSpan {
	tokens := []models.TokenWithSpan{
		tw(models.TokenTypeSelect, "SELECT"),
	}

	// Add multiple columns
	for i := 0; i < numColumns; i++ {
		if i > 0 {
			tokens = append(tokens, tw(models.TokenTypeComma, ","))
		}
		tokens = append(tokens, tw(models.TokenTypeIdentifier, fmt.Sprintf("col%d", i)))
	}

	tokens = append(tokens,
		tw(models.TokenTypeFrom, "FROM"),
		tw(models.TokenTypeIdentifier, "large_table"),
		tw(models.TokenTypeWhere, "WHERE"),
		tw(models.TokenTypeIdentifier, "active"),
		tw(models.TokenTypeEq, "="),
		tw(models.TokenTypeTrue, "TRUE"),
		tw(models.TokenTypeEOF, ""),
	)

	return tokens
}

func generateComplexJoinTokens(numJoins int) []models.TokenWithSpan {
	tokens := []models.TokenWithSpan{
		tw(models.TokenTypeSelect, "SELECT"),
		tw(models.TokenTypeIdentifier, "t1"),
		tw(models.TokenTypePeriod, "."),
		tw(models.TokenTypeIdentifier, "id"),
	}

	// Add columns from joined tables
	for i := 0; i < numJoins; i++ {
		tokens = append(tokens,
			tw(models.TokenTypeComma, ","),
			tw(models.TokenTypeIdentifier, fmt.Sprintf("t%d", i+2)),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "name"),
		)
	}

	// Add FROM clause
	tokens = append(tokens,
		tw(models.TokenTypeFrom, "FROM"),
		tw(models.TokenTypeIdentifier, "table1"),
		tw(models.TokenTypeIdentifier, "t1"),
	)

	// Add multiple joins
	for i := 0; i < numJoins; i++ {
		tokens = append(tokens,
			tw(models.TokenTypeJoin, "JOIN"),
			tw(models.TokenTypeIdentifier, fmt.Sprintf("table%d", i+2)),
			tw(models.TokenTypeIdentifier, fmt.Sprintf("t%d", i+2)),
			tw(models.TokenTypeOn, "ON"),
			tw(models.TokenTypeIdentifier, "t1"),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "id"),
			tw(models.TokenTypeEq, "="),
			tw(models.TokenTypeIdentifier, fmt.Sprintf("t%d", i+2)),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "ref_id"),
		)
	}

	// Add EOF token
	tokens = append(tokens, tw(models.TokenTypeEOF, ""))

	return tokens
}

// Comprehensive Parser Performance Benchmarks

func BenchmarkParserComplexity(b *testing.B) {
	b.Run("SimpleSelect_10_Columns", func(b *testing.B) {
		tokens := generateLargeSelectTokens(10)
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SimpleSelect_100_Columns", func(b *testing.B) {
		tokens := generateLargeSelectTokens(100)
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SimpleSelect_1000_Columns", func(b *testing.B) {
		tokens := generateLargeSelectTokens(1000)
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SingleJoin", func(b *testing.B) {
		tokens := []models.TokenWithSpan{
			tw(models.TokenTypeSelect, "SELECT"),
			tw(models.TokenTypeIdentifier, "u"),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "id"),
			tw(models.TokenTypeComma, ","),
			tw(models.TokenTypeIdentifier, "o"),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "total"),
			tw(models.TokenTypeFrom, "FROM"),
			tw(models.TokenTypeIdentifier, "users"),
			tw(models.TokenTypeIdentifier, "u"),
			tw(models.TokenTypeJoin, "JOIN"),
			tw(models.TokenTypeIdentifier, "orders"),
			tw(models.TokenTypeIdentifier, "o"),
			tw(models.TokenTypeOn, "ON"),
			tw(models.TokenTypeIdentifier, "u"),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "id"),
			tw(models.TokenTypeEq, "="),
			tw(models.TokenTypeIdentifier, "o"),
			tw(models.TokenTypePeriod, "."),
			tw(models.TokenTypeIdentifier, "user_id"),
			tw(models.TokenTypeEOF, ""),
		}
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SimpleWhere", func(b *testing.B) {
		tokens := []models.TokenWithSpan{
			tw(models.TokenTypeSelect, "SELECT"),
			tw(models.TokenTypeIdentifier, "id"),
			tw(models.TokenTypeFrom, "FROM"),
			tw(models.TokenTypeIdentifier, "users"),
			tw(models.TokenTypeWhere, "WHERE"),
			tw(models.TokenTypeIdentifier, "active"),
			tw(models.TokenTypeEq, "="),
			tw(models.TokenTypeTrue, "TRUE"),
			tw(models.TokenTypeEOF, ""),
		}
		benchmarkParserWithTokens(b, tokens)
	})
}

func benchmarkParserWithTokens(b *testing.B, tokens []models.TokenWithSpan) {
	b.Helper()
	parser := NewParser()
	defer parser.Release()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			panic(err)
		}
		if tree == nil {
			b.Fatal("expected non-nil AST")
		}
	}
}

func BenchmarkParserConcurrency(b *testing.B) {
	tokens := generateLargeSelectTokens(50)

	concurrencyLevels := []int{1, 2, 4, 8, 16, 32, 64, 128}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(b *testing.B) {
			b.ReportAllocs()
			b.SetParallelism(concurrency)

			b.RunParallel(func(pb *testing.PB) {
				parser := NewParser()
				defer parser.Release()

				for pb.Next() {
					tree, err := parser.ParseFromModelTokens(tokens)
					if err != nil {
						panic(err)
					}
					if tree == nil {
						b.Fatal("expected non-nil AST")
					}
				}
			})
		})
	}
}

func BenchmarkParserMemoryScaling(b *testing.B) {
	complexTokens := generateComplexJoinTokens(50)

	b.Run("MemoryUsageUnderLoad", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		b.ReportAllocs()
		b.SetParallelism(50)

		b.RunParallel(func(pb *testing.PB) {
			parser := NewParser()
			defer parser.Release()

			for pb.Next() {
				tree, err := parser.ParseFromModelTokens(complexTokens)
				if err != nil {
					panic(err)
				}
				if tree == nil {
					b.Fatal("expected non-nil AST")
				}
			}
		})

		runtime.GC()
		runtime.ReadMemStats(&m2)

		// Report memory metrics
		b.ReportMetric(float64(m2.Alloc-m1.Alloc), "bytes_allocated")
		b.ReportMetric(float64(m2.TotalAlloc-m1.TotalAlloc), "total_bytes_allocated")
		b.ReportMetric(float64(m2.NumGC-m1.NumGC), "gc_cycles")
	})
}

func BenchmarkParserThroughput(b *testing.B) {
	tokens := generateLargeSelectTokens(20)

	concurrencyLevels := []int{1, 10, 50, 100}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Throughput_%d_goroutines", concurrency), func(b *testing.B) {
			b.ReportAllocs()

			start := time.Now()
			totalOps := int64(0)

			var wg sync.WaitGroup
			opsPerGoroutine := b.N / concurrency

			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					parser := NewParser()
					defer parser.Release()

					for j := 0; j < opsPerGoroutine; j++ {
						tree, err := parser.ParseFromModelTokens(tokens)
						if err != nil {
							panic(err)
						}
						if tree == nil {
							panic("expected non-nil AST")
						}
						totalOps++
					}
				}()
			}

			wg.Wait()
			duration := time.Since(start)

			// Calculate throughput metrics
			opsPerSecond := float64(totalOps) / duration.Seconds()
			b.ReportMetric(opsPerSecond, "ops/sec")
		})
	}
}

func BenchmarkParserSustainedLoad(b *testing.B) {
	tokens := generateLargeSelectTokens(30)

	b.Run("SustainedLoad_30sec", func(b *testing.B) {
		b.ReportAllocs()

		start := time.Now()
		endTime := start.Add(30 * time.Second)
		totalOps := int64(0)

		var wg sync.WaitGroup
		concurrency := 25

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				parser := NewParser()
				defer parser.Release()

				for time.Now().Before(endTime) {
					tree, err := parser.ParseFromModelTokens(tokens)
					if err != nil {
						panic(err)
					}
					if tree == nil {
						panic("expected non-nil AST")
					}
					totalOps++
				}
			}()
		}

		wg.Wait()
		actualDuration := time.Since(start)

		// Report sustained load metrics
		opsPerSecond := float64(totalOps) / actualDuration.Seconds()
		b.ReportMetric(opsPerSecond, "sustained_ops/sec")
		b.ReportMetric(float64(totalOps), "total_operations")
	})
}

func BenchmarkParserStatementTypes(b *testing.B) {
	// Test different statement types for performance comparison
	testCases := []struct {
		name   string
		tokens []models.TokenWithSpan
	}{
		{
			name: "INSERT_Simple",
			tokens: []models.TokenWithSpan{
				tw(models.TokenTypeInsert, "INSERT"),
				tw(models.TokenTypeInto, "INTO"),
				tw(models.TokenTypeIdentifier, "users"),
				tw(models.TokenTypeLParen, "("),
				tw(models.TokenTypeIdentifier, "name"),
				tw(models.TokenTypeRParen, ")"),
				tw(models.TokenTypeValues, "VALUES"),
				tw(models.TokenTypeLParen, "("),
				tw(models.TokenTypeString, "John"),
				tw(models.TokenTypeRParen, ")"),
				tw(models.TokenTypeEOF, ""),
			},
		},
		{
			name: "UPDATE_Simple",
			tokens: []models.TokenWithSpan{
				tw(models.TokenTypeUpdate, "UPDATE"),
				tw(models.TokenTypeIdentifier, "users"),
				tw(models.TokenTypeSet, "SET"),
				tw(models.TokenTypeIdentifier, "active"),
				tw(models.TokenTypeEq, "="),
				tw(models.TokenTypeTrue, "TRUE"),
				tw(models.TokenTypeWhere, "WHERE"),
				tw(models.TokenTypeIdentifier, "id"),
				tw(models.TokenTypeEq, "="),
				tw(models.TokenTypeNumber, "1"),
				tw(models.TokenTypeEOF, ""),
			},
		},
		{
			name: "DELETE_Simple",
			tokens: []models.TokenWithSpan{
				tw(models.TokenTypeDelete, "DELETE"),
				tw(models.TokenTypeFrom, "FROM"),
				tw(models.TokenTypeIdentifier, "users"),
				tw(models.TokenTypeWhere, "WHERE"),
				tw(models.TokenTypeIdentifier, "active"),
				tw(models.TokenTypeEq, "="),
				tw(models.TokenTypeFalse, "FALSE"),
				tw(models.TokenTypeEOF, ""),
			},
		},
		{
			name:   "SELECT_Complex",
			tokens: generateComplexJoinTokens(10),
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkParserWithTokens(b, tc.tokens)
		})
	}
}

func BenchmarkParserMixedWorkload(b *testing.B) {
	// Simulate realistic mixed workload
	statements := [][]models.TokenWithSpan{
		generateLargeSelectTokens(5),
		generateLargeSelectTokens(20),
		{
			tw(models.TokenTypeInsert, "INSERT"),
			tw(models.TokenTypeInto, "INTO"),
			tw(models.TokenTypeIdentifier, "users"),
			tw(models.TokenTypeLParen, "("),
			tw(models.TokenTypeIdentifier, "name"),
			tw(models.TokenTypeRParen, ")"),
			tw(models.TokenTypeValues, "VALUES"),
			tw(models.TokenTypeLParen, "("),
			tw(models.TokenTypeString, "Test"),
			tw(models.TokenTypeRParen, ")"),
			tw(models.TokenTypeEOF, ""),
		},
	}

	b.Run("MixedWorkload_Sequential", func(b *testing.B) {
		parser := NewParser()
		defer parser.Release()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokens := statements[i%len(statements)]
			tree, err := parser.ParseFromModelTokens(tokens)
			if err != nil {
				panic(err)
			}
			if tree == nil {
				b.Fatal("expected non-nil AST")
			}
		}
	})

	b.Run("MixedWorkload_Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(20)

		b.RunParallel(func(pb *testing.PB) {
			parser := NewParser()
			defer parser.Release()

			i := 0
			for pb.Next() {
				tokens := statements[i%len(statements)]
				tree, err := parser.ParseFromModelTokens(tokens)
				if err != nil {
					panic(err)
				}
				if tree == nil {
					b.Fatal("expected non-nil AST")
				}
				i++
			}
		})
	})
}

func BenchmarkParserGCPressure(b *testing.B) {
	tokens := generateComplexJoinTokens(20)

	b.Run("GCPressure_Analysis", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Force allocation/deallocation cycles
			for j := 0; j < 5; j++ {
				parser := NewParser()
				tree, err := parser.ParseFromModelTokens(tokens)
				if err != nil {
					panic(err)
				}
				if tree == nil {
					b.Fatal("expected non-nil AST")
				}
				parser.Release()
			}
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)

		// Calculate GC efficiency metrics
		totalAllocs := m2.TotalAlloc - m1.TotalAlloc
		gcCycles := m2.NumGC - m1.NumGC
		avgAllocPerGC := float64(totalAllocs) / float64(gcCycles)

		b.ReportMetric(float64(gcCycles), "gc_cycles")
		b.ReportMetric(avgAllocPerGC, "avg_alloc_per_gc")
		b.ReportMetric(float64(m2.PauseTotalNs-m1.PauseTotalNs)/1e6, "total_gc_pause_ms")
	})
}
