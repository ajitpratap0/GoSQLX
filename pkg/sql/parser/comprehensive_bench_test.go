package parser

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// Generate complex token sets for comprehensive testing
func generateLargeSelectTokens(numColumns int) []token.Token {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
	}

	// Add multiple columns
	for i := 0; i < numColumns; i++ {
		if i > 0 {
			tokens = append(tokens, token.Token{Type: ",", Literal: ","})
		}
		tokens = append(tokens, token.Token{Type: "IDENT", Literal: fmt.Sprintf("col%d", i)})
	}

	tokens = append(tokens, []token.Token{
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "large_table"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "EOF", Literal: ""},
	}...)

	return tokens
}

func generateComplexJoinTokens(numJoins int) []token.Token {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "t1"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
	}

	// Add columns from joined tables
	for i := 0; i < numJoins; i++ {
		colTokens := []token.Token{
			{Type: ",", Literal: ","},
			{Type: "IDENT", Literal: fmt.Sprintf("t%d", i+2)},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "name"},
		}
		tokens = append(tokens, colTokens...)
	}

	// Add FROM clause
	tokens = append(tokens, []token.Token{
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "table1"},
		{Type: "IDENT", Literal: "t1"},
	}...)

	// Add multiple joins
	for i := 0; i < numJoins; i++ {
		joinTokens := []token.Token{
			{Type: "JOIN", Literal: "JOIN"},
			{Type: "IDENT", Literal: fmt.Sprintf("table%d", i+2)},
			{Type: "IDENT", Literal: fmt.Sprintf("t%d", i+2)},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "t1"},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "id"},
			{Type: "=", Literal: "="},
			{Type: "IDENT", Literal: fmt.Sprintf("t%d", i+2)},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "ref_id"},
		}
		tokens = append(tokens, joinTokens...)
	}

	// Add EOF token
	tokens = append(tokens, token.Token{Type: "EOF", Literal: ""})

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
		// Use existing complex SELECT tokens which include JOIN
		tokens := []token.Token{
			{Type: "SELECT", Literal: "SELECT"},
			{Type: "IDENT", Literal: "u"},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "id"},
			{Type: ",", Literal: ","},
			{Type: "IDENT", Literal: "o"},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "total"},
			{Type: "FROM", Literal: "FROM"},
			{Type: "IDENT", Literal: "users"},
			{Type: "IDENT", Literal: "u"},
			{Type: "JOIN", Literal: "JOIN"},
			{Type: "IDENT", Literal: "orders"},
			{Type: "IDENT", Literal: "o"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "u"},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "id"},
			{Type: "=", Literal: "="},
			{Type: "IDENT", Literal: "o"},
			{Type: ".", Literal: "."},
			{Type: "IDENT", Literal: "user_id"},
		}
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SimpleWhere", func(b *testing.B) {
		tokens := []token.Token{
			{Type: "SELECT", Literal: "SELECT"},
			{Type: "IDENT", Literal: "id"},
			{Type: "FROM", Literal: "FROM"},
			{Type: "IDENT", Literal: "users"},
			{Type: "WHERE", Literal: "WHERE"},
			{Type: "IDENT", Literal: "active"},
			{Type: "=", Literal: "="},
			{Type: "TRUE", Literal: "TRUE"},
		}
		benchmarkParserWithTokens(b, tokens)
	})
}

func benchmarkParserWithTokens(b *testing.B, tokens []token.Token) {
	parser := NewParser()
	defer parser.Release()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree, err := parser.Parse(tokens)
		if err != nil {
			b.Fatal(err)
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
					tree, err := parser.Parse(tokens)
					if err != nil {
						b.Fatal(err)
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
				tree, err := parser.Parse(complexTokens)
				if err != nil {
					b.Fatal(err)
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
						tree, err := parser.Parse(tokens)
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
					tree, err := parser.Parse(tokens)
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
		tokens []token.Token
	}{
		{
			name: "INSERT_Simple",
			tokens: []token.Token{
				{Type: "INSERT", Literal: "INSERT"},
				{Type: "INTO", Literal: "INTO"},
				{Type: "IDENT", Literal: "users"},
				{Type: "(", Literal: "("},
				{Type: "IDENT", Literal: "name"},
				{Type: ")", Literal: ")"},
				{Type: "VALUES", Literal: "VALUES"},
				{Type: "(", Literal: "("},
				{Type: "STRING", Literal: "John"},
				{Type: ")", Literal: ")"},
			},
		},
		{
			name: "UPDATE_Simple",
			tokens: []token.Token{
				{Type: "UPDATE", Literal: "UPDATE"},
				{Type: "IDENT", Literal: "users"},
				{Type: "SET", Literal: "SET"},
				{Type: "IDENT", Literal: "active"},
				{Type: "=", Literal: "="},
				{Type: "TRUE", Literal: "TRUE"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "id"},
				{Type: "=", Literal: "="},
				{Type: "INT", Literal: "1"},
			},
		},
		{
			name: "DELETE_Simple",
			tokens: []token.Token{
				{Type: "DELETE", Literal: "DELETE"},
				{Type: "FROM", Literal: "FROM"},
				{Type: "IDENT", Literal: "users"},
				{Type: "WHERE", Literal: "WHERE"},
				{Type: "IDENT", Literal: "active"},
				{Type: "=", Literal: "="},
				{Type: "FALSE", Literal: "FALSE"},
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
	statements := [][]token.Token{
		generateLargeSelectTokens(5),
		generateLargeSelectTokens(20),
		{
			{Type: "INSERT", Literal: "INSERT"},
			{Type: "INTO", Literal: "INTO"},
			{Type: "IDENT", Literal: "users"},
			{Type: "(", Literal: "("},
			{Type: "IDENT", Literal: "name"},
			{Type: ")", Literal: ")"},
			{Type: "VALUES", Literal: "VALUES"},
			{Type: "(", Literal: "("},
			{Type: "STRING", Literal: "Test"},
			{Type: ")", Literal: ")"},
		},
	}

	b.Run("MixedWorkload_Sequential", func(b *testing.B) {
		parser := NewParser()
		defer parser.Release()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokens := statements[i%len(statements)]
			tree, err := parser.Parse(tokens)
			if err != nil {
				b.Fatal(err)
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
				tree, err := parser.Parse(tokens)
				if err != nil {
					b.Fatal(err)
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
				tree, err := parser.Parse(tokens)
				if err != nil {
					b.Fatal(err)
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
