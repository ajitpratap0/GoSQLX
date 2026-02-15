package parser

import (
	"fmt"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// Generate complex token sets for comprehensive testing
func generateLargeSelectTokens(numColumns int) []token.Token {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
	}

	// Add multiple columns
	for i := 0; i < numColumns; i++ {
		if i > 0 {
			tokens = append(tokens, token.Token{Type: models.TokenTypeComma, Literal: ","})
		}
		tokens = append(tokens, token.Token{Type: models.TokenTypeIdentifier, Literal: fmt.Sprintf("col%d", i)})
	}

	tokens = append(tokens, []token.Token{
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "large_table"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeTrue, Literal: "TRUE"},
		{Type: models.TokenTypeEOF, Literal: ""},
	}...)

	return tokens
}

func generateComplexJoinTokens(numJoins int) []token.Token {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "t1"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "id"},
	}

	// Add columns from joined tables
	for i := 0; i < numJoins; i++ {
		colTokens := []token.Token{
			{Type: models.TokenTypeComma, Literal: ","},
			{Type: models.TokenTypeIdentifier, Literal: fmt.Sprintf("t%d", i+2)},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "name"},
		}
		tokens = append(tokens, colTokens...)
	}

	// Add FROM clause
	tokens = append(tokens, []token.Token{
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "table1"},
		{Type: models.TokenTypeIdentifier, Literal: "t1"},
	}...)

	// Add multiple joins
	for i := 0; i < numJoins; i++ {
		joinTokens := []token.Token{
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
			{Type: models.TokenTypeIdentifier, Literal: fmt.Sprintf("table%d", i+2)},
			{Type: models.TokenTypeIdentifier, Literal: fmt.Sprintf("t%d", i+2)},
			{Type: models.TokenTypeOn, Literal: "ON"},
			{Type: models.TokenTypeIdentifier, Literal: "t1"},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeEq, Literal: "="},
			{Type: models.TokenTypeIdentifier, Literal: fmt.Sprintf("t%d", i+2)},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "ref_id"},
		}
		tokens = append(tokens, joinTokens...)
	}

	// Add EOF token
	tokens = append(tokens, token.Token{Type: models.TokenTypeEOF, Literal: ""})

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
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "u"},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeComma, Literal: ","},
			{Type: models.TokenTypeIdentifier, Literal: "o"},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "total"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeIdentifier, Literal: "u"},
			{Type: models.TokenTypeJoin, Literal: "JOIN"},
			{Type: models.TokenTypeIdentifier, Literal: "orders"},
			{Type: models.TokenTypeIdentifier, Literal: "o"},
			{Type: models.TokenTypeOn, Literal: "ON"},
			{Type: models.TokenTypeIdentifier, Literal: "u"},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeEq, Literal: "="},
			{Type: models.TokenTypeIdentifier, Literal: "o"},
			{Type: models.TokenTypePeriod, Literal: "."},
			{Type: models.TokenTypeIdentifier, Literal: "user_id"},
			{Type: models.TokenTypeEOF, Literal: ""},
		}
		benchmarkParserWithTokens(b, tokens)
	})

	b.Run("SimpleWhere", func(b *testing.B) {
		tokens := []token.Token{
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeWhere, Literal: "WHERE"},
			{Type: models.TokenTypeIdentifier, Literal: "active"},
			{Type: models.TokenTypeEq, Literal: "="},
			{Type: models.TokenTypeTrue, Literal: "TRUE"},
			{Type: models.TokenTypeEOF, Literal: ""},
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
					tree, err := parser.Parse(tokens)
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
				tree, err := parser.Parse(complexTokens)
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
				{Type: models.TokenTypeInsert, Literal: "INSERT"},
				{Type: models.TokenTypeInto, Literal: "INTO"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeValues, Literal: "VALUES"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeString, Literal: "John"},
				{Type: models.TokenTypeRParen, Literal: ")"},
				{Type: models.TokenTypeEOF, Literal: ""},
			},
		},
		{
			name: "UPDATE_Simple",
			tokens: []token.Token{
				{Type: models.TokenTypeUpdate, Literal: "UPDATE"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeSet, Literal: "SET"},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeTrue, Literal: "TRUE"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "id"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeEOF, Literal: ""},
			},
		},
		{
			name: "DELETE_Simple",
			tokens: []token.Token{
				{Type: models.TokenTypeDelete, Literal: "DELETE"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "active"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeFalse, Literal: "FALSE"},
				{Type: models.TokenTypeEOF, Literal: ""},
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
			{Type: models.TokenTypeInsert, Literal: "INSERT"},
			{Type: models.TokenTypeInto, Literal: "INTO"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeIdentifier, Literal: "name"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeValues, Literal: "VALUES"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeString, Literal: "Test"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeEOF, Literal: ""},
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
				tree, err := parser.Parse(tokens)
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
				tree, err := parser.Parse(tokens)
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
