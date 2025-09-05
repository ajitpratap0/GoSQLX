package tokenizer

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Scalability and Concurrent Usage Benchmarks

func BenchmarkTokenizerConcurrency(b *testing.B) {
	testSQL := []byte(`SELECT u.id, u.name, COUNT(o.id) as orders FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = true GROUP BY u.id, u.name ORDER BY orders DESC LIMIT 100`)

	concurrencyLevels := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1000}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(b *testing.B) {
			b.ReportAllocs()
			b.SetParallelism(concurrency)

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					tokenizer := GetTokenizer()
					_, err := tokenizer.Tokenize(testSQL)
					if err != nil {
						panic(err)
					}
					PutTokenizer(tokenizer)
				}
			})
		})
	}
}

func BenchmarkTokenizerPoolContention(b *testing.B) {
	testSQL := []byte(`SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)`)

	b.Run("HighContention", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(1000) // High contention scenario

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	})

	b.Run("MediumContention", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(100)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	})

	b.Run("LowContention", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(10)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	})
}

func BenchmarkTokenizerMemoryScaling(b *testing.B) {
	// Test memory usage scaling with concurrent operations
	testSQL := []byte(`SELECT u.id, u.name, u.email, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name, u.email`)

	b.Run("MemoryUsageUnderLoad", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		b.ReportAllocs()
		b.SetParallelism(100)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
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

func BenchmarkTokenizerThroughputScaling(b *testing.B) {
	testSQL := []byte(`SELECT id, name FROM users WHERE active = true LIMIT 1000`)

	concurrencyLevels := []int{1, 10, 50, 100, 200}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Throughput_%d_goroutines", concurrency), func(b *testing.B) {
			b.ReportAllocs()

			start := time.Now()
			totalOps := int64(0)

			var wg sync.WaitGroup
			opsPerGoroutine := b.N / concurrency
			errCh := make(chan error, concurrency)

			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < opsPerGoroutine; j++ {
						tokenizer := GetTokenizer()
						_, err := tokenizer.Tokenize(testSQL)
						if err != nil {
							errCh <- err
							return
						}
						PutTokenizer(tokenizer)
						totalOps++
					}
				}()
			}

			wg.Wait()
			close(errCh)

			// Check for errors after goroutines complete
			if err := <-errCh; err != nil {
				panic(err)
			}
			duration := time.Since(start)

			// Calculate throughput metrics
			opsPerSecond := float64(totalOps) / duration.Seconds()
			b.ReportMetric(opsPerSecond, "ops/sec")
		})
	}
}

// Test sustained load over time
func BenchmarkTokenizerSustainedLoad(b *testing.B) {
	testSQL := []byte(`SELECT u.*, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id`)

	b.Run("SustainedLoad_1min", func(b *testing.B) {
		b.ReportAllocs()

		start := time.Now()
		endTime := start.Add(1 * time.Minute)
		totalOps := int64(0)

		var wg sync.WaitGroup
		concurrency := 50

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(endTime) {
					tokenizer := GetTokenizer()
					_, err := tokenizer.Tokenize(testSQL)
					if err != nil {
						panic(err)
					}
					PutTokenizer(tokenizer)
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

// Test pool efficiency under different usage patterns
func BenchmarkTokenizerPoolEfficiency(b *testing.B) {
	testSQL := []byte(`SELECT id FROM users WHERE name LIKE 'John%'`)

	b.Run("PoolReuse_Sequential", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		tokenizer := GetTokenizer()
		defer PutTokenizer(tokenizer)

		for i := 0; i < b.N; i++ {
			_, err := tokenizer.Tokenize(testSQL)
			if err != nil {
				panic(err)
			}
		}
	})

	b.Run("PoolReuse_GetPutCycle", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokenizer := GetTokenizer()
			_, err := tokenizer.Tokenize(testSQL)
			if err != nil {
				panic(err)
			}
			PutTokenizer(tokenizer)
		}
	})

	b.Run("PoolReuse_Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetParallelism(20)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
			}
		})
	})
}

// Memory pressure testing
func BenchmarkTokenizerMemoryPressure(b *testing.B) {
	// Generate large SQL to create memory pressure
	largeSQL := generateComplexSQL(50000) // 50KB SQL

	b.Run("MemoryPressure_Large_Concurrent", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		b.ReportAllocs()
		b.SetParallelism(50)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(largeSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
			}
		})

		runtime.GC()
		runtime.ReadMemStats(&m2)

		// Report memory pressure metrics
		b.ReportMetric(float64(m2.Sys-m1.Sys), "system_memory_bytes")
		b.ReportMetric(float64(m2.HeapInuse-m1.HeapInuse), "heap_inuse_bytes")
		b.ReportMetric(float64(m2.NumGC-m1.NumGC), "gc_cycles")
		b.ReportMetric(float64(m2.PauseTotalNs-m1.PauseTotalNs)/1e6, "gc_pause_ms")
	})
}

// Test GC pressure analysis
func BenchmarkTokenizerGCPressure(b *testing.B) {
	testSQL := []byte(`SELECT * FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true`)

	b.Run("GCPressure_Analysis", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Force some allocation/deallocation cycles
			for j := 0; j < 10; j++ {
				tokenizer := GetTokenizer()
				_, err := tokenizer.Tokenize(testSQL)
				if err != nil {
					panic(err)
				}
				PutTokenizer(tokenizer)
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
