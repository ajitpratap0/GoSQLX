package tokenizer

import (
	"runtime"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestMemoryLeakDetection checks for memory leaks in tokenizer and AST operations
func TestMemoryLeakDetection(t *testing.T) {
	// Force garbage collection to get baseline
	runtime.GC()
	runtime.GC() // Call twice to ensure full collection
	time.Sleep(10 * time.Millisecond)

	// Get initial memory stats
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	t.Logf("Initial memory stats:")
	t.Logf("  Alloc: %d bytes", m1.Alloc)
	t.Logf("  TotalAlloc: %d bytes", m1.TotalAlloc)
	t.Logf("  Sys: %d bytes", m1.Sys)
	t.Logf("  NumGC: %d", m1.NumGC)

	// Perform a large number of operations that should not leak memory
	const iterations = 10000
	const testQuery = "SELECT id, name, email FROM users WHERE age > 21 AND status = 'active' ORDER BY name"

	t.Logf("Running %d iterations of tokenizer operations...", iterations)

	for i := 0; i < iterations; i++ {
		// Get tokenizer from pool
		tkz := GetTokenizer()

		// Tokenize query
		tokens, err := tkz.Tokenize([]byte(testQuery))
		if err != nil {
			t.Fatalf("Tokenization failed at iteration %d: %v", i, err)
		}

		// Verify we got tokens
		if len(tokens) == 0 {
			t.Fatalf("No tokens produced at iteration %d", i)
		}

		// Return tokenizer to pool (this should prevent leaks)
		PutTokenizer(tkz)

		// Also test AST operations
		astObj := ast.NewAST()
		ast.ReleaseAST(astObj)

		// Periodically force GC during the test
		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	// Force garbage collection after operations
	runtime.GC()
	runtime.GC() // Call twice to ensure full collection
	time.Sleep(10 * time.Millisecond)

	// Get final memory stats
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	t.Logf("Final memory stats:")
	t.Logf("  Alloc: %d bytes", m2.Alloc)
	t.Logf("  TotalAlloc: %d bytes", m2.TotalAlloc)
	t.Logf("  Sys: %d bytes", m2.Sys)
	t.Logf("  NumGC: %d", m2.NumGC)

	// Calculate memory differences
	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	sysDiff := int64(m2.Sys) - int64(m1.Sys)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)

	t.Logf("Memory differences:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  Sys diff: %d bytes", sysDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", float64(totalAllocDiff)/float64(iterations))

	// Memory leak detection thresholds
	const maxAllocIncrease = 1024 * 1024    // 1MB max increase in current allocation
	const maxBytesPerOp = 5000              // 5KB max per operation (tokenization includes string allocations)
	const maxSysIncrease = 10 * 1024 * 1024 // 10MB max system memory increase

	// Check for memory leaks
	if allocDiff > maxAllocIncrease {
		t.Errorf("Potential memory leak detected: allocated memory increased by %d bytes (threshold: %d)",
			allocDiff, maxAllocIncrease)
	}

	bytesPerOp := float64(totalAllocDiff) / float64(iterations)
	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage per operation: %.2f bytes (threshold: %d)",
			bytesPerOp, maxBytesPerOp)
	}

	if sysDiff > maxSysIncrease {
		t.Errorf("System memory increased significantly: %d bytes (threshold: %d)",
			sysDiff, maxSysIncrease)
	}

	// Success metrics
	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp && sysDiff <= maxSysIncrease {
		t.Logf("✅ Memory leak test PASSED:")
		t.Logf("  - Allocated memory increase: %d bytes (✓ under %d limit)", allocDiff, maxAllocIncrease)
		t.Logf("  - Bytes per operation: %.2f (✓ under %d limit)", bytesPerOp, maxBytesPerOp)
		t.Logf("  - System memory increase: %d bytes (✓ under %d limit)", sysDiff, maxSysIncrease)
		t.Logf("  - Total operations completed: %d", iterations)
		t.Logf("  - No memory leaks detected! 🎉")
	}
}

// TestMemoryStabilityOverTime checks memory stability over extended period
func TestMemoryStabilityOverTime(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping extended memory stability test in short mode")
	}

	// Test for 10 seconds of continuous operation
	testDuration := 10 * time.Second
	reportInterval := 2 * time.Second

	t.Logf("Running memory stability test for %v...", testDuration)

	startTime := time.Now()
	lastReport := startTime
	operationCount := 0

	// Get initial memory
	runtime.GC()
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)

	for time.Since(startTime) < testDuration {
		// Perform operations
		tkz := GetTokenizer()
		_, err := tkz.Tokenize([]byte("SELECT * FROM test_table WHERE id = 123"))
		if err != nil {
			t.Fatalf("Tokenization failed: %v", err)
		}
		PutTokenizer(tkz)

		astObj := ast.NewAST()
		ast.ReleaseAST(astObj)

		operationCount++

		// Report progress
		if time.Since(lastReport) >= reportInterval {
			var currentMem runtime.MemStats
			runtime.ReadMemStats(&currentMem)

			allocDiff := int64(currentMem.Alloc) - int64(initialMem.Alloc)
			elapsed := time.Since(startTime)

			t.Logf("Progress: %v elapsed, %d operations, alloc diff: %d bytes",
				elapsed.Round(time.Second), operationCount, allocDiff)

			lastReport = time.Now()

			// Force GC periodically
			runtime.GC()
		}

		// Small delay to simulate realistic usage
		time.Sleep(time.Microsecond * 100)
	}

	// Final check
	runtime.GC()
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)

	finalAllocDiff := int64(finalMem.Alloc) - int64(initialMem.Alloc)
	opsPerSecond := float64(operationCount) / testDuration.Seconds()

	t.Logf("Memory stability test completed:")
	t.Logf("  Duration: %v", testDuration)
	t.Logf("  Total operations: %d", operationCount)
	t.Logf("  Operations per second: %.0f", opsPerSecond)
	t.Logf("  Final memory difference: %d bytes", finalAllocDiff)

	// Check stability (should not grow continuously)
	maxStabilityDrift := int64(5 * 1024 * 1024) // 5MB max drift
	if finalAllocDiff > maxStabilityDrift {
		t.Errorf("Memory not stable over time: grew by %d bytes (max allowed: %d)",
			finalAllocDiff, maxStabilityDrift)
	} else {
		t.Logf("✅ Memory stability test PASSED: growth within acceptable limits")
	}
}

// BenchmarkMemoryUsage provides memory usage benchmarks
func BenchmarkMemoryUsage(b *testing.B) {
	query := []byte("SELECT id, name, email, created_at FROM users WHERE status = 'active' AND age BETWEEN 18 AND 65 ORDER BY created_at DESC LIMIT 100")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tkz := GetTokenizer()
		_, err := tkz.Tokenize(query)
		if err != nil {
			b.Fatal(err)
		}
		PutTokenizer(tkz)
	}
}
