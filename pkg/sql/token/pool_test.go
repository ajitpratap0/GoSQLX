package token

import (
	"runtime"
	"testing"
	"time"
)

// TestTokenPool tests basic token pool operations
func TestTokenPool(t *testing.T) {
	t.Run("Get and Put", func(t *testing.T) {
		// Get from pool
		tok := Get()
		if tok == nil {
			t.Fatal("Get() returned nil")
		}

		// Use it
		tok.Type = "IDENTIFIER"
		tok.Literal = "test"

		// Return to pool
		err := Put(tok)
		if err != nil {
			t.Errorf("Put() returned error: %v", err)
		}

		// Verify it was cleaned
		if tok.Type != "" {
			t.Errorf("Type not cleared, got %v", tok.Type)
		}
		if tok.Literal != "" {
			t.Errorf("Literal not cleared, got %v", tok.Literal)
		}
	})

	t.Run("Put nil token", func(t *testing.T) {
		// Should not panic or error
		err := Put(nil)
		if err != nil {
			t.Errorf("Put(nil) returned error: %v", err)
		}
	})

	t.Run("Token reuse", func(t *testing.T) {
		// Get first token
		tok1 := Get()
		tok1.Type = "SELECT"
		tok1.Literal = "SELECT"

		// Return it
		Put(tok1)

		// Get another token - might be the same one
		tok2 := Get()
		if tok2 == nil {
			t.Fatal("Get() returned nil on reuse")
		}

		// Should be clean
		if tok2.Type != "" {
			t.Errorf("Reused token not clean, Type = %v", tok2.Type)
		}
		if tok2.Literal != "" {
			t.Errorf("Reused token not clean, Literal = %v", tok2.Literal)
		}

		Put(tok2)
	})
}

// TestMemoryLeaks_TokenPool tests for memory leaks in token pool
func TestMemoryLeaks_TokenPool(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	t.Logf("Running %d iterations of token pool operations...", iterations)

	for i := 0; i < iterations; i++ {
		tok := Get()
		tok.Type = "IDENTIFIER"
		tok.Literal = "test_column_name"
		Put(tok)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("Token pool memory stats:")
	t.Logf("  Initial Alloc: %d bytes", m1.Alloc)
	t.Logf("  Final Alloc: %d bytes", m2.Alloc)
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 512 * 1024 // 512KB
	const maxBytesPerOp = 2000          // 2KB per operation

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak detected in token pool: allocated memory increased by %d bytes (threshold: %d)",
			allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage per operation in token pool: %.2f bytes (threshold: %d)",
			bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ Token pool memory leak test PASSED")
	}
}

// TestMemoryLeaks_TokenPool_VariableTypes tests with different token types
func TestMemoryLeaks_TokenPool_VariableTypes(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 10000

	tokenTypes := []struct {
		typ     Type
		literal string
	}{
		{Type("IDENTIFIER"), "column_name"},
		{Type("SELECT"), "SELECT"},
		{Type("FROM"), "FROM"},
		{Type("WHERE"), "WHERE"},
		{Type("STRING"), "'test string'"},
		{Type("NUMBER"), "12345"},
		{Type("OPERATOR"), "="},
		{Type("COMMA"), ","},
	}

	t.Logf("Running %d iterations with variable token types...", iterations)

	for i := 0; i < iterations; i++ {
		tokType := tokenTypes[i%len(tokenTypes)]

		tok := Get()
		tok.Type = tokType.typ
		tok.Literal = tokType.literal
		Put(tok)

		if i%1000 == 0 && i > 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)

	t.Logf("Variable types memory stats:")
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 512 * 1024 // 512KB
	const maxBytesPerOp = 2500          // 2.5KB per operation

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak detected: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ Variable types memory leak test PASSED")
	}
}

// TestMemoryLeaks_TokenPool_StressTest runs 100K operations
func TestMemoryLeaks_TokenPool_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const iterations = 100000

	t.Logf("Running stress test with %d iterations...", iterations)

	startTime := time.Now()

	for i := 0; i < iterations; i++ {
		tok := Get()
		tok.Type = "IDENTIFIER"
		tok.Literal = "test_column"
		Put(tok)

		if i%10000 == 0 && i > 0 {
			runtime.GC()
			t.Logf("Completed %d iterations...", i)
		}
	}

	elapsed := time.Since(startTime)

	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)
	totalAllocDiff := int64(m2.TotalAlloc) - int64(m1.TotalAlloc)
	bytesPerOp := float64(totalAllocDiff) / float64(iterations)
	opsPerSecond := float64(iterations) / elapsed.Seconds()

	t.Logf("Stress test results:")
	t.Logf("  Duration: %v", elapsed)
	t.Logf("  Operations: %d", iterations)
	t.Logf("  Ops/sec: %.0f", opsPerSecond)
	t.Logf("  Alloc diff: %d bytes", allocDiff)
	t.Logf("  TotalAlloc diff: %d bytes", totalAllocDiff)
	t.Logf("  Bytes per operation: %.2f", bytesPerOp)

	const maxAllocIncrease = 2 * 1024 * 1024 // 2MB for stress test
	const maxBytesPerOp = 2000               // 2KB per operation

	if allocDiff > maxAllocIncrease {
		t.Errorf("Memory leak detected: %d bytes (threshold: %d)", allocDiff, maxAllocIncrease)
	}

	if bytesPerOp > maxBytesPerOp {
		t.Errorf("High memory usage: %.2f bytes/op (threshold: %d)", bytesPerOp, maxBytesPerOp)
	}

	if allocDiff <= maxAllocIncrease && bytesPerOp <= maxBytesPerOp {
		t.Logf("✅ Stress test PASSED - %d operations completed successfully", iterations)
	}
}

// TestMemoryLeaks_TokenPool_SustainedLoad tests memory stability over time
func TestMemoryLeaks_TokenPool_SustainedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained load test in short mode")
	}

	testDuration := 30 * time.Second
	reportInterval := 5 * time.Second

	t.Logf("Running sustained load test for %v...", testDuration)

	startTime := time.Now()
	lastReport := startTime
	operationCount := 0

	runtime.GC()
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)

	for time.Since(startTime) < testDuration {
		tok := Get()
		tok.Type = "IDENTIFIER"
		tok.Literal = "test_column"
		Put(tok)

		operationCount++

		if time.Since(lastReport) >= reportInterval {
			var currentMem runtime.MemStats
			runtime.ReadMemStats(&currentMem)

			allocDiff := int64(currentMem.Alloc) - int64(initialMem.Alloc)
			elapsed := time.Since(startTime)
			opsPerSec := float64(operationCount) / elapsed.Seconds()

			t.Logf("Progress: %v elapsed, %d ops (%.0f ops/sec), alloc diff: %d bytes",
				elapsed.Round(time.Second), operationCount, opsPerSec, allocDiff)

			lastReport = time.Now()
			runtime.GC()
		}
	}

	runtime.GC()
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)

	finalAllocDiff := int64(finalMem.Alloc) - int64(initialMem.Alloc)
	opsPerSecond := float64(operationCount) / testDuration.Seconds()

	t.Logf("Sustained load test completed:")
	t.Logf("  Duration: %v", testDuration)
	t.Logf("  Total operations: %d", operationCount)
	t.Logf("  Operations per second: %.0f", opsPerSecond)
	t.Logf("  Final memory difference: %d bytes", finalAllocDiff)

	maxStabilityDrift := int64(5 * 1024 * 1024) // 5MB max drift
	if finalAllocDiff > maxStabilityDrift {
		t.Errorf("Memory not stable over time: grew by %d bytes (max allowed: %d)",
			finalAllocDiff, maxStabilityDrift)
	} else {
		t.Logf("✅ Sustained load test PASSED: memory stable over %v", testDuration)
	}
}

// TestTokenReset tests that Reset() properly clears token fields
func TestTokenReset(t *testing.T) {
	tok := &Token{
		Type:    "IDENTIFIER",
		Literal: "test",
	}

	tok.Reset()

	if tok.Type != "" {
		t.Errorf("Type not cleared by Reset(), got %v", tok.Type)
	}
	if tok.Literal != "" {
		t.Errorf("Literal not cleared by Reset(), got %v", tok.Literal)
	}
}

// BenchmarkTokenPool benchmarks token pool operations
func BenchmarkTokenPool(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tok := Get()
		tok.Type = "IDENTIFIER"
		tok.Literal = "column_name"
		Put(tok)
	}
}

// BenchmarkTokenPoolParallel benchmarks concurrent token pool operations
func BenchmarkTokenPoolParallel(b *testing.B) {
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok := Get()
			tok.Type = "IDENTIFIER"
			tok.Literal = "column_name"
			Put(tok)
		}
	})
}
