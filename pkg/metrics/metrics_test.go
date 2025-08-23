package metrics

import (
	"errors"
	"testing"
	"time"
)

func TestMetricsBasicFunctionality(t *testing.T) {
	// Reset metrics to start fresh
	Reset()

	// Metrics should be disabled by default
	if IsEnabled() {
		t.Error("Metrics should be disabled by default")
	}

	// Enable metrics
	Enable()
	if !IsEnabled() {
		t.Error("Metrics should be enabled after Enable()")
	}

	// Record some operations
	RecordTokenization(time.Millisecond*5, 100, nil)
	RecordTokenization(time.Millisecond*3, 50, nil)
	RecordTokenization(time.Millisecond*8, 200, errors.New("test error"))

	// Record pool operations
	RecordPoolGet(true)  // from pool
	RecordPoolGet(false) // pool miss
	RecordPoolPut()

	// Get stats
	stats := GetStats()

	// Verify basic counts
	if stats.TokenizeOperations != 3 {
		t.Errorf("Expected 3 operations, got %d", stats.TokenizeOperations)
	}

	if stats.TokenizeErrors != 1 {
		t.Errorf("Expected 1 error, got %d", stats.TokenizeErrors)
	}

	if stats.ErrorRate != 1.0/3.0 {
		t.Errorf("Expected error rate 0.333, got %f", stats.ErrorRate)
	}

	// Verify pool metrics
	if stats.PoolGets != 2 {
		t.Errorf("Expected 2 pool gets, got %d", stats.PoolGets)
	}

	if stats.PoolPuts != 1 {
		t.Errorf("Expected 1 pool put, got %d", stats.PoolPuts)
	}

	if stats.PoolBalance != 1 {
		t.Errorf("Expected pool balance 1, got %d", stats.PoolBalance)
	}

	if stats.PoolMissRate != 0.5 {
		t.Errorf("Expected pool miss rate 0.5, got %f", stats.PoolMissRate)
	}

	// Verify query size metrics
	if stats.MinQuerySize != 50 {
		t.Errorf("Expected min query size 50, got %d", stats.MinQuerySize)
	}

	if stats.MaxQuerySize != 200 {
		t.Errorf("Expected max query size 200, got %d", stats.MaxQuerySize)
	}

	expectedAvgSize := float64(350) / 3.0 // (100+50+200)/3
	if stats.AverageQuerySize != expectedAvgSize {
		t.Errorf("Expected average query size %.2f, got %.2f", expectedAvgSize, stats.AverageQuerySize)
	}

	if stats.TotalBytesProcessed != 350 {
		t.Errorf("Expected total bytes 350, got %d", stats.TotalBytesProcessed)
	}

	// Verify error breakdown
	if len(stats.ErrorsByType) != 1 {
		t.Errorf("Expected 1 error type, got %d", len(stats.ErrorsByType))
	}

	if count, exists := stats.ErrorsByType["test error"]; !exists || count != 1 {
		t.Errorf("Expected 'test error' with count 1, got count %d", count)
	}

	// Verify timing
	if stats.AverageDuration <= 0 {
		t.Error("Average duration should be positive")
	}

	if stats.OperationsPerSecond <= 0 {
		t.Error("Operations per second should be positive")
	}

	if stats.Uptime <= 0 {
		t.Error("Uptime should be positive")
	}

	// Test disable
	Disable()
	if IsEnabled() {
		t.Error("Metrics should be disabled after Disable()")
	}
}

func TestMetricsDisabled(t *testing.T) {
	// Reset and ensure disabled
	Reset()
	Disable()

	// Record operations while disabled
	RecordTokenization(time.Millisecond*5, 100, nil)
	RecordPoolGet(true)
	RecordPoolPut()

	// Stats should be empty
	stats := GetStats()
	if stats.TokenizeOperations != 0 {
		t.Errorf("Expected 0 operations when disabled, got %d", stats.TokenizeOperations)
	}

	if stats.PoolGets != 0 {
		t.Errorf("Expected 0 pool gets when disabled, got %d", stats.PoolGets)
	}
}

func TestMetricsReset(t *testing.T) {
	// Enable and record some data
	Enable()
	RecordTokenization(time.Millisecond*5, 100, nil)
	RecordPoolGet(true)

	// Verify data exists
	stats := GetStats()
	if stats.TokenizeOperations == 0 {
		t.Error("Expected operations before reset")
	}

	// Reset and verify clean state
	Reset()
	stats = GetStats()

	if stats.TokenizeOperations != 0 {
		t.Errorf("Expected 0 operations after reset, got %d", stats.TokenizeOperations)
	}

	if stats.PoolGets != 0 {
		t.Errorf("Expected 0 pool gets after reset, got %d", stats.PoolGets)
	}

	if stats.MinQuerySize != -1 {
		t.Errorf("Expected min query size -1 after reset, got %d", stats.MinQuerySize)
	}

	if len(stats.ErrorsByType) != 0 {
		t.Errorf("Expected 0 error types after reset, got %d", len(stats.ErrorsByType))
	}
}

func TestMetricsConcurrency(t *testing.T) {
	Reset()
	Enable()

	// Test concurrent access
	const numGoroutines = 10
	const operationsPerGoroutine = 100

	done := make(chan bool, numGoroutines)

	// Start multiple goroutines recording metrics
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < operationsPerGoroutine; j++ {
				RecordTokenization(time.Microsecond*100, 50, nil)
				RecordPoolGet(true)
				RecordPoolPut()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify final counts
	stats := GetStats()
	expectedOps := int64(numGoroutines * operationsPerGoroutine)

	if stats.TokenizeOperations != expectedOps {
		t.Errorf("Expected %d operations, got %d", expectedOps, stats.TokenizeOperations)
	}

	if stats.PoolGets != expectedOps {
		t.Errorf("Expected %d pool gets, got %d", expectedOps, stats.PoolGets)
	}

	if stats.PoolPuts != expectedOps {
		t.Errorf("Expected %d pool puts, got %d", expectedOps, stats.PoolPuts)
	}

	if stats.PoolBalance != 0 {
		t.Errorf("Expected pool balance 0, got %d", stats.PoolBalance)
	}
}

func BenchmarkMetricsRecordTokenization(b *testing.B) {
	Reset()
	Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordTokenization(time.Microsecond*100, 50, nil)
	}
}

func BenchmarkMetricsRecordPool(b *testing.B) {
	Reset()
	Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordPoolGet(true)
		RecordPoolPut()
	}
}

func BenchmarkMetricsGetStats(b *testing.B) {
	Reset()
	Enable()

	// Record some data first
	for i := 0; i < 1000; i++ {
		RecordTokenization(time.Microsecond*100, 50, nil)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetStats()
	}
}
