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

package metrics

import (
	"errors"
	"fmt"
	"testing"
	"time"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
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

	// Add a small sleep to ensure uptime is measurable on fast Windows systems
	time.Sleep(10 * time.Millisecond)

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

	// Verify error breakdown. Unstructured errors (stdlib errors.New)
	// are bucketed into the "E_UNKNOWN" bucket rather than keyed by
	// err.Error() — this is the fix for the metrics memory-DoS (C3).
	if len(stats.ErrorsByType) != 1 {
		t.Errorf("Expected 1 error type, got %d", len(stats.ErrorsByType))
	}

	if count, exists := stats.ErrorsByType["E_UNKNOWN"]; !exists || count != 1 {
		t.Errorf("Expected 'E_UNKNOWN' bucket with count 1, got count %d (exists=%v)", count, exists)
	}

	// Verify timing
	if stats.AverageTokenizeDuration <= 0 {
		t.Error("Average tokenize duration should be positive")
	}

	if stats.TokenizeOperationsPerSecond <= 0 {
		t.Error("Tokenize operations per second should be positive")
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

// TestRecordTokenization_BoundedCardinality verifies the fix for issue C3:
// generating 10,000 errors with unique err.Error() strings but the same
// structured ErrorCode must NOT inflate ErrorsByType — it should stay at
// a single bucket. This closes the memory-DoS vector where pathological
// or fuzz inputs could grow the map without bound.
func TestRecordTokenization_BoundedCardinality(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	const n = 10_000
	for i := 0; i < n; i++ {
		// Each error has a unique Message (via fmt) but shares the same
		// structured Code. Prior implementation keyed on err.Error(),
		// which would produce 10,000 distinct map keys.
		err := sqlerrors.NewError(
			sqlerrors.ErrCodeUnexpectedChar,
			fmt.Sprintf("unique message #%d for fuzz input %x", i, i*31+7),
			models.Location{Line: i, Column: i},
		)
		RecordTokenization(time.Microsecond, 10, err)
	}

	stats := GetStats()

	// Only one bucket should exist (E1001). The old implementation
	// would produce n distinct buckets here.
	if got := len(stats.ErrorsByType); got > 5 {
		t.Fatalf("expected bounded cardinality (<=5 buckets), got %d buckets — "+
			"indicates the DoS fix regressed", got)
	}

	if count, ok := stats.ErrorsByType[string(sqlerrors.ErrCodeUnexpectedChar)]; !ok || count != n {
		t.Errorf("expected bucket %q with count %d, got count=%d ok=%v",
			sqlerrors.ErrCodeUnexpectedChar, n, count, ok)
	}

	if stats.TokenizeErrors != n {
		t.Errorf("expected %d tokenize errors, got %d", n, stats.TokenizeErrors)
	}
}

// TestRecordTokenization_DifferentCodes verifies that distinct structured
// ErrorCodes produce distinct buckets with correct per-bucket counts.
func TestRecordTokenization_DifferentCodes(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	cases := []struct {
		code  sqlerrors.ErrorCode
		count int
	}{
		{sqlerrors.ErrCodeUnexpectedChar, 7},
		{sqlerrors.ErrCodeUnterminatedString, 11},
		{sqlerrors.ErrCodeInvalidNumber, 3},
	}

	for _, c := range cases {
		for i := 0; i < c.count; i++ {
			err := sqlerrors.NewError(c.code, "msg", models.Location{Line: 1, Column: 1})
			RecordTokenization(time.Microsecond, 10, err)
		}
	}

	stats := GetStats()

	if got := len(stats.ErrorsByType); got != len(cases) {
		t.Errorf("expected %d distinct buckets, got %d: %v",
			len(cases), got, stats.ErrorsByType)
	}

	for _, c := range cases {
		if got := stats.ErrorsByType[string(c.code)]; got != int64(c.count) {
			t.Errorf("bucket %q: expected count %d, got %d",
				c.code, c.count, got)
		}
	}
}

// TestRecordTokenization_UnstructuredFallback verifies that plain
// (non-*sqlerrors.Error) errors are bucketed into E_UNKNOWN rather than
// keyed by err.Error() — preserving the memory-DoS fix for stdlib errors
// and fmt.Errorf wrapping too.
func TestRecordTokenization_UnstructuredFallback(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	const n = 1_000
	for i := 0; i < n; i++ {
		// Each err has a unique string; the old implementation would
		// produce n map entries.
		RecordTokenization(time.Microsecond, 10,
			fmt.Errorf("unstructured unique %d", i))
	}

	stats := GetStats()

	if got := len(stats.ErrorsByType); got > 2 {
		t.Fatalf("expected unstructured errors to collapse into 1 bucket, "+
			"got %d buckets: %v", got, stats.ErrorsByType)
	}
	if count := stats.ErrorsByType["E_UNKNOWN"]; count != n {
		t.Errorf("expected E_UNKNOWN bucket count %d, got %d", n, count)
	}
}

// TestRecordParse_BoundedCardinality mirrors the tokenization test for the
// parser path. Parse errors are namespaced with the "parse:" prefix in the
// exported Stats shape.
func TestRecordParse_BoundedCardinality(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	const n = 10_000
	for i := 0; i < n; i++ {
		err := sqlerrors.NewError(
			sqlerrors.ErrCodeUnexpectedToken,
			fmt.Sprintf("unique parse message #%d", i),
			models.Location{Line: i, Column: i},
		)
		RecordParse(time.Microsecond, 0, err)
	}

	stats := GetStats()

	if got := len(stats.ErrorsByType); got > 5 {
		t.Fatalf("parse: expected bounded cardinality (<=5), got %d buckets", got)
	}

	key := "parse:" + string(sqlerrors.ErrCodeUnexpectedToken)
	if count, ok := stats.ErrorsByType[key]; !ok || count != n {
		t.Errorf("expected bucket %q with count %d, got count=%d ok=%v",
			key, n, count, ok)
	}
}

// TestGetStats_NoAllocationGrowth verifies that repeated GetStats() calls
// do not leak allocations. Prior implementation deep-copied an unbounded
// map on every call; now the error snapshot walks a fixed-size table.
//
// We assert on an upper bound rather than an exact count because Go's
// allocation accounting includes small bookkeeping (map header, stats
// struct) that can shift slightly between versions.
func TestGetStats_NoAllocationGrowth(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	// Seed a few errors so the snapshot has non-empty buckets to walk.
	for _, code := range []sqlerrors.ErrorCode{
		sqlerrors.ErrCodeUnexpectedChar,
		sqlerrors.ErrCodeUnterminatedString,
		sqlerrors.ErrCodeUnexpectedToken,
	} {
		err := sqlerrors.NewError(code, "seed", models.Location{Line: 1, Column: 1})
		RecordTokenization(time.Microsecond, 10, err)
		RecordParse(time.Microsecond, 0, err)
	}

	// Warm up to avoid counting init-time allocations.
	for i := 0; i < 10; i++ {
		_ = GetStats()
	}

	// Upper bound: GetStats should allocate a constant, small number of
	// objects (Stats struct + ErrorsByType map + map buckets). We allow
	// headroom for map growth internals.
	const maxAllocs = 20
	allocs := testing.AllocsPerRun(1000, func() {
		_ = GetStats()
	})

	if allocs > maxAllocs {
		t.Errorf("GetStats allocations = %.1f per call, want <= %d — "+
			"allocation growth may indicate regression of the C3 fix",
			allocs, maxAllocs)
	}

	// Additionally verify that 1000 calls do not inflate the bucket
	// count (i.e. no side-effect growth from the read path).
	before := len(GetStats().ErrorsByType)
	for i := 0; i < 1000; i++ {
		_ = GetStats()
	}
	after := len(GetStats().ErrorsByType)
	if before != after {
		t.Errorf("GetStats mutated bucket count: before=%d after=%d",
			before, after)
	}
}

// TestReset_ZerosErrorBuckets verifies Reset() restores all error-code
// buckets to zero without reallocating the underlying counter table.
func TestReset_ZerosErrorBuckets(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	err := sqlerrors.NewError(
		sqlerrors.ErrCodeUnexpectedChar, "boom",
		models.Location{Line: 1, Column: 1})
	for i := 0; i < 50; i++ {
		RecordTokenization(time.Microsecond, 10, err)
	}

	if got := GetStats().ErrorsByType[string(sqlerrors.ErrCodeUnexpectedChar)]; got != 50 {
		t.Fatalf("precondition failed: expected 50, got %d", got)
	}

	Reset()

	stats := GetStats()
	if len(stats.ErrorsByType) != 0 {
		t.Errorf("Reset should clear all buckets, got: %v", stats.ErrorsByType)
	}

	// And a fresh record after reset should work (proves the counter
	// table was zeroed, not destroyed).
	RecordTokenization(time.Microsecond, 10, err)
	if got := GetStats().ErrorsByType[string(sqlerrors.ErrCodeUnexpectedChar)]; got != 1 {
		t.Errorf("after Reset+record expected count 1, got %d", got)
	}
}
