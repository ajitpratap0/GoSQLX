package monitor

import (
	"testing"
	"time"
)

func TestMetricsCollection(t *testing.T) {
	// Reset and enable metrics
	Reset()
	Enable()
	defer Disable()

	// Record some tokenizer calls
	RecordTokenizerCall(100*time.Microsecond, 50, nil)
	RecordTokenizerCall(200*time.Microsecond, 75, nil)
	RecordTokenizerCall(150*time.Microsecond, 60, nil)

	// Record a tokenizer error
	RecordTokenizerCall(50*time.Microsecond, 0, ErrTest)

	// Record parser calls
	RecordParserCall(500*time.Microsecond, nil)
	RecordParserCall(600*time.Microsecond, nil)
	RecordParserCall(400*time.Microsecond, ErrTest)

	// Record pool operations
	RecordPoolHit()
	RecordPoolHit()
	RecordPoolHit()
	RecordPoolMiss()

	// Get metrics
	m := GetMetrics()

	// Verify tokenizer metrics
	if m.TokenizerCalls != 4 {
		t.Errorf("Expected 4 tokenizer calls, got %d", m.TokenizerCalls)
	}

	if m.TokensProcessed != 185 {
		t.Errorf("Expected 185 tokens processed, got %d", m.TokensProcessed)
	}

	if m.TokenizerErrors != 1 {
		t.Errorf("Expected 1 tokenizer error, got %d", m.TokenizerErrors)
	}

	// Verify parser metrics
	if m.ParserCalls != 3 {
		t.Errorf("Expected 3 parser calls, got %d", m.ParserCalls)
	}

	if m.StatementsProcessed != 2 {
		t.Errorf("Expected 2 statements processed, got %d", m.StatementsProcessed)
	}

	if m.ParserErrors != 1 {
		t.Errorf("Expected 1 parser error, got %d", m.ParserErrors)
	}

	// Verify pool metrics
	if m.PoolHits != 3 {
		t.Errorf("Expected 3 pool hits, got %d", m.PoolHits)
	}

	if m.PoolMisses != 1 {
		t.Errorf("Expected 1 pool miss, got %d", m.PoolMisses)
	}

	if m.PoolReuse != 75.0 {
		t.Errorf("Expected 75%% pool reuse, got %.2f%%", m.PoolReuse)
	}
}

func TestMetricsDisabled(t *testing.T) {
	Reset()
	Disable()

	// Record operations while disabled
	RecordTokenizerCall(100*time.Microsecond, 50, nil)
	RecordParserCall(500*time.Microsecond, nil)
	RecordPoolHit()

	m := GetMetrics()

	// All metrics should be zero
	if m.TokenizerCalls != 0 {
		t.Errorf("Expected 0 tokenizer calls when disabled, got %d", m.TokenizerCalls)
	}

	if m.ParserCalls != 0 {
		t.Errorf("Expected 0 parser calls when disabled, got %d", m.ParserCalls)
	}

	if m.PoolHits != 0 {
		t.Errorf("Expected 0 pool hits when disabled, got %d", m.PoolHits)
	}
}

func TestSummary(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	// Record some operations
	for i := 0; i < 100; i++ {
		RecordTokenizerCall(100*time.Microsecond, 50, nil)
		if i%10 == 0 {
			RecordTokenizerCall(100*time.Microsecond, 0, ErrTest)
		}
	}

	for i := 0; i < 50; i++ {
		RecordParserCall(500*time.Microsecond, nil)
		if i%25 == 0 {
			RecordParserCall(500*time.Microsecond, ErrTest)
		}
	}

	// Get summary
	s := GetSummary()

	// Verify summary calculations
	if s.TotalOperations != 162 { // 110 tokenizer + 52 parser
		t.Errorf("Expected 162 total operations, got %d", s.TotalOperations)
	}

	expectedAvgTokenizer := (100 * time.Microsecond * 110) / 110
	if s.AvgTokenizerLatency != expectedAvgTokenizer {
		t.Errorf("Expected avg tokenizer latency %v, got %v", expectedAvgTokenizer, s.AvgTokenizerLatency)
	}

	expectedAvgParser := (500 * time.Microsecond * 52) / 52
	if s.AvgParserLatency != expectedAvgParser {
		t.Errorf("Expected avg parser latency %v, got %v", expectedAvgParser, s.AvgParserLatency)
	}

	// Error rate should be (10 + 2) / 162 * 100 ≈ 7.41%
	expectedErrorRate := float64(12) / float64(162) * 100
	if s.ErrorRate < expectedErrorRate-0.1 || s.ErrorRate > expectedErrorRate+0.1 {
		t.Errorf("Expected error rate ~%.2f%%, got %.2f%%", expectedErrorRate, s.ErrorRate)
	}
}

func TestReset(t *testing.T) {
	Enable()
	defer Disable()

	// Record some operations
	RecordTokenizerCall(100*time.Microsecond, 50, nil)
	RecordParserCall(500*time.Microsecond, nil)
	RecordPoolHit()

	// Verify metrics exist
	m := GetMetrics()
	if m.TokenizerCalls == 0 {
		t.Error("Expected metrics before reset")
	}

	// Reset
	Reset()

	// Verify all metrics are zero
	m = GetMetrics()
	if m.TokenizerCalls != 0 || m.ParserCalls != 0 || m.PoolHits != 0 {
		t.Error("Expected all metrics to be zero after reset")
	}
}

func TestConcurrentAccess(t *testing.T) {
	Reset()
	Enable()
	defer Disable()

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				RecordTokenizerCall(100*time.Microsecond, 50, nil)
				RecordParserCall(500*time.Microsecond, nil)
				RecordPoolHit()
				GetMetrics()
				GetSummary()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final counts
	m := GetMetrics()
	if m.TokenizerCalls != 1000 {
		t.Errorf("Expected 1000 tokenizer calls, got %d", m.TokenizerCalls)
	}

	if m.ParserCalls != 1000 {
		t.Errorf("Expected 1000 parser calls, got %d", m.ParserCalls)
	}

	if m.PoolHits != 1000 {
		t.Errorf("Expected 1000 pool hits, got %d", m.PoolHits)
	}
}

// Test error for testing
type testError struct{}

func (e testError) Error() string { return "test error" }

var ErrTest = testError{}

func BenchmarkRecordTokenizerCall(b *testing.B) {
	Enable()
	defer Disable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecordTokenizerCall(100*time.Microsecond, 50, nil)
	}
}

func BenchmarkGetMetrics(b *testing.B) {
	Enable()
	defer Disable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetMetrics()
	}
}

func BenchmarkGetSummary(b *testing.B) {
	Enable()
	defer Disable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetSummary()
	}
}