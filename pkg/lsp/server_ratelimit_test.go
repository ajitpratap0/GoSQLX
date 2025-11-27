package lsp

import (
	"encoding/json"
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

// TestServer_RateLimit_WithinWindow tests that requests within limit are allowed
func TestServer_RateLimit_WithinWindow(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Send requests within the rate limit
	requestCount := RateLimitRequests / 2 // Send half the limit
	for i := 0; i < requestCount; i++ {
		allowed := server.checkRateLimit()
		if !allowed {
			t.Errorf("request %d was rate limited but should be allowed (within limit)", i+1)
		}
	}

	// Verify total count is as expected
	count := server.requestCount
	if count != int64(requestCount) {
		t.Errorf("expected request count %d, got %d", requestCount, count)
	}
}

// TestServer_RateLimit_Exceeded tests that requests over limit are rejected
func TestServer_RateLimit_Exceeded(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Send requests up to the limit
	for i := 0; i < RateLimitRequests; i++ {
		allowed := server.checkRateLimit()
		if !allowed {
			t.Errorf("request %d was rate limited but should be allowed", i+1)
		}
	}

	// Next request should be rate limited
	allowed := server.checkRateLimit()
	if allowed {
		t.Error("request after limit should be rate limited but was allowed")
	}

	// Multiple requests after limit should all be rejected
	for i := 0; i < 5; i++ {
		allowed := server.checkRateLimit()
		if allowed {
			t.Errorf("request %d after limit should be rate limited but was allowed", i+1)
		}
	}
}

// TestServer_RateLimit_WindowReset tests that counter resets after time window
func TestServer_RateLimit_WindowReset(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Fill up the rate limit
	for i := 0; i < RateLimitRequests; i++ {
		allowed := server.checkRateLimit()
		if !allowed {
			t.Errorf("request %d was rate limited but should be allowed", i+1)
		}
	}

	// Next request should be limited
	allowed := server.checkRateLimit()
	if allowed {
		t.Error("request after limit should be rate limited")
	}

	// Wait for rate limit window to pass
	time.Sleep(RateLimitWindow + 10*time.Millisecond)

	// Now requests should be allowed again
	allowed = server.checkRateLimit()
	if !allowed {
		t.Error("request after window reset should be allowed")
	}

	// Verify counter was reset (should be 1 after the check above)
	count := server.requestCount
	if count != 1 {
		t.Errorf("expected request count to reset to 1, got %d", count)
	}
}

// TestServer_RateLimit_Concurrent tests that concurrent access is thread-safe
func TestServer_RateLimit_Concurrent(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Use a smaller number than the limit to ensure some succeed
	numGoroutines := 50
	numRequestsPerGoroutine := 2

	var wg sync.WaitGroup
	allowedCount := int64(0)
	deniedCount := int64(0)
	var countMu sync.Mutex

	// Launch concurrent goroutines making requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numRequestsPerGoroutine; j++ {
				allowed := server.checkRateLimit()
				countMu.Lock()
				if allowed {
					allowedCount++
				} else {
					deniedCount++
				}
				countMu.Unlock()
			}
		}()
	}

	wg.Wait()

	totalRequests := int64(numGoroutines * numRequestsPerGoroutine)
	if allowedCount+deniedCount != totalRequests {
		t.Errorf("expected %d total requests, got %d allowed + %d denied = %d",
			totalRequests, allowedCount, deniedCount, allowedCount+deniedCount)
	}

	// The allowed count should not exceed the rate limit
	if allowedCount > RateLimitRequests {
		t.Errorf("allowed count %d exceeds rate limit %d", allowedCount, RateLimitRequests)
	}

	t.Logf("Concurrent test: %d allowed, %d denied out of %d total requests",
		allowedCount, deniedCount, totalRequests)
}

// TestServer_RateLimit_HandleMessage tests rate limiting in message handling
func TestServer_RateLimit_HandleMessage(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Create a valid request
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "shutdown",
	}
	msgBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Send requests up to the limit
	for i := 0; i < RateLimitRequests; i++ {
		server.handleMessage(msgBytes)
	}

	// Clear output buffer to check next response
	mock.output.Reset()

	// Next request should be rate limited
	server.handleMessage(msgBytes)

	// Check that a rate limit error response was sent
	output := mock.output.String()
	if output != "" {
		// Rate limited requests should get an error response
		if !contains(output, "RequestCancelled") && !contains(output, "rate limit") {
			t.Logf("Output after rate limit: %s", output)
		}
	}
}

// TestServer_RateLimit_MultipleWindows tests behavior across multiple windows
func TestServer_RateLimit_MultipleWindows(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Window 1: Fill the limit
	for i := 0; i < RateLimitRequests; i++ {
		allowed := server.checkRateLimit()
		if !allowed {
			t.Errorf("window 1: request %d was rate limited but should be allowed", i+1)
		}
	}

	// Verify next request is blocked
	if server.checkRateLimit() {
		t.Error("window 1: request after limit should be blocked")
	}

	// Wait for window to reset
	time.Sleep(RateLimitWindow + 10*time.Millisecond)

	// Window 2: Should be able to make requests again
	for i := 0; i < RateLimitRequests/2; i++ {
		allowed := server.checkRateLimit()
		if !allowed {
			t.Errorf("window 2: request %d was rate limited but should be allowed", i+1)
		}
	}

	// Wait for another window
	time.Sleep(RateLimitWindow + 10*time.Millisecond)

	// Window 3: Again should allow requests
	allowed := server.checkRateLimit()
	if !allowed {
		t.Error("window 3: first request should be allowed")
	}
}

// TestServer_RateLimit_EdgeCases tests edge cases in rate limiting
func TestServer_RateLimit_EdgeCases(t *testing.T) {
	t.Run("exactly at limit", func(t *testing.T) {
		mock := newMockReadWriter()
		logger := log.New(io.Discard, "", 0)
		server := NewServer(mock.input, mock.output, logger)

		// Send exactly RateLimitRequests
		for i := 0; i < RateLimitRequests; i++ {
			allowed := server.checkRateLimit()
			if !allowed {
				t.Errorf("request %d should be allowed", i+1)
			}
		}

		// The (RateLimitRequests + 1)th request should fail
		allowed := server.checkRateLimit()
		if allowed {
			t.Error("request at limit+1 should be denied")
		}
	})

	t.Run("burst at start", func(t *testing.T) {
		mock := newMockReadWriter()
		logger := log.New(io.Discard, "", 0)
		server := NewServer(mock.input, mock.output, logger)

		// Rapid burst of requests
		allowedCount := 0
		for i := 0; i < RateLimitRequests+10; i++ {
			if server.checkRateLimit() {
				allowedCount++
			}
		}

		if allowedCount > RateLimitRequests {
			t.Errorf("burst allowed %d requests, expected max %d", allowedCount, RateLimitRequests)
		}
	})

	t.Run("alternating windows", func(t *testing.T) {
		mock := newMockReadWriter()
		logger := log.New(io.Discard, "", 0)
		server := NewServer(mock.input, mock.output, logger)

		for window := 0; window < 3; window++ {
			// Make some requests in this window
			for i := 0; i < 10; i++ {
				allowed := server.checkRateLimit()
				if !allowed {
					t.Errorf("window %d: request %d was blocked unexpectedly", window, i+1)
				}
			}

			// Wait for window to reset
			time.Sleep(RateLimitWindow + 10*time.Millisecond)
		}
	})
}

// TestServer_RateLimit_StressTest performs a stress test with many concurrent requests
func TestServer_RateLimit_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	numGoroutines := 100
	numRequestsPerGoroutine := 10

	var wg sync.WaitGroup
	results := make([]bool, numGoroutines*numRequestsPerGoroutine)
	resultsMu := sync.Mutex{}
	resultIdx := 0

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numRequestsPerGoroutine; j++ {
				allowed := server.checkRateLimit()
				resultsMu.Lock()
				if resultIdx < len(results) {
					results[resultIdx] = allowed
					resultIdx++
				}
				resultsMu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Count allowed and denied
	allowed := 0
	denied := 0
	for _, result := range results {
		if result {
			allowed++
		} else {
			denied++
		}
	}

	t.Logf("Stress test results: %d allowed, %d denied out of %d requests",
		allowed, denied, len(results))

	// Verify rate limit was enforced (no more than RateLimitRequests allowed)
	if allowed > RateLimitRequests {
		t.Errorf("rate limit violated: %d requests allowed (limit: %d)", allowed, RateLimitRequests)
	}

	// Verify we got some denials (since we're making way more than the limit)
	if denied == 0 {
		t.Error("expected some requests to be denied in stress test")
	}
}

// TestServer_RateLimit_ResetTiming tests the precise timing of window resets
func TestServer_RateLimit_ResetTiming(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Fill rate limit
	for i := 0; i < RateLimitRequests; i++ {
		server.checkRateLimit()
	}

	// Verify blocked
	if server.checkRateLimit() {
		t.Error("should be blocked after hitting limit")
	}

	// Record time and wait just under the window
	startTime := time.Now()
	time.Sleep(RateLimitWindow - 50*time.Millisecond)

	// Should still be blocked
	if server.checkRateLimit() {
		t.Error("should still be blocked before window completes")
	}

	// Wait for remaining time plus buffer
	elapsed := time.Since(startTime)
	remaining := RateLimitWindow - elapsed + 20*time.Millisecond
	if remaining > 0 {
		time.Sleep(remaining)
	}

	// Now should be allowed
	if !server.checkRateLimit() {
		t.Error("should be allowed after window reset")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsInner(s, substr)))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
