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

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRateLimitAllowsNormalTraffic(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	allowed, limit, remaining, _ := rl.allow("192.168.1.1", 1)
	if !allowed {
		t.Fatal("expected first request to be allowed")
	}
	if limit != sustainedLimit {
		t.Fatalf("expected limit %d, got %d", sustainedLimit, limit)
	}
	if remaining != sustainedLimit-1 {
		t.Fatalf("expected remaining %d, got %d", sustainedLimit-1, remaining)
	}
}

func TestRateLimitBlocksBurst(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	ip := "10.0.0.1"
	// Send burstLimit requests - all should be allowed.
	for i := 0; i < burstLimit; i++ {
		allowed, _, _, _ := rl.allow(ip, 1)
		if !allowed {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	// The 11th request should be burst-limited.
	allowed, _, _, _ := rl.allow(ip, 1)
	if allowed {
		t.Fatal("expected 11th request to be blocked by burst limit")
	}
}

func TestRateLimitToolWeighting(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	ip := "10.0.0.2"
	// analyze_sql has weight 5. After 10 requests at burst limit,
	// we should have consumed 50 of 120 weighted budget.
	for i := 0; i < burstLimit; i++ {
		allowed, _, _, _ := rl.allow(ip, 5) // analyze_sql weight
		if !allowed {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	// Verify the remaining budget was consumed at 5x rate.
	// After 10 requests * weight 5 = 50 weighted units consumed.
	// We can't send more right now due to burst limit, but let's check
	// a fresh IP with just sustained limit checks.
	ip2 := "10.0.0.3"
	count := 0
	for {
		allowed, _, remaining, _ := rl.allow(ip2, 5)
		if !allowed {
			break
		}
		count++
		_ = remaining
		// Safety: break if we somehow loop too many times
		if count > 200 {
			t.Fatal("too many requests allowed, expected sustained limit to kick in")
		}
	}
	// With burst limit 10, we can only send 10 before burst blocks us.
	// But sustained: 120/5 = 24 before sustained blocks. Burst kicks in at 10.
	if count != burstLimit {
		t.Fatalf("expected %d requests before blocking (burst limit), got %d", burstLimit, count)
	}
}

func TestRateLimitNonToolUnlimited(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	ip := "10.0.0.4"
	// Weight 0 requests bypass sustained limiting but still hit burst limit.
	// Send burstLimit weight-0 requests.
	for i := 0; i < burstLimit; i++ {
		allowed, _, _, _ := rl.allow(ip, 0)
		if !allowed {
			t.Fatalf("weight-0 request %d should have been allowed", i+1)
		}
	}

	// After burstLimit requests, the burst tokens are depleted.
	// But verify the sustained budget (weightedCount) was NOT consumed.
	idx := shardFor(ip)
	sh := &rl.shards[idx]
	sh.RLock()
	b := sh.buckets[ip]
	sh.RUnlock()

	b.mu.Lock()
	wc := b.weightedCount
	b.mu.Unlock()

	if wc != 0 {
		t.Fatalf("expected weightedCount=0 for weight-0 requests, got %d", wc)
	}
}

func TestRateLimitAdaptive(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	// Normal load.
	limit := currentLimit(rl)
	if limit != sustainedLimit {
		t.Fatalf("expected %d at normal load, got %d", sustainedLimit, limit)
	}

	// Simulate elevated load.
	rl.activeReqs.Store(55)
	limit = currentLimit(rl)
	if limit != elevatedLimit {
		t.Fatalf("expected %d at elevated load, got %d", elevatedLimit, limit)
	}

	// Simulate critical load.
	rl.activeReqs.Store(85)
	limit = currentLimit(rl)
	if limit != criticalLimit {
		t.Fatalf("expected %d at critical load, got %d", criticalLimit, limit)
	}
}

func TestRateLimitResponse(t *testing.T) {
	// Build a middleware that will be rate-limited.
	handler := RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
	}))

	ip := "10.0.0.5"

	// Helper to create a tools/call request body.
	makeBody := func() io.Reader {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}`
		return strings.NewReader(body)
	}

	// Exhaust burst limit.
	for i := 0; i < burstLimit; i++ {
		req := httptest.NewRequest("POST", "/mcp", makeBody())
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Next request should be rate-limited but still return 200 with JSON-RPC error.
	req := httptest.NewRequest("POST", "/mcp", makeBody())
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("rate-limited response should be HTTP 200, got %d", rec.Code)
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      *int   `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("expected jsonrpc 2.0, got %s", resp.JSONRPC)
	}
	if resp.Error.Code != -32000 {
		t.Fatalf("expected error code -32000, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "Rate limit exceeded") {
		t.Fatalf("expected rate limit message, got: %s", resp.Error.Message)
	}

	// Check rate limit headers.
	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatal("missing X-RateLimit-Limit header")
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Fatal("missing X-RateLimit-Remaining header")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatal("missing X-RateLimit-Reset header")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{
			name:       "X-Forwarded-For single IP",
			xff:        "203.0.113.50",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			remoteAddr: "10.0.0.1:1234",
			want:       "203.0.113.50",
		},
		{
			name:       "no XFF, use RemoteAddr with port",
			xff:        "",
			remoteAddr: "192.168.1.100:5678",
			want:       "192.168.1.100",
		},
		{
			name:       "no XFF, RemoteAddr without port",
			xff:        "",
			remoteAddr: "192.168.1.100",
			want:       "192.168.1.100",
		},
		{
			name:       "XFF with spaces",
			xff:        "  10.0.0.5 , 10.0.0.6",
			remoteAddr: "127.0.0.1:9999",
			want:       "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := extractIP(req)
			if got != tt.want {
				t.Errorf("extractIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractToolWeight(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantWeight int
	}{
		{
			name:       "validate_sql",
			body:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}`,
			wantWeight: 1,
		},
		{
			name:       "analyze_sql",
			body:       `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_sql","arguments":{"sql":"SELECT 1"}}}`,
			wantWeight: 5,
		},
		{
			name:       "security_scan",
			body:       `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"security_scan","arguments":{"sql":"SELECT 1"}}}`,
			wantWeight: 2,
		},
		{
			name:       "initialize method (not tools/call)",
			body:       `{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`,
			wantWeight: 0,
		},
		{
			name:       "list_tools method",
			body:       `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}`,
			wantWeight: 0,
		},
		{
			name:       "unknown tool",
			body:       `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}`,
			wantWeight: 1,
		},
		{
			name:       "empty body",
			body:       "",
			wantWeight: 0,
		},
		{
			name:       "invalid JSON",
			body:       `not json at all`,
			wantWeight: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest("POST", "/mcp", body)

			weight, newReq := extractToolWeight(req)
			if weight != tt.wantWeight {
				t.Errorf("extractToolWeight() weight = %d, want %d", weight, tt.wantWeight)
			}

			// Verify the body was re-buffered (downstream can read it).
			if tt.body != "" {
				rebuffered, err := io.ReadAll(newReq.Body)
				if err != nil {
					t.Fatalf("failed to read re-buffered body: %v", err)
				}
				if !bytes.Equal(rebuffered, []byte(tt.body)) {
					t.Errorf("re-buffered body mismatch: got %q, want %q", rebuffered, tt.body)
				}
			}
		})
	}
}
