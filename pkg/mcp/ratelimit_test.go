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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestRateLimitAllowsNormalTraffic(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()

	d := rl.allow("192.168.1.1", 1)
	allowed, limit, remaining := d.allowed, d.limit, d.remaining
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
		allowed := rl.allow(ip, 1).allowed
		if !allowed {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	// The 11th request should be burst-limited.
	allowed := rl.allow(ip, 1).allowed
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
		allowed := rl.allow(ip, 5).allowed // analyze_sql weight
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
		if !rl.allow(ip2, 5).allowed {
			break
		}
		count++
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
		allowed := rl.allow(ip, 0).allowed
		if !allowed {
			t.Fatalf("weight-0 request %d should have been allowed", i+1)
		}
	}

	// After burstLimit requests, the burst tokens are depleted.
	// But verify the sustained budget (weightedCount) was NOT consumed.
	idx := shardFor(ip)
	sh := &rl.shards[idx]
	sh.mu.Lock()
	b, ok := sh.buckets[ip].Value.(*bucket)
	sh.mu.Unlock()
	if !ok {
		t.Fatal("bucket not found")
	}

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

	// Next request should be rate-limited: HTTP 429 with a JSON-RPC error.
	req := httptest.NewRequest("POST", "/mcp", makeBody())
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited response should be HTTP 429, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
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
	if resp.ID == nil || *resp.ID != 1 {
		t.Fatalf("expected the request id 1 to be echoed, got %v", resp.ID)
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

func TestClientKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		hops       int
		xff        []string
		cfIP       string
		remoteAddr string
		want       string
	}{
		{name: "default ignores spoofed XFF", xff: []string{"203.0.113.50"}, remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "default ignores trusted-looking header", cfIP: "203.0.113.9", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "RemoteAddr without port", remoteAddr: "192.168.1.100", want: "192.168.1.100"},
		{name: "trusted header used", header: "Cf-Connecting-Ip", cfIP: "203.0.113.9", remoteAddr: "10.0.0.1:1234", want: "203.0.113.9"},
		{name: "trusted header invalid falls back", header: "Cf-Connecting-Ip", cfIP: "not-an-ip", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "trusted header oversized falls back", header: "Cf-Connecting-Ip", cfIP: strings.Repeat("a", 2048), remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "trusted header missing falls back", header: "Cf-Connecting-Ip", remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "trusted header list takes rightmost", header: "Cf-Connecting-Ip", cfIP: "1.1.1.1, 203.0.113.9", remoteAddr: "10.0.0.1:1234", want: "203.0.113.9"},
		{name: "hops=1 takes rightmost XFF", hops: 1, xff: []string{"6.6.6.6, 203.0.113.50"}, remoteAddr: "10.0.0.1:1234", want: "203.0.113.50"},
		{name: "hops=2 skips one proxy", hops: 2, xff: []string{"6.6.6.6, 203.0.113.50, 70.41.3.18"}, remoteAddr: "10.0.0.1:1234", want: "203.0.113.50"},
		{name: "hops spans header lines", hops: 2, xff: []string{"6.6.6.6", "203.0.113.50", "70.41.3.18"}, remoteAddr: "10.0.0.1:1234", want: "203.0.113.50"},
		{name: "hops beyond entries falls back", hops: 3, xff: []string{"203.0.113.50"}, remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "hops invalid entry falls back", hops: 1, xff: []string{"garbage"}, remoteAddr: "10.0.0.1:1234", want: "10.0.0.1"},
		{name: "XFF entry with port", hops: 1, xff: []string{"203.0.113.50:4711"}, remoteAddr: "10.0.0.1:1234", want: "203.0.113.50"},
		{name: "IPv6 grouped by /64", remoteAddr: "[2001:db8:1:2:aaaa::1]:443", want: "2001:db8:1:2::/64"},
		{name: "IPv4-mapped IPv6 normalised", header: "Cf-Connecting-Ip", cfIP: "::ffff:203.0.113.9", remoteAddr: "10.0.0.1:1234", want: "203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, v := range tt.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if tt.cfIP != "" {
				req.Header.Set("CF-Connecting-IP", tt.cfIP)
			}
			r := newClientIPResolver(&Config{TrustedProxyHeader: tt.header, TrustedProxyHops: tt.hops})
			if got := r.clientKey(req); got != tt.want {
				t.Errorf("clientKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// okHandler is a downstream handler that always succeeds.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.WriteHeader(http.StatusOK)
})

func toolCallBody(id, tool string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"sql":"SELECT 1"}}}`
}

func TestRateLimitMiddleware_SpoofedXFFStillLimited(t *testing.T) {
	handler := RateLimitMiddleware(okHandler)
	var last int
	for i := 0; i <= burstLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolCallBody("1", "validate_sql")))
		req.RemoteAddr = "198.51.100.7:5555"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("11.0.%d.1", i))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request %d with rotating X-Forwarded-For: status %d, want 429", burstLimit+1, last)
	}
}

func TestRateLimiter_BucketsBounded(t *testing.T) {
	tests := []struct {
		name        string
		maxPerShard int
		keys        int
	}{
		{name: "small cap flood", maxPerShard: 8, keys: 10000},
		{name: "default cap flood", maxPerShard: maxBucketsPerShard, keys: 200000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter()
			defer rl.Close()
			rl.maxPerShard = tt.maxPerShard

			for i := 0; i < tt.keys; i++ {
				rl.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), 1)
			}
			if got, max := rl.bucketCount(), numShards*tt.maxPerShard; got > max {
				t.Fatalf("bucketCount = %d after %d distinct keys, want <= %d", got, tt.keys, max)
			}
		})
	}
}

func TestRateLimiter_EvictsLeastRecentlySeen(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()
	rl.maxPerShard = 2

	// Find three keys that land in the same shard.
	var keys []string
	for i := 0; len(keys) < 3; i++ {
		k := fmt.Sprintf("10.0.0.%d", i)
		if len(keys) == 0 || shardFor(k) == shardFor(keys[0]) {
			keys = append(keys, k)
		}
	}
	rl.allow(keys[0], 1)
	rl.allow(keys[1], 1)
	rl.allow(keys[0], 1) // keys[0] is now most recently seen
	rl.allow(keys[2], 1) // evicts keys[1]

	sh := &rl.shards[shardFor(keys[0])]
	sh.mu.Lock()
	_, has0 := sh.buckets[keys[0]]
	_, has1 := sh.buckets[keys[1]]
	_, has2 := sh.buckets[keys[2]]
	sh.mu.Unlock()
	if !has0 || has1 || !has2 {
		t.Fatalf("after eviction: has[0]=%v has[1]=%v has[2]=%v, want true false true", has0, has1, has2)
	}
}

func TestRateLimiter_CleanupRemovesStale(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Close()
	for i := 0; i < 100; i++ {
		rl.allow(fmt.Sprintf("10.1.0.%d", i), 1)
	}
	rl.cleanup(time.Now())
	if got := rl.bucketCount(); got != 100 {
		t.Fatalf("fresh buckets removed: count = %d, want 100", got)
	}
	rl.cleanup(time.Now().Add(staleTimeout + time.Minute))
	if got := rl.bucketCount(); got != 0 {
		t.Fatalf("stale buckets kept: count = %d, want 0", got)
	}
}

func TestRateLimitMiddleware_Denials(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantID     string
	}{
		{name: "tools/call echoes numeric id", body: toolCallBody("7", "validate_sql"), wantStatus: http.StatusTooManyRequests, wantID: "7"},
		{name: "tools/call echoes string id", body: toolCallBody(`"req-abc"`, "validate_sql"), wantStatus: http.StatusTooManyRequests, wantID: `"req-abc"`},
		{name: "notification gets null id", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, wantStatus: http.StatusTooManyRequests, wantID: "null"},
		{name: "unparseable body gets null id", body: `{not json`, wantStatus: http.StatusTooManyRequests, wantID: "null"},
		{name: "initialize stays HTTP 200", body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, wantStatus: http.StatusOK, wantID: "1"},
		{name: "batched initialize stays HTTP 200", body: `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}]`, wantStatus: http.StatusOK, wantID: "null"},
		{name: "batch without initialize gets 429", body: "[" + toolCallBody("1", "validate_sql") + "]", wantStatus: http.StatusTooManyRequests, wantID: "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RateLimitMiddleware(okHandler)
			var rec *httptest.ResponseRecorder
			for i := 0; i <= burstLimit; i++ {
				req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tt.body))
				req.RemoteAddr = "10.9.9.9:1"
				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
			}
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("missing Retry-After header")
			}
			var resp struct {
				ID    json.RawMessage `json:"id"`
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if string(resp.ID) != tt.wantID {
				t.Errorf("id = %s, want %s", resp.ID, tt.wantID)
			}
			if resp.Error.Code != -32000 {
				t.Errorf("error code = %d, want -32000", resp.Error.Code)
			}
		})
	}
}

func TestRateLimitMiddleware_HeadersOnDenial(t *testing.T) {
	t.Run("burst denial reports sustained remaining", func(t *testing.T) {
		handler := RateLimitMiddleware(okHandler)
		var rec *httptest.ResponseRecorder
		for i := 0; i <= burstLimit; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolCallBody("1", "validate_sql")))
			req.RemoteAddr = "10.8.0.1:1"
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", rec.Code)
		}
		want := strconv.Itoa(sustainedLimit - burstLimit)
		if got := rec.Header().Get("X-RateLimit-Remaining"); got != want {
			t.Errorf("X-RateLimit-Remaining = %s, want %s", got, want)
		}
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Errorf("Retry-After = %s, want 1", got)
		}
	})
	t.Run("sustained denial waits for window reset", func(t *testing.T) {
		rl := NewRateLimiter()
		defer rl.Close()
		key := "10.8.0.2"
		// Exhaust the sustained budget without tripping the burst limiter.
		sh := &rl.shards[shardFor(key)]
		rl.allow(key, 1)
		sh.mu.Lock()
		b, _ := sh.buckets[key].Value.(*bucket)
		sh.mu.Unlock()
		b.mu.Lock()
		b.weightedCount = sustainedLimit
		b.mu.Unlock()

		d := rl.allow(key, 1)
		if d.allowed {
			t.Fatal("expected sustained denial")
		}
		if d.remaining != 0 {
			t.Errorf("remaining = %d, want 0", d.remaining)
		}
		if secs := retryAfterSeconds(d.retryAfter); secs < 50 || secs > 60 {
			t.Errorf("Retry-After = %ds, want ~60s", secs)
		}
	})
}

func TestRateLimitMiddleware_BodyLimits(t *testing.T) {
	tests := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{name: "at limit accepted", size: maxBodySize, wantStatus: http.StatusOK},
		{name: "over limit rejected with 413", size: maxBodySize + 1, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"`
			suffix := `"}}}`
			body := prefix + strings.Repeat("x", tt.size-len(prefix)-len(suffix)) + suffix
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			rec := httptest.NewRecorder()
			RateLimitMiddleware(okHandler).ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusRequestEntityTooLarge &&
				!strings.Contains(rec.Body.String(), "exceeds the 65536-byte") {
				t.Errorf("413 body does not explain the limit: %s", rec.Body.String())
			}
		})
	}
}

func TestRateLimitMiddleware_SlowBodyTimesOut(t *testing.T) {
	h, rl := newRateLimitHandler(nil, okHandler, 200*time.Millisecond)
	defer rl.Close()
	ts := httptest.NewServer(h)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled body within 5s: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", resp.StatusCode)
	}
}

func TestRateLimitMiddleware_ReadDeadlineClearedAfterBody(t *testing.T) {
	// A POST whose response streams for longer than the body read timeout
	// must not be cancelled by that deadline.
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
			http.Error(w, "cancelled", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("done"))
	})
	h, rl := newRateLimitHandler(nil, slow, 100*time.Millisecond)
	defer rl.Close()
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(toolCallBody("1", "validate_sql")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "done" {
		t.Fatalf("status %d body %q, want 200 done", resp.StatusCode, b)
	}
}

func TestRateLimitMiddleware_GETStreams(t *testing.T) {
	started := make(chan struct{}, 16)
	stream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		started <- struct{}{}
		<-r.Context().Done()
	})
	h, rl := newRateLimitHandler(nil, stream, time.Second)
	defer rl.Close()
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	open := func() *http.Response {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/mcp", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		return resp
	}

	var held []*http.Response
	for i := 0; i < maxStreamsPerIP; i++ {
		resp := open()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream %d: status %d, want 200", i+1, resp.StatusCode)
		}
		<-started
		held = append(held, resp)
	}
	if got := rl.activeReqs.Load(); got != 0 {
		t.Errorf("open GET streams counted as active requests: %d", got)
	}
	if got := currentLimit(rl); got != sustainedLimit {
		t.Errorf("open GET streams changed the sustained limit to %d", got)
	}

	extra := open()
	extra.Body.Close()
	if extra.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("stream %d: status %d, want 429", maxStreamsPerIP+1, extra.StatusCode)
	}

	// Closing a stream frees its slot.
	held[0].Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rl.streams.mu.Lock()
		n := rl.streams.open["127.0.0.1"]
		rl.streams.mu.Unlock()
		if n < maxStreamsPerIP || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp := open()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream after close: status %d, want 200", resp.StatusCode)
	}
	<-started
	resp.Body.Close()
	for _, r := range held[1:] {
		r.Body.Close()
	}
}

func TestReadRequestInfo(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantWeight int
		wantID     string
		wantMethod string
		wantInit   bool
	}{
		{name: "validate_sql", body: toolCallBody("1", "validate_sql"), wantWeight: 1, wantID: "1", wantMethod: "tools/call"},
		{name: "analyze_sql", body: toolCallBody("2", "analyze_sql"), wantWeight: 5, wantID: "2", wantMethod: "tools/call"},
		{name: "security_scan", body: toolCallBody(`"s"`, "security_scan"), wantWeight: 2, wantID: `"s"`, wantMethod: "tools/call"},
		{name: "initialize", body: `{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}`, wantWeight: 0, wantID: "4", wantMethod: "initialize", wantInit: true},
		{name: "tools/list", body: `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}`, wantWeight: 0, wantID: "5", wantMethod: "tools/list"},
		{name: "unknown tool", body: toolCallBody("6", "unknown_tool"), wantWeight: 1, wantID: "6", wantMethod: "tools/call"},
		{name: "null id", body: `{"jsonrpc":"2.0","id":null,"method":"ping"}`, wantWeight: 0, wantMethod: "ping"},
		{name: "batch sums weights", body: "[" + toolCallBody("1", "analyze_sql") + "," + toolCallBody("2", "lint_sql") + "]", wantWeight: 7},
		{name: "batched initialize", body: `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},{"jsonrpc":"2.0","method":"notifications/initialized"}]`, wantWeight: 0, wantInit: true},
		{name: "empty body", body: "", wantWeight: 0},
		{name: "invalid JSON costs minimum weight", body: `not json at all`, wantWeight: minUnparsedWeight},
		{name: "truncated object costs minimum weight", body: `{"jsonrpc":"2.0","method":"tools/call"`, wantWeight: minUnparsedWeight},
		{name: "non-object JSON costs minimum weight", body: `42`, wantWeight: minUnparsedWeight},
		{name: "whitespace-only body costs minimum weight", body: " \n\t", wantWeight: minUnparsedWeight},
		{name: "invalid batch costs minimum weight", body: `[{"method":`, wantWeight: minUnparsedWeight},
		{name: "empty batch costs minimum weight", body: `[]`, wantWeight: minUnparsedWeight},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", body)
			info, newReq, err := readRequestInfo(httptest.NewRecorder(), req)
			if err != nil {
				t.Fatalf("readRequestInfo: %v", err)
			}
			if info.weight != tt.wantWeight || string(info.id) != tt.wantID || info.method != tt.wantMethod || info.initialize != tt.wantInit {
				t.Errorf("got weight=%d id=%s method=%q initialize=%v, want weight=%d id=%s method=%q initialize=%v",
					info.weight, info.id, info.method, info.initialize, tt.wantWeight, tt.wantID, tt.wantMethod, tt.wantInit)
			}
			if tt.body != "" {
				rebuffered, err := io.ReadAll(newReq.Body)
				if err != nil {
					t.Fatalf("read re-buffered body: %v", err)
				}
				if !bytes.Equal(rebuffered, []byte(tt.body)) {
					t.Errorf("re-buffered body mismatch: got %q, want %q", rebuffered, tt.body)
				}
			}
		})
	}
}

func TestRateLimitMiddleware_RejectsUnreadableBody(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "transport error", err: errors.New("boom"), wantStatus: http.StatusBadRequest},
		{name: "timeout", err: os.ErrDeadlineExceeded, wantStatus: http.StatusRequestTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", iotest.ErrReader(tt.err))
			rec := httptest.NewRecorder()
			RateLimitMiddleware(okHandler).ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

// bucketCount reports how many client buckets are currently tracked.
func (rl *rateLimiter) bucketCount() int {
	n := 0
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

// weightedCount reports the sustained budget key has used in its window.
func (rl *rateLimiter) weightedCount(t *testing.T, key string) int {
	t.Helper()
	sh := &rl.shards[shardFor(key)]
	sh.mu.Lock()
	el, ok := sh.buckets[key]
	sh.mu.Unlock()
	if !ok {
		return 0
	}
	b, ok := el.Value.(*bucket)
	if !ok {
		t.Fatalf("bucket for %s has type %T", key, el.Value)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.weightedCount
}

// openStreams reports how many GET stream slots key holds.
func (rl *rateLimiter) openStreams(key string) int {
	rl.streams.mu.Lock()
	defer rl.streams.mu.Unlock()
	return rl.streams.open[key]
}

// discardLogs stops rl from writing warnings to the test output.
func discardLogs(rl *rateLimiter) { rl.logf = func(string, ...any) {} }

func TestRateLimitMiddleware_StreamCapRejectionIsFree(t *testing.T) {
	started := make(chan struct{}, 16)
	stream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	h, rl := newRateLimitHandler(nil, stream, time.Second)
	defer rl.Close()
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	get := func() *http.Response {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/mcp", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		return resp
	}

	for i := 0; i < maxStreamsPerIP; i++ {
		resp := get()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream %d: status %d, want 200", i+1, resp.StatusCode)
		}
		<-started
	}
	const key = "127.0.0.1"
	if got := rl.weightedCount(t, key); got != maxStreamsPerIP*streamWeight {
		t.Fatalf("after %d streams weightedCount = %d, want %d", maxStreamsPerIP, got, maxStreamsPerIP*streamWeight)
	}

	// More refused GETs than the burst limit allows: none may cost budget.
	for i := 0; i < 2*burstLimit; i++ {
		resp := get()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "Too many open streams") {
			t.Fatalf("refused GET %d: status %d body %q, want 429 stream-cap error", i+1, resp.StatusCode, body)
		}
	}
	if got := rl.weightedCount(t, key); got != maxStreamsPerIP*streamWeight {
		t.Errorf("stream-cap rejections were charged: weightedCount = %d, want %d", got, maxStreamsPerIP*streamWeight)
	}

	// The client can still make tool calls with its full remaining budget.
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(toolCallBody("1", "validate_sql")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST after refused GETs: status %d, want 200", resp.StatusCode)
	}
	want := strconv.Itoa(sustainedLimit - maxStreamsPerIP*streamWeight - 1)
	if got := resp.Header.Get("X-RateLimit-Remaining"); got != want {
		t.Errorf("X-RateLimit-Remaining = %s, want %s", got, want)
	}
}

func TestRateLimitMiddleware_RateLimitedGETReleasesStreamSlot(t *testing.T) {
	h, rl := newRateLimitHandler(nil, okHandler, time.Second)
	defer rl.Close()
	discardLogs(rl)
	const key = "10.7.0.1"
	rl.allow(key, 1)
	sh := &rl.shards[shardFor(key)]
	sh.mu.Lock()
	b, _ := sh.buckets[key].Value.(*bucket)
	sh.mu.Unlock()
	b.mu.Lock()
	b.weightedCount = sustainedLimit
	b.mu.Unlock()

	for i := 0; i < maxStreamsPerIP+1; i++ {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.RemoteAddr = key + ":1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Rate limit exceeded") {
			t.Fatalf("GET %d: status %d body %q, want 429 rate-limit error", i+1, rec.Code, rec.Body.String())
		}
	}
	if got := rl.openStreams(key); got != 0 {
		t.Fatalf("rate-limited GETs kept %d stream slots, want 0", got)
	}
}

func TestRateLimitMiddleware_ReadDeadlineErrors(t *testing.T) {
	t.Run("unsupported writer is logged once and counted", func(t *testing.T) {
		h, rl := newRateLimitHandler(nil, okHandler, time.Second)
		defer rl.Close()
		var logs []string
		var mu sync.Mutex
		rl.logf = func(format string, v ...any) {
			mu.Lock()
			defer mu.Unlock()
			logs = append(logs, fmt.Sprintf(format, v...))
		}

		const sessionID = "mcp-session-0b5e7c1a-1111-2222-3333-444455556666"
		const sqlMarker = "SELECT secret_marker_column"
		for i := 0; i < 3; i++ {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"` + sqlMarker + `"}}}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.RemoteAddr = "10.6.0.1:1"
			req.Header.Set("Mcp-Session-Id", sessionID)
			rec := httptest.NewRecorder() // does not support read deadlines
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("request %d: status %d, want 200", i+1, rec.Code)
			}
		}
		// Each request fails to set and to clear the deadline.
		if got := rl.deadlineErrs.Load(); got != 6 {
			t.Errorf("deadlineErrs = %d, want 6", got)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(logs) != 1 {
			t.Fatalf("logged %d warnings, want exactly 1: %q", len(logs), logs)
		}
		if !strings.Contains(logs[0], "does not support read deadlines") {
			t.Errorf("warning does not explain the problem: %q", logs[0])
		}
		for _, secret := range []string{sessionID, "mcp-session-", sqlMarker, "10.6.0.1"} {
			if strings.Contains(logs[0], secret) {
				t.Errorf("warning leaks %q: %q", secret, logs[0])
			}
		}
	})
	t.Run("other errors log only the error type", func(t *testing.T) {
		rl := NewRateLimiter()
		defer rl.Close()
		var logs []string
		rl.logf = func(format string, v ...any) { logs = append(logs, fmt.Sprintf(format, v...)) }
		rl.noteDeadlineErr(nil)
		if rl.deadlineErrs.Load() != 0 || len(logs) != 0 {
			t.Fatalf("nil error was recorded: count=%d logs=%q", rl.deadlineErrs.Load(), logs)
		}
		rl.noteDeadlineErr(&net.OpError{Op: "set", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 443}, Err: errors.New("use of closed network connection")})
		rl.noteDeadlineErr(errors.New("again"))
		if got := rl.deadlineErrs.Load(); got != 2 {
			t.Errorf("deadlineErrs = %d, want 2", got)
		}
		if len(logs) != 1 {
			t.Fatalf("logged %d warnings, want 1: %q", len(logs), logs)
		}
		if strings.Contains(logs[0], "192.0.2.44") || !strings.Contains(logs[0], "*net.OpError") {
			t.Errorf("warning = %q, want the error type without its address", logs[0])
		}
	})
	t.Run("real connection has no deadline errors", func(t *testing.T) {
		h, rl := newRateLimitHandler(nil, okHandler, time.Second)
		defer rl.Close()
		ts := httptest.NewServer(h)
		defer ts.Close()
		resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(toolCallBody("1", "validate_sql")))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if got := rl.deadlineErrs.Load(); got != 0 {
			t.Errorf("deadlineErrs = %d, want 0", got)
		}
	})
}

func TestRateLimitMiddleware_UnparseableBodyCostsBudget(t *testing.T) {
	h, rl := newRateLimitHandler(nil, okHandler, time.Second)
	defer rl.Close()
	discardLogs(rl)
	const key = "10.5.0.1"
	for _, body := range []string{`{not json`, `[]`, `[{"method":`} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.RemoteAddr = key + ":1"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := rl.weightedCount(t, key); got != 3*minUnparsedWeight {
		t.Fatalf("weightedCount = %d, want %d", got, 3*minUnparsedWeight)
	}
	// A body-less request (e.g. DELETE to end a session) stays free.
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.RemoteAddr = key + ":1"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got := rl.weightedCount(t, key); got != 3*minUnparsedWeight {
		t.Fatalf("DELETE was charged: weightedCount = %d, want %d", got, 3*minUnparsedWeight)
	}
}

const testProxySecret = "s3cret-0123456789abcdef"

func TestClientKey_ProxySecret(t *testing.T) {
	gated := &Config{TrustedProxyHeader: "Cf-Connecting-Ip", TrustedProxySecretHeader: "X-Origin-Secret", TrustedProxySecret: testProxySecret}
	gatedHops := &Config{TrustedProxyHops: 1, TrustedProxySecretHeader: "X-Origin-Secret", TrustedProxySecret: testProxySecret}
	tests := []struct {
		name    string
		cfg     *Config
		secrets []string
		want    string
	}{
		{name: "matching secret trusts header", cfg: gated, secrets: []string{testProxySecret}, want: "203.0.113.9"},
		{name: "missing secret falls back", cfg: gated, want: "10.0.0.1"},
		{name: "wrong secret falls back", cfg: gated, secrets: []string{"s3cret-0123456789abcdeX"}, want: "10.0.0.1"},
		{name: "secret prefix falls back", cfg: gated, secrets: []string{testProxySecret[:8]}, want: "10.0.0.1"},
		{name: "secret with suffix falls back", cfg: gated, secrets: []string{testProxySecret + "x"}, want: "10.0.0.1"},
		{name: "empty secret falls back", cfg: gated, secrets: []string{""}, want: "10.0.0.1"},
		{name: "last value is the proxy's", cfg: gated, secrets: []string{"forged", testProxySecret}, want: "203.0.113.9"},
		{name: "forged last value falls back", cfg: gated, secrets: []string{testProxySecret, "forged"}, want: "10.0.0.1"},
		{name: "matching secret trusts XFF hops", cfg: gatedHops, secrets: []string{testProxySecret}, want: "198.51.100.4"},
		{name: "missing secret ignores XFF hops", cfg: gatedHops, want: "10.0.0.1"},
		{name: "secret header without secret never trusts", cfg: &Config{TrustedProxyHeader: "Cf-Connecting-Ip", TrustedProxySecretHeader: "X-Origin-Secret"}, secrets: []string{""}, want: "10.0.0.1"},
		{name: "secret without header never trusts", cfg: &Config{TrustedProxyHeader: "Cf-Connecting-Ip", TrustedProxySecret: testProxySecret}, want: "10.0.0.1"},
		{name: "no secret configured keeps old behaviour", cfg: &Config{TrustedProxyHeader: "Cf-Connecting-Ip"}, want: "203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			req.Header.Set("CF-Connecting-IP", "203.0.113.9")
			req.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.4")
			for _, v := range tt.secrets {
				req.Header.Add("X-Origin-Secret", v)
			}
			if got := newClientIPResolver(tt.cfg).clientKey(req); got != tt.want {
				t.Errorf("clientKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitMiddleware_ProxySecret(t *testing.T) {
	cfg := &Config{TrustedProxyHeader: "Cf-Connecting-Ip", TrustedProxySecretHeader: "X-Origin-Secret", TrustedProxySecret: testProxySecret}
	var seen []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Origin-Secret"))
		w.WriteHeader(http.StatusOK)
	})
	h, rl := newRateLimitHandler(cfg, next, time.Second)
	defer rl.Close()
	discardLogs(rl)

	send := func(cfIP, secret string) int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolCallBody("1", "validate_sql")))
		req.RemoteAddr = "10.4.0.1:1"
		req.Header.Set("CF-Connecting-IP", cfIP)
		if secret != "" {
			req.Header.Set("X-Origin-Secret", secret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Without the secret, rotating CF-Connecting-IP does not escape the
	// RemoteAddr bucket.
	last := 0
	for i := 0; i <= burstLimit; i++ {
		last = send(fmt.Sprintf("11.0.%d.1", i), "")
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("rotating CF-Connecting-IP without the secret: status %d, want 429", last)
	}
	// With the secret, each forwarded client gets its own bucket.
	for i := 0; i <= burstLimit; i++ {
		if code := send(fmt.Sprintf("12.0.%d.1", i), testProxySecret); code != http.StatusOK {
			t.Fatalf("client %d with the secret: status %d, want 200", i, code)
		}
	}
	for _, v := range seen {
		if v != "" {
			t.Fatalf("secret header reached the MCP handler: %q", v)
		}
	}
}
