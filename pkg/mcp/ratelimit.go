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
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// toolWeights defines the cost weight for each MCP tool.
// Higher-cost operations consume more of the per-IP budget.
var toolWeights = map[string]int{
	"validate_sql":     1,
	"format_sql":       1,
	"parse_sql":        1,
	"extract_metadata": 2,
	"security_scan":    2,
	"lint_sql":         2,
	"analyze_sql":      5,
}

const (
	burstLimit      = 10               // max requests per second per IP
	sustainedLimit  = 120              // max weighted requests per minute per IP (normal load)
	elevatedLimit   = 60               // under elevated load
	criticalLimit   = 30               // under critical load
	elevatedThresh  = 50               // active requests threshold for elevated
	criticalThresh  = 80               // active requests threshold for critical
	numShards       = 16               // number of shards for concurrent map access
	cleanupInterval = 5 * time.Minute  // how often to run stale entry cleanup
	staleTimeout    = 10 * time.Minute // idle time before an entry is removed
	maxBodySize     = 64 * 1024        // 64KB max request body size
)

// bucket tracks rate limit state for a single IP address.
type bucket struct {
	mu            sync.Mutex
	burstTokens   float64
	lastBurst     time.Time
	weightedCount int
	windowStart   time.Time
	lastSeen      time.Time
}

// shard is one segment of the sharded map, holding its own lock and bucket map.
type shard struct {
	sync.RWMutex
	buckets map[string]*bucket
}

// rateLimiter implements a three-layer rate limiting strategy:
// per-IP burst limiting, tool-weighted sustained limiting, and adaptive load scaling.
type rateLimiter struct {
	shards      [numShards]shard
	activeReqs  atomic.Int64
	stopCleanup chan struct{}
}

// NewRateLimiter creates a new rateLimiter, initializes all shards,
// and starts the background cleanup goroutine.
func NewRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		stopCleanup: make(chan struct{}),
	}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*bucket)
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background cleanup goroutine.
func (rl *rateLimiter) Close() {
	close(rl.stopCleanup)
}

// shardFor returns the shard index for the given IP using FNV hashing.
func shardFor(ip string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return int(h.Sum32() % numShards)
}

// currentLimit returns the sustained limit based on the current number of
// active concurrent requests, implementing adaptive load scaling.
func currentLimit(rl *rateLimiter) int {
	active := rl.activeReqs.Load()
	switch {
	case active > criticalThresh:
		return criticalLimit
	case active > elevatedThresh:
		return elevatedLimit
	default:
		return sustainedLimit
	}
}

// allow checks whether a request from the given IP with the given weight
// should be permitted. It returns:
//   - allowed: whether the request is permitted
//   - limit: the current sustained limit
//   - remaining: how many weighted units remain in the window
//   - resetTime: when the current window resets
func (rl *rateLimiter) allow(ip string, weight int) (bool, int, int, time.Time) {
	idx := shardFor(ip)
	sh := &rl.shards[idx]

	now := time.Now()
	limit := currentLimit(rl)

	sh.Lock()
	b, ok := sh.buckets[ip]
	if !ok {
		b = &bucket{
			burstTokens: float64(burstLimit),
			lastBurst:   now,
			windowStart: now,
			lastSeen:    now,
		}
		sh.buckets[ip] = b
	}
	sh.Unlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastSeen = now

	// --- Layer 1: Burst check (token bucket) ---
	elapsed := now.Sub(b.lastBurst).Seconds()
	b.burstTokens += elapsed * float64(burstLimit) // refill at burstLimit tokens/sec
	if b.burstTokens > float64(burstLimit) {
		b.burstTokens = float64(burstLimit)
	}
	b.lastBurst = now

	if b.burstTokens < 1.0 {
		resetTime := now.Add(time.Duration((1.0-b.burstTokens)/float64(burstLimit)*1000) * time.Millisecond)
		return false, limit, 0, resetTime
	}

	// Weight-0 requests (initialize, list_tools) bypass sustained limiting.
	if weight == 0 {
		b.burstTokens -= 1.0
		remaining := limit - b.weightedCount
		if remaining < 0 {
			remaining = 0
		}
		resetTime := b.windowStart.Add(time.Minute)
		return true, limit, remaining, resetTime
	}

	// --- Layer 2: Sustained weighted check ---
	// Reset window if a minute has passed.
	if now.Sub(b.windowStart) >= time.Minute {
		b.weightedCount = 0
		b.windowStart = now
	}

	resetTime := b.windowStart.Add(time.Minute)

	if b.weightedCount+weight > limit {
		remaining := limit - b.weightedCount
		if remaining < 0 {
			remaining = 0
		}
		return false, limit, remaining, resetTime
	}

	// Allowed: consume tokens.
	b.burstTokens -= 1.0
	b.weightedCount += weight

	remaining := limit - b.weightedCount
	if remaining < 0 {
		remaining = 0
	}
	return true, limit, remaining, resetTime
}

// cleanupLoop periodically removes entries that have been idle for longer
// than staleTimeout.
func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCleanup:
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes stale bucket entries from all shards.
func (rl *rateLimiter) cleanup() {
	now := time.Now()
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.Lock()
		for ip, b := range sh.buckets {
			b.mu.Lock()
			if now.Sub(b.lastSeen) > staleTimeout {
				delete(sh.buckets, ip)
			}
			b.mu.Unlock()
		}
		sh.Unlock()
	}
}

// extractIP extracts the client IP address from the request.
// It checks X-Forwarded-For first (taking the first IP in the list),
// then falls back to RemoteAddr.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// jsonRPCRequest is used to partially decode a JSON-RPC request to extract
// the method and tool name.
type jsonRPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// toolCallParams holds the params.name field from a tools/call request.
type toolCallParams struct {
	Name string `json:"name"`
}

// extractToolWeight reads the request body to determine the tool weight.
// It re-buffers the body so downstream handlers can read it again.
// Returns the weight (0 for non-tool requests) and the modified request.
func extractToolWeight(r *http.Request) (int, *http.Request) {
	if r.Body == nil {
		return 0, r
	}

	limited := http.MaxBytesReader(nil, r.Body, maxBodySize)
	body, err := io.ReadAll(limited)
	if err != nil {
		// On read error (e.g., body too large), re-buffer what we got
		// and treat as weight 1 (default cost).
		r.Body = io.NopCloser(bytes.NewReader(body))
		return 1, r
	}

	// Re-buffer the body for downstream handlers.
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, r
	}

	if req.Method != "tools/call" {
		return 0, r
	}

	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return 1, r
	}

	if w, ok := toolWeights[params.Name]; ok {
		return w, r
	}
	return 1, r
}

// RateLimitMiddleware creates a rate limiter and returns an http.Handler
// that enforces the three-layer rate limiting strategy. Requests that exceed
// limits receive an HTTP 200 response with a JSON-RPC error (MCP clients
// expect JSON-RPC responses, not HTTP 429).
func RateLimitMiddleware(next http.Handler) http.Handler {
	rl := NewRateLimiter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		weight, r := extractToolWeight(r)

		rl.activeReqs.Add(1)
		defer rl.activeReqs.Add(-1)

		allowed, limit, remaining, resetTime := rl.allow(ip, weight)

		// Always set rate limit headers.
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

		if !allowed {
			retryAfter := time.Until(resetTime).Seconds()
			if retryAfter < 1 {
				retryAfter = 1
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Rate limit exceeded. Try again in %.0f seconds."}}`,
				retryAfter,
			)
			_, _ = w.Write([]byte(resp))
			return
		}

		next.ServeHTTP(w, r)
	})
}
