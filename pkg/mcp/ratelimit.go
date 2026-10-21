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
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
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

	// maxBucketsPerShard caps how many clients each shard tracks. When a shard
	// is full the least-recently-seen client is evicted, so memory stays bounded
	// (numShards*maxBucketsPerShard buckets) no matter how many distinct
	// addresses send traffic.
	maxBucketsPerShard = 4096

	// maxStreamsPerIP caps concurrent GET (SSE) streams from one client.
	maxStreamsPerIP = 4
	// streamWeight is the sustained-budget cost of opening a GET stream.
	streamWeight = 1

	// bodyReadTimeout bounds how long a client may take to send a request
	// body, so slow-body (slowloris) connections cannot be held open forever.
	bodyReadTimeout = 30 * time.Second

	// maxBodySize is the largest accepted request body. analyze_sql on 64KB of
	// SQL allocates ~33MB; 1MB of SQL allocates ~530MB, more than the 512MB
	// hosted instance has, so the limit is kept at 64KB.
	maxBodySize = 64 * 1024
)

// bucket tracks rate limit state for a single client key.
type bucket struct {
	key string

	// lastSeen is guarded by the owning shard's mutex.
	lastSeen time.Time

	mu            sync.Mutex
	burstTokens   float64
	lastBurst     time.Time
	weightedCount int
	windowStart   time.Time
}

// shard is one segment of the sharded map, holding its own lock, bucket map
// and an LRU list (front = most recently seen) used for eviction and cleanup.
type shard struct {
	mu      sync.Mutex
	buckets map[string]*list.Element
	lru     *list.List
}

// streamCounter tracks open GET streams per client key. Entries are removed
// when their count drops to zero, so its size is bounded by open connections.
type streamCounter struct {
	mu   sync.Mutex
	open map[string]int
}

// acquire reserves a stream slot for key, reporting false when key already
// holds max streams.
func (s *streamCounter) acquire(key string, max int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open[key] >= max {
		return false
	}
	s.open[key]++
	return true
}

// release frees a slot reserved by acquire.
func (s *streamCounter) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open[key] <= 1 {
		delete(s.open, key)
		return
	}
	s.open[key]--
}

// rateLimiter implements a three-layer rate limiting strategy:
// per-IP burst limiting, tool-weighted sustained limiting, and adaptive load scaling.
type rateLimiter struct {
	shards      [numShards]shard
	maxPerShard int
	activeReqs  atomic.Int64
	streams     streamCounter
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

// NewRateLimiter creates a new rateLimiter, initializes all shards,
// and starts the background cleanup goroutine.
func NewRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		maxPerShard: maxBucketsPerShard,
		streams:     streamCounter{open: make(map[string]int)},
		stopCleanup: make(chan struct{}),
	}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*list.Element)
		rl.shards[i].lru = list.New()
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background cleanup goroutine. It is safe to call more than once.
func (rl *rateLimiter) Close() {
	rl.closeOnce.Do(func() { close(rl.stopCleanup) })
}

// shardFor returns the shard index for the given key using FNV hashing.
func shardFor(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
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

// bucketFor returns the bucket for key, creating it (and evicting the
// least-recently-seen bucket when the shard is full) if needed.
func (rl *rateLimiter) bucketFor(key string, now time.Time) *bucket {
	sh := &rl.shards[shardFor(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if el, ok := sh.buckets[key]; ok {
		b, _ := el.Value.(*bucket)
		b.lastSeen = now
		sh.lru.MoveToFront(el)
		return b
	}

	for sh.lru.Len() >= rl.maxPerShard {
		oldest := sh.lru.Back()
		if oldest == nil {
			break
		}
		if old, ok := oldest.Value.(*bucket); ok {
			delete(sh.buckets, old.key)
		}
		sh.lru.Remove(oldest)
	}

	b := &bucket{
		key:         key,
		lastSeen:    now,
		burstTokens: float64(burstLimit),
		lastBurst:   now,
		windowStart: now,
	}
	sh.buckets[key] = sh.lru.PushFront(b)
	return b
}

// decision is the outcome of a rate-limit check.
type decision struct {
	allowed bool
	// limit is the current sustained limit (weighted requests per minute).
	limit int
	// remaining is the unused sustained budget in the current window.
	remaining int
	// reset is when the current sustained window ends.
	reset time.Time
	// retryAfter is how long a denied client should wait; zero when allowed.
	retryAfter time.Duration
}

// allow checks whether a request from the given client key with the given
// weight should be permitted, consuming budget when it is.
func (rl *rateLimiter) allow(key string, weight int) decision {
	now := time.Now()
	limit := currentLimit(rl)
	b := rl.bucketFor(key, now)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset the sustained window if a minute has passed.
	if now.Sub(b.windowStart) >= time.Minute {
		b.weightedCount = 0
		b.windowStart = now
	}
	d := decision{limit: limit, reset: b.windowStart.Add(time.Minute)}
	remaining := func() int {
		if r := limit - b.weightedCount; r > 0 {
			return r
		}
		return 0
	}

	// --- Layer 1: Burst check (token bucket) ---
	elapsed := now.Sub(b.lastBurst).Seconds()
	b.burstTokens += elapsed * float64(burstLimit) // refill at burstLimit tokens/sec
	if b.burstTokens > float64(burstLimit) {
		b.burstTokens = float64(burstLimit)
	}
	b.lastBurst = now

	if b.burstTokens < 1.0 {
		d.remaining = remaining()
		d.retryAfter = time.Duration((1.0 - b.burstTokens) / float64(burstLimit) * float64(time.Second))
		return d
	}

	// --- Layer 2: Sustained weighted check ---
	// Weight-0 requests (initialize, tools/list) bypass sustained limiting.
	if weight > 0 && b.weightedCount+weight > limit {
		d.remaining = remaining()
		d.retryAfter = d.reset.Sub(now)
		return d
	}

	// Allowed: consume tokens.
	b.burstTokens -= 1.0
	b.weightedCount += weight
	d.allowed = true
	d.remaining = remaining()
	return d
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
			rl.cleanup(time.Now())
		}
	}
}

// cleanup removes buckets not seen since now-staleTimeout. Each shard's LRU
// list is ordered by lastSeen, so only the stale tail is visited.
func (rl *rateLimiter) cleanup(now time.Time) {
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for el := sh.lru.Back(); el != nil; {
			b, ok := el.Value.(*bucket)
			if ok && now.Sub(b.lastSeen) <= staleTimeout {
				break
			}
			prev := el.Prev()
			if ok {
				delete(sh.buckets, b.key)
			}
			sh.lru.Remove(el)
			el = prev
		}
		sh.mu.Unlock()
	}
}

// clientIPResolver derives the rate-limit key for a request. By default it
// uses the TCP peer address only; forwarding headers are client-controlled
// and are honoured only when the operator opts in via Config.
type clientIPResolver struct {
	// header, when set, is a single-IP header written by a trusted proxy
	// (e.g. CF-Connecting-IP).
	header string
	// hops, when > 0, is the number of trusted proxies that append to
	// X-Forwarded-For; the client is the hops-th entry from the right.
	hops int
}

// newClientIPResolver builds a resolver from cfg (nil means RemoteAddr only).
func newClientIPResolver(cfg *Config) clientIPResolver {
	if cfg == nil {
		return clientIPResolver{}
	}
	return clientIPResolver{header: cfg.TrustedProxyHeader, hops: cfg.TrustedProxyHops}
}

// clientKey returns the normalised client address for r. Invalid or missing
// forwarded values fall back to RemoteAddr.
func (c clientIPResolver) clientKey(r *http.Request) string {
	if c.header != "" {
		if vals := r.Header.Values(c.header); len(vals) > 0 {
			// The trusted proxy's value is the last one it wrote.
			entries := splitList(vals[len(vals)-1])
			if len(entries) > 0 {
				if key, ok := normalizeIP(entries[len(entries)-1]); ok {
					return key
				}
			}
		}
	}
	if c.hops > 0 {
		var entries []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			entries = append(entries, splitList(v)...)
		}
		if len(entries) >= c.hops {
			if key, ok := normalizeIP(entries[len(entries)-c.hops]); ok {
				return key
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if key, ok := normalizeIP(host); ok {
		return key
	}
	return host
}

// splitList splits a comma-separated header value into trimmed, non-empty entries.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ipv6KeyMask groups IPv6 clients by /64, the smallest prefix normally
// assigned to one subscriber, so rotating addresses inside it does not
// yield fresh budgets.
var ipv6KeyMask = net.CIDRMask(64, 128)

// normalizeIP parses s (optionally with a port or brackets) and returns its
// canonical rate-limit key: the dotted IPv4 address, or the IPv6 /64 prefix.
func normalizeIP(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			return "", false
		}
		if ip = net.ParseIP(host); ip == nil {
			return "", false
		}
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.Mask(ipv6KeyMask).String() + "/64", true
}

// jsonRPCRequest is used to partially decode a JSON-RPC request to extract
// the id, method and tool name.
type jsonRPCRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// toolCallParams holds the params.name field from a tools/call request.
type toolCallParams struct {
	Name string `json:"name"`
}

// requestInfo is what the rate limiter needs to know about a JSON-RPC body.
type requestInfo struct {
	// weight is the sustained-budget cost (0 for non-tool requests).
	weight int
	// id is the JSON-RPC id to echo in an error, or nil when unknown.
	id json.RawMessage
	// method is the JSON-RPC method of a single (non-batch) request.
	method string
}

// weightOf returns the cost of one decoded JSON-RPC message.
func weightOf(req jsonRPCRequest) int {
	if req.Method != "tools/call" {
		return 0
	}
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return 1
	}
	if w, ok := toolWeights[params.Name]; ok {
		return w
	}
	return 1
}

// readRequestInfo reads the request body (at most maxBodySize bytes) to
// determine its weight and JSON-RPC id, then re-buffers it so downstream
// handlers can read it again. A non-nil error means the body could not be
// read in full (too large, too slow, or a transport error) and the request
// must be rejected.
func readRequestInfo(w http.ResponseWriter, r *http.Request) (requestInfo, *http.Request, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return requestInfo{}, r, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		return requestInfo{}, r, fmt.Errorf("read request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// JSON-RPC batch: charge for every message in it.
		var batch []jsonRPCRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return requestInfo{}, r, nil
		}
		info := requestInfo{}
		for _, m := range batch {
			info.weight += weightOf(m)
		}
		return info, r, nil
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return requestInfo{}, r, nil
	}
	info := requestInfo{weight: weightOf(req), method: req.Method}
	if len(req.ID) > 0 && !bytes.Equal(req.ID, []byte("null")) {
		info.id = req.ID
	}
	return info, r, nil
}

// writeJSONRPCError writes a JSON-RPC error response with the given HTTP status.
func writeJSONRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Error: struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: code, Message: msg},
	})
	if err != nil {
		http.Error(w, msg, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

// writeBodyError rejects a request whose body could not be read.
func writeBodyError(w http.ResponseWriter, err error, readTimeout time.Duration) {
	var tooLarge *http.MaxBytesError
	var netErr net.Error
	switch {
	case errors.As(err, &tooLarge):
		writeJSONRPCError(w, http.StatusRequestEntityTooLarge, nil, -32600,
			fmt.Sprintf("Request body exceeds the %d-byte (%d KB) limit.", maxBodySize, maxBodySize/1024))
	case errors.As(err, &netErr) && netErr.Timeout():
		writeJSONRPCError(w, http.StatusRequestTimeout, nil, -32600,
			fmt.Sprintf("Request body was not received within %s.", readTimeout))
	default:
		writeJSONRPCError(w, http.StatusBadRequest, nil, -32600, "Request body could not be read.")
	}
}

// retryAfterSeconds rounds d up to whole seconds, with a minimum of 1.
func retryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		return 1
	}
	return s
}

// RateLimitMiddleware is NewRateLimitMiddleware with the default
// configuration: clients are keyed by their TCP peer address only.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return NewRateLimitMiddleware(nil, next)
}

// NewRateLimitMiddleware creates a rate limiter and returns an http.Handler
// that enforces the three-layer rate limiting strategy. Clients are keyed by
// RemoteAddr unless cfg names a trusted proxy header or hop count.
//
// Denied requests get HTTP 429 with Retry-After and a JSON-RPC error that
// echoes the request id. A denied initialize gets HTTP 200 instead, because
// mcp-go clients treat any 4xx on initialize as "legacy SSE server".
// POST bodies must arrive within bodyReadTimeout and fit in maxBodySize.
// GET (SSE) streams are capped per client and excluded from the load metric,
// since they stay open for the life of the session.
func NewRateLimitMiddleware(cfg *Config, next http.Handler) http.Handler {
	h, _ := newRateLimitHandler(cfg, next, bodyReadTimeout)
	return h
}

// newRateLimitHandler is NewRateLimitMiddleware with a configurable body
// read timeout; it also returns the limiter so tests can inspect it.
func newRateLimitHandler(cfg *Config, next http.Handler, readTimeout time.Duration) (http.Handler, *rateLimiter) {
	rl := NewRateLimiter()
	resolver := newClientIPResolver(cfg)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := resolver.clientKey(r)
		isStream := r.Method == http.MethodGet

		var info requestInfo
		if isStream {
			info.weight = streamWeight
		} else {
			// Bound the body read. On success clear the deadline so a
			// streamed (SSE) POST response is not cut off by it; on failure
			// keep it, so net/http's drain of the unread body cannot block.
			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Now().Add(readTimeout))
			var err error
			info, r, err = readRequestInfo(w, r)
			if err != nil {
				writeBodyError(w, err, readTimeout)
				return
			}
			_ = rc.SetReadDeadline(time.Time{})
			rl.activeReqs.Add(1)
			defer rl.activeReqs.Add(-1)
		}

		d := rl.allow(key, info.weight)

		h := w.Header()
		h.Set("X-RateLimit-Limit", strconv.Itoa(d.limit))
		h.Set("X-RateLimit-Remaining", strconv.Itoa(d.remaining))
		h.Set("X-RateLimit-Reset", strconv.FormatInt(d.reset.Unix(), 10))

		if !d.allowed {
			secs := retryAfterSeconds(d.retryAfter)
			h.Set("Retry-After", strconv.Itoa(secs))
			status := http.StatusTooManyRequests
			if info.method == "initialize" {
				status = http.StatusOK
			}
			writeJSONRPCError(w, status, info.id, -32000,
				fmt.Sprintf("Rate limit exceeded. Try again in %d seconds.", secs))
			return
		}

		if isStream {
			if !rl.streams.acquire(key, maxStreamsPerIP) {
				h.Set("Retry-After", "60")
				writeJSONRPCError(w, http.StatusTooManyRequests, nil, -32000,
					fmt.Sprintf("Too many open streams: at most %d concurrent GET streams per client.", maxStreamsPerIP))
				return
			}
			defer rl.streams.release(key)
		}

		next.ServeHTTP(w, r)
	}), rl
}
