// Package monitor provides performance monitoring and metrics collection for GoSQLX
package monitor

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSnapshot represents a point-in-time snapshot of performance metrics.
//
// This structure contains all metric data without internal locks, making it
// safe to pass between goroutines and serialize for monitoring systems.
//
// Use GetMetrics() to obtain a snapshot of current metrics.
//
// Example:
//
//	metrics := monitor.GetMetrics()
//	fmt.Printf("Tokenizer calls: %d\n", metrics.TokenizerCalls)
//	fmt.Printf("Pool reuse: %.1f%%\n", metrics.PoolReuse)
type MetricsSnapshot struct {
	// TokenizerCalls is the total number of tokenization operations performed
	TokenizerCalls int64

	// TokenizerDuration is the cumulative time spent in tokenization
	TokenizerDuration time.Duration

	// TokensProcessed is the total number of tokens generated
	TokensProcessed int64

	// TokenizerErrors is the total number of tokenization failures
	TokenizerErrors int64

	// ParserCalls is the total number of parse operations performed
	ParserCalls int64

	// ParserDuration is the cumulative time spent in parsing
	ParserDuration time.Duration

	// StatementsProcessed is the total number of SQL statements successfully parsed
	StatementsProcessed int64

	// ParserErrors is the total number of parse failures
	ParserErrors int64

	// PoolHits is the number of successful pool retrievals (object reused from pool)
	PoolHits int64

	// PoolMisses is the number of pool misses (new allocation required)
	PoolMisses int64

	// PoolReuse is the pool reuse percentage (0-100)
	PoolReuse float64

	// AllocBytes is the current memory allocation in bytes (currently unused)
	AllocBytes uint64

	// TotalAllocs is the total number of allocations (currently unused)
	TotalAllocs uint64

	// LastGCPause is the duration of the last garbage collection pause (currently unused)
	LastGCPause time.Duration

	// StartTime is when metrics collection started or was last reset
	StartTime time.Time
}

// Metrics holds performance metrics for the tokenizer and parser with thread-safe access.
//
// This is the internal metrics structure protected by a read-write mutex.
// Do not access this directly; use the global functions (Enable, Disable,
// RecordTokenizerCall, RecordParserCall, etc.) instead.
//
// The mutex ensures safe concurrent access from multiple goroutines.
// All metric fields use atomic operations or are protected by the mutex.
type Metrics struct {
	mu sync.RWMutex // Protects concurrent access to non-atomic fields

	// Tokenizer metrics
	TokenizerCalls    int64         // Total tokenization operations (atomic)
	TokenizerDuration time.Duration // Cumulative tokenization time
	TokensProcessed   int64         // Total tokens generated (atomic)
	TokenizerErrors   int64         // Total tokenization errors (atomic)

	// Parser metrics
	ParserCalls         int64         // Total parse operations (atomic)
	ParserDuration      time.Duration // Cumulative parse time
	StatementsProcessed int64         // Total statements parsed (atomic)
	ParserErrors        int64         // Total parse errors (atomic)

	// Pool metrics
	PoolHits   int64   // Pool retrieval hits (atomic)
	PoolMisses int64   // Pool retrieval misses (atomic)
	PoolReuse  float64 // Pool reuse percentage (calculated)

	// Memory metrics (currently unused - reserved for future use)
	AllocBytes  uint64        // Memory allocation in bytes
	TotalAllocs uint64        // Total allocation count
	LastGCPause time.Duration // Last GC pause duration

	startTime time.Time // When metrics started or were reset
}

var (
	globalMetrics = &Metrics{
		startTime: time.Now(),
	}
	enabled atomic.Bool
)

// Enable activates metrics collection globally.
//
// After calling Enable, all Record* functions will track operations.
// This function is safe to call multiple times and from multiple goroutines.
//
// Example:
//
//	monitor.Enable()
//	defer monitor.Disable()
//	// All operations are now tracked
func Enable() {
	enabled.Store(true)
}

// Disable deactivates metrics collection globally.
//
// After calling Disable, all Record* functions become no-ops.
// Existing metrics data is preserved until Reset() is called.
// This function is safe to call multiple times and from multiple goroutines.
//
// Example:
//
//	monitor.Disable()
//	// Metrics collection stopped but data preserved
//	metrics := monitor.GetMetrics() // Still returns last collected data
func Disable() {
	enabled.Store(false)
}

// IsEnabled returns whether metrics collection is currently active.
//
// Returns true if Enable() has been called, false otherwise.
// This function is safe to call from multiple goroutines.
//
// Example:
//
//	if monitor.IsEnabled() {
//	    fmt.Println("Metrics are being collected")
//	}
func IsEnabled() bool {
	return enabled.Load()
}

// RecordTokenizerCall records a tokenization operation with timing and error information.
//
// This function is a no-op if metrics are disabled. Call this after each
// tokenization operation to track performance.
//
// Parameters:
//   - duration: Time taken to tokenize the SQL
//   - tokens: Number of tokens generated
//   - err: Error returned from tokenization, or nil if successful
//
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	start := time.Now()
//	tokens, err := tokenizer.Tokenize(sqlBytes)
//	duration := time.Since(start)
//	monitor.RecordTokenizerCall(duration, len(tokens), err)
func RecordTokenizerCall(duration time.Duration, tokens int, err error) {
	if !IsEnabled() {
		return
	}

	atomic.AddInt64(&globalMetrics.TokenizerCalls, 1)
	atomic.AddInt64(&globalMetrics.TokensProcessed, int64(tokens))

	globalMetrics.mu.Lock()
	globalMetrics.TokenizerDuration += duration
	globalMetrics.mu.Unlock()

	if err != nil {
		atomic.AddInt64(&globalMetrics.TokenizerErrors, 1)
	}
}

// RecordParserCall records a parse operation with timing and error information.
//
// This function is a no-op if metrics are disabled. Call this after each
// parse operation to track performance.
//
// Parameters:
//   - duration: Time taken to parse the SQL
//   - err: Error returned from parsing, or nil if successful
//
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	start := time.Now()
//	ast, err := parser.Parse(tokens)
//	duration := time.Since(start)
//	monitor.RecordParserCall(duration, err)
func RecordParserCall(duration time.Duration, err error) {
	if !IsEnabled() {
		return
	}

	atomic.AddInt64(&globalMetrics.ParserCalls, 1)

	globalMetrics.mu.Lock()
	globalMetrics.ParserDuration += duration
	globalMetrics.mu.Unlock()

	if err != nil {
		atomic.AddInt64(&globalMetrics.ParserErrors, 1)
	} else {
		atomic.AddInt64(&globalMetrics.StatementsProcessed, 1)
	}
}

// RecordPoolHit records a successful object retrieval from the pool.
//
// Call this when an object is successfully retrieved from sync.Pool
// (i.e., the pool had an available object to reuse).
//
// This function is a no-op if metrics are disabled.
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	obj := pool.Get()
//	if obj != nil {
//	    monitor.RecordPoolHit()
//	} else {
//	    monitor.RecordPoolMiss()
//	}
func RecordPoolHit() {
	if !IsEnabled() {
		return
	}
	atomic.AddInt64(&globalMetrics.PoolHits, 1)
}

// RecordPoolMiss records a pool miss requiring new allocation.
//
// Call this when sync.Pool.Get() returns nil and a new object must be allocated.
// High pool miss rates indicate insufficient pool warm-up or excessive load.
//
// This function is a no-op if metrics are disabled.
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	obj := pool.Get()
//	if obj == nil {
//	    monitor.RecordPoolMiss()
//	    obj = &NewObject{} // Create new object
//	}
func RecordPoolMiss() {
	if !IsEnabled() {
		return
	}
	atomic.AddInt64(&globalMetrics.PoolMisses, 1)
}

// GetMetrics returns a snapshot of current performance metrics.
//
// This function is safe to call concurrently and can be called whether
// metrics are enabled or disabled. When disabled, returns a snapshot
// with the last collected values.
//
// The returned MetricsSnapshot is a copy and safe to use across goroutines.
// The PoolReuse field is calculated as (PoolHits / (PoolHits + PoolMisses)) * 100.
//
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	metrics := monitor.GetMetrics()
//	fmt.Printf("Tokenizer calls: %d\n", metrics.TokenizerCalls)
//	fmt.Printf("Tokenizer errors: %d\n", metrics.TokenizerErrors)
//	fmt.Printf("Pool reuse: %.1f%%\n", metrics.PoolReuse)
//	fmt.Printf("Uptime: %v\n", time.Since(metrics.StartTime))
func GetMetrics() MetricsSnapshot {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()

	m := MetricsSnapshot{
		TokenizerCalls:      atomic.LoadInt64(&globalMetrics.TokenizerCalls),
		TokenizerDuration:   globalMetrics.TokenizerDuration,
		TokensProcessed:     atomic.LoadInt64(&globalMetrics.TokensProcessed),
		TokenizerErrors:     atomic.LoadInt64(&globalMetrics.TokenizerErrors),
		ParserCalls:         atomic.LoadInt64(&globalMetrics.ParserCalls),
		ParserDuration:      globalMetrics.ParserDuration,
		StatementsProcessed: atomic.LoadInt64(&globalMetrics.StatementsProcessed),
		ParserErrors:        atomic.LoadInt64(&globalMetrics.ParserErrors),
		PoolHits:            atomic.LoadInt64(&globalMetrics.PoolHits),
		PoolMisses:          atomic.LoadInt64(&globalMetrics.PoolMisses),
		AllocBytes:          globalMetrics.AllocBytes,
		TotalAllocs:         globalMetrics.TotalAllocs,
		LastGCPause:         globalMetrics.LastGCPause,
		StartTime:           globalMetrics.startTime,
	}

	// Calculate pool reuse rate
	total := m.PoolHits + m.PoolMisses
	if total > 0 {
		m.PoolReuse = float64(m.PoolHits) / float64(total) * 100
	}

	return m
}

// Reset clears all metrics and resets the start time.
//
// This function resets all counters to zero and sets the start time to now.
// The enabled/disabled state is preserved.
//
// Useful for testing, service restart, or when you want to start fresh
// metrics collection without stopping the service.
//
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	monitor.Reset()
//	fmt.Println("All metrics cleared")
func Reset() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	// Reset individual fields without overwriting the mutex
	// Use atomic stores for fields that are accessed atomically elsewhere
	atomic.StoreInt64(&globalMetrics.TokenizerCalls, 0)
	globalMetrics.TokenizerDuration = 0
	atomic.StoreInt64(&globalMetrics.TokensProcessed, 0)
	atomic.StoreInt64(&globalMetrics.TokenizerErrors, 0)
	atomic.StoreInt64(&globalMetrics.ParserCalls, 0)
	globalMetrics.ParserDuration = 0
	atomic.StoreInt64(&globalMetrics.StatementsProcessed, 0)
	atomic.StoreInt64(&globalMetrics.ParserErrors, 0)
	atomic.StoreInt64(&globalMetrics.PoolHits, 0)
	atomic.StoreInt64(&globalMetrics.PoolMisses, 0)
	globalMetrics.PoolReuse = 0
	globalMetrics.AllocBytes = 0
	globalMetrics.TotalAllocs = 0
	globalMetrics.LastGCPause = 0
	globalMetrics.startTime = time.Now()
}

// Uptime returns the duration since metrics were enabled or reset.
//
// This provides the time window over which current metrics have been collected.
// Useful for calculating rates (operations per second, etc.).
//
// Thread safety: Safe to call from multiple goroutines concurrently.
//
// Example:
//
//	uptime := monitor.Uptime()
//	metrics := monitor.GetMetrics()
//	opsPerSec := float64(metrics.TokenizerCalls) / uptime.Seconds()
//	fmt.Printf("Uptime: %v, Ops/sec: %.0f\n", uptime, opsPerSec)
func Uptime() time.Duration {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()
	return time.Since(globalMetrics.startTime)
}

// Summary contains aggregated performance statistics and calculated rates.
//
// This structure provides high-level performance metrics derived from
// the raw MetricsSnapshot data. Use GetSummary() to obtain this information.
//
// All rate calculations are based on the uptime duration.
//
// Example:
//
//	summary := monitor.GetSummary()
//	fmt.Printf("Uptime: %v\n", summary.Uptime)
//	fmt.Printf("Operations/sec: %.0f\n", summary.OperationsPerSecond)
//	fmt.Printf("Error rate: %.2f%%\n", summary.ErrorRate)
type Summary struct {
	// Uptime is the duration since metrics were started or reset
	Uptime time.Duration

	// TotalOperations is the sum of tokenizer and parser operations
	TotalOperations int64

	// OperationsPerSecond is the average operations per second (total ops / uptime)
	OperationsPerSecond float64

	// TokensPerSecond is the average tokens generated per second
	TokensPerSecond float64

	// AvgTokenizerLatency is the average time per tokenization operation
	AvgTokenizerLatency time.Duration

	// AvgParserLatency is the average time per parse operation
	AvgParserLatency time.Duration

	// ErrorRate is the percentage of failed operations (0-100)
	ErrorRate float64

	// PoolEfficiency is the pool reuse percentage (0-100)
	PoolEfficiency float64
}

// GetSummary returns an aggregated performance summary with calculated rates.
//
// This function computes derived metrics from the raw counters:
//   - Operations per second (total operations / uptime)
//   - Tokens per second (total tokens / uptime)
//   - Average latencies (total duration / operation count)
//   - Overall error rate across tokenizer and parser
//   - Pool efficiency percentage
//
// Returns a Summary struct with all calculated fields populated.
// Safe to call concurrently from multiple goroutines.
//
// Example:
//
//	summary := monitor.GetSummary()
//	fmt.Printf("Summary:\n")
//	fmt.Printf("  Uptime: %v\n", summary.Uptime)
//	fmt.Printf("  Total Operations: %d\n", summary.TotalOperations)
//	fmt.Printf("  Operations/sec: %.0f\n", summary.OperationsPerSecond)
//	fmt.Printf("  Tokens/sec: %.0f\n", summary.TokensPerSecond)
//	fmt.Printf("  Avg Tokenizer Latency: %v\n", summary.AvgTokenizerLatency)
//	fmt.Printf("  Avg Parser Latency: %v\n", summary.AvgParserLatency)
//	fmt.Printf("  Error Rate: %.2f%%\n", summary.ErrorRate)
//	fmt.Printf("  Pool Efficiency: %.1f%%\n", summary.PoolEfficiency)
func GetSummary() Summary {
	m := GetMetrics()
	uptime := Uptime()
	uptimeSeconds := uptime.Seconds()

	s := Summary{
		Uptime:          uptime,
		TotalOperations: m.TokenizerCalls + m.ParserCalls,
		PoolEfficiency:  m.PoolReuse,
	}

	if uptimeSeconds > 0 {
		s.OperationsPerSecond = float64(s.TotalOperations) / uptimeSeconds
		s.TokensPerSecond = float64(m.TokensProcessed) / uptimeSeconds
	}

	if m.TokenizerCalls > 0 {
		s.AvgTokenizerLatency = m.TokenizerDuration / time.Duration(m.TokenizerCalls)
	}

	if m.ParserCalls > 0 {
		s.AvgParserLatency = m.ParserDuration / time.Duration(m.ParserCalls)
	}

	totalCalls := m.TokenizerCalls + m.ParserCalls
	if totalCalls > 0 {
		totalErrors := m.TokenizerErrors + m.ParserErrors
		s.ErrorRate = float64(totalErrors) / float64(totalCalls) * 100
	}

	return s
}
