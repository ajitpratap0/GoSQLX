// Package monitor provides performance monitoring and metrics collection for GoSQLX
package monitor

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds performance metrics for the tokenizer and parser
type Metrics struct {
	mu sync.RWMutex

	// Tokenizer metrics
	TokenizerCalls    int64
	TokenizerDuration time.Duration
	TokensProcessed   int64
	TokenizerErrors   int64

	// Parser metrics
	ParserCalls    int64
	ParserDuration time.Duration
	StatementsProcessed int64
	ParserErrors   int64

	// Pool metrics
	PoolHits   int64
	PoolMisses int64
	PoolReuse  float64

	// Memory metrics
	AllocBytes   uint64
	TotalAllocs  uint64
	LastGCPause  time.Duration

	startTime time.Time
}

var (
	globalMetrics = &Metrics{
		startTime: time.Now(),
	}
	enabled atomic.Bool
)

// Enable turns on metrics collection
func Enable() {
	enabled.Store(true)
}

// Disable turns off metrics collection
func Disable() {
	enabled.Store(false)
}

// IsEnabled returns whether metrics collection is enabled
func IsEnabled() bool {
	return enabled.Load()
}

// RecordTokenizerCall records a tokenizer operation
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

// RecordParserCall records a parser operation
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

// RecordPoolHit records a successful pool retrieval
func RecordPoolHit() {
	if !IsEnabled() {
		return
	}
	atomic.AddInt64(&globalMetrics.PoolHits, 1)
}

// RecordPoolMiss records a pool miss (new allocation)
func RecordPoolMiss() {
	if !IsEnabled() {
		return
	}
	atomic.AddInt64(&globalMetrics.PoolMisses, 1)
}

// GetMetrics returns a copy of current metrics
func GetMetrics() Metrics {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()

	m := *globalMetrics
	
	// Calculate pool reuse rate
	total := m.PoolHits + m.PoolMisses
	if total > 0 {
		m.PoolReuse = float64(m.PoolHits) / float64(total) * 100
	}

	return m
}

// Reset clears all metrics
func Reset() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	*globalMetrics = Metrics{
		startTime: time.Now(),
	}
}

// Uptime returns the duration since metrics were started or reset
func Uptime() time.Duration {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()
	return time.Since(globalMetrics.startTime)
}

// Summary returns a performance summary
type Summary struct {
	Uptime              time.Duration
	TotalOperations     int64
	OperationsPerSecond float64
	TokensPerSecond     float64
	AvgTokenizerLatency time.Duration
	AvgParserLatency    time.Duration
	ErrorRate           float64
	PoolEfficiency      float64
}

// GetSummary returns a performance summary
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