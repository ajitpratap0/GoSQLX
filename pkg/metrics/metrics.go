// Package metrics provides production performance monitoring for GoSQLX
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects runtime performance data for GoSQLX operations
type Metrics struct {
	// Tokenization metrics
	tokenizeOperations  int64         // Total tokenization operations
	tokenizeErrors      int64         // Total tokenization errors  
	tokenizeDuration    int64         // Total tokenization time in nanoseconds
	lastTokenizeTime    int64         // Last tokenization timestamp
	
	// Memory metrics
	poolGets            int64         // Total pool retrievals
	poolPuts            int64         // Total pool returns
	poolMisses          int64         // Pool misses (had to create new)
	
	// Query size metrics
	minQuerySize        int64         // Minimum query size processed
	maxQuerySize        int64         // Maximum query size processed
	totalQueryBytes     int64         // Total bytes of SQL processed
	
	// Error tracking
	errorsByType        map[string]int64
	errorsMutex         sync.RWMutex
	
	// Configuration
	enabled             bool
	startTime           time.Time
}

// Global metrics instance
var globalMetrics = &Metrics{
	enabled:     false,
	errorsByType: make(map[string]int64),
	startTime:   time.Now(),
	minQuerySize: -1, // -1 means not set yet
}

// Enable activates metrics collection
func Enable() {
	globalMetrics.enabled = true
	globalMetrics.startTime = time.Now()
}

// Disable deactivates metrics collection
func Disable() {
	globalMetrics.enabled = false
}

// IsEnabled returns whether metrics collection is active
func IsEnabled() bool {
	return globalMetrics.enabled
}

// RecordTokenization records a tokenization operation
func RecordTokenization(duration time.Duration, querySize int, err error) {
	if !globalMetrics.enabled {
		return
	}
	
	// Record operation
	atomic.AddInt64(&globalMetrics.tokenizeOperations, 1)
	atomic.AddInt64(&globalMetrics.tokenizeDuration, int64(duration))
	atomic.StoreInt64(&globalMetrics.lastTokenizeTime, time.Now().UnixNano())
	
	// Record query size
	atomic.AddInt64(&globalMetrics.totalQueryBytes, int64(querySize))
	
	// Update min/max query sizes
	currentMin := atomic.LoadInt64(&globalMetrics.minQuerySize)
	if currentMin == -1 || int64(querySize) < currentMin {
		atomic.StoreInt64(&globalMetrics.minQuerySize, int64(querySize))
	}
	
	currentMax := atomic.LoadInt64(&globalMetrics.maxQuerySize)
	if int64(querySize) > currentMax {
		atomic.StoreInt64(&globalMetrics.maxQuerySize, int64(querySize))
	}
	
	// Record errors
	if err != nil {
		atomic.AddInt64(&globalMetrics.tokenizeErrors, 1)
		
		// Record error by type
		errorType := err.Error()
		globalMetrics.errorsMutex.Lock()
		globalMetrics.errorsByType[errorType]++
		globalMetrics.errorsMutex.Unlock()
	}
}

// RecordPoolGet records a tokenizer pool retrieval
func RecordPoolGet(fromPool bool) {
	if !globalMetrics.enabled {
		return
	}
	
	atomic.AddInt64(&globalMetrics.poolGets, 1)
	if !fromPool {
		atomic.AddInt64(&globalMetrics.poolMisses, 1)
	}
}

// RecordPoolPut records a tokenizer pool return
func RecordPoolPut() {
	if !globalMetrics.enabled {
		return
	}
	
	atomic.AddInt64(&globalMetrics.poolPuts, 1)
}

// Stats represents current performance statistics
type Stats struct {
	// Basic counts
	TokenizeOperations  int64   `json:"tokenize_operations"`
	TokenizeErrors      int64   `json:"tokenize_errors"`
	ErrorRate           float64 `json:"error_rate"`
	
	// Performance metrics
	AverageDuration     time.Duration `json:"average_duration"`
	OperationsPerSecond float64       `json:"operations_per_second"`
	
	// Memory/Pool metrics
	PoolGets            int64   `json:"pool_gets"`
	PoolPuts            int64   `json:"pool_puts"`
	PoolBalance         int64   `json:"pool_balance"`
	PoolMissRate        float64 `json:"pool_miss_rate"`
	
	// Query size metrics
	MinQuerySize        int64   `json:"min_query_size"`
	MaxQuerySize        int64   `json:"max_query_size"`
	AverageQuerySize    float64 `json:"average_query_size"`
	TotalBytesProcessed int64   `json:"total_bytes_processed"`
	
	// Timing
	Uptime              time.Duration `json:"uptime"`
	LastOperationTime   time.Time     `json:"last_operation_time"`
	
	// Error breakdown
	ErrorsByType        map[string]int64 `json:"errors_by_type"`
}

// GetStats returns current performance statistics
func GetStats() Stats {
	if !globalMetrics.enabled {
		return Stats{}
	}
	
	operations := atomic.LoadInt64(&globalMetrics.tokenizeOperations)
	errors := atomic.LoadInt64(&globalMetrics.tokenizeErrors)
	duration := atomic.LoadInt64(&globalMetrics.tokenizeDuration)
	poolGets := atomic.LoadInt64(&globalMetrics.poolGets)
	poolPuts := atomic.LoadInt64(&globalMetrics.poolPuts)
	poolMisses := atomic.LoadInt64(&globalMetrics.poolMisses)
	minSize := atomic.LoadInt64(&globalMetrics.minQuerySize)
	maxSize := atomic.LoadInt64(&globalMetrics.maxQuerySize)
	totalBytes := atomic.LoadInt64(&globalMetrics.totalQueryBytes)
	lastOpTime := atomic.LoadInt64(&globalMetrics.lastTokenizeTime)
	
	stats := Stats{
		TokenizeOperations:  operations,
		TokenizeErrors:      errors,
		PoolGets:           poolGets,
		PoolPuts:           poolPuts,
		PoolBalance:        poolGets - poolPuts,
		MinQuerySize:       minSize,
		MaxQuerySize:       maxSize,
		TotalBytesProcessed: totalBytes,
		Uptime:             time.Since(globalMetrics.startTime),
	}
	
	// Calculate rates and averages
	if operations > 0 {
		stats.ErrorRate = float64(errors) / float64(operations)
		stats.AverageDuration = time.Duration(duration / operations)
		stats.AverageQuerySize = float64(totalBytes) / float64(operations)
		
		// Operations per second
		uptime := time.Since(globalMetrics.startTime).Seconds()
		if uptime > 0 {
			stats.OperationsPerSecond = float64(operations) / uptime
		}
	}
	
	if poolGets > 0 {
		stats.PoolMissRate = float64(poolMisses) / float64(poolGets)
	}
	
	if lastOpTime > 0 {
		stats.LastOperationTime = time.Unix(0, lastOpTime)
	}
	
	// Copy error breakdown
	globalMetrics.errorsMutex.RLock()
	stats.ErrorsByType = make(map[string]int64)
	for errorType, count := range globalMetrics.errorsByType {
		stats.ErrorsByType[errorType] = count
	}
	globalMetrics.errorsMutex.RUnlock()
	
	return stats
}

// Reset clears all metrics (useful for testing)
func Reset() {
	atomic.StoreInt64(&globalMetrics.tokenizeOperations, 0)
	atomic.StoreInt64(&globalMetrics.tokenizeErrors, 0)
	atomic.StoreInt64(&globalMetrics.tokenizeDuration, 0)
	atomic.StoreInt64(&globalMetrics.lastTokenizeTime, 0)
	atomic.StoreInt64(&globalMetrics.poolGets, 0)
	atomic.StoreInt64(&globalMetrics.poolPuts, 0)
	atomic.StoreInt64(&globalMetrics.poolMisses, 0)
	atomic.StoreInt64(&globalMetrics.minQuerySize, -1)
	atomic.StoreInt64(&globalMetrics.maxQuerySize, 0)
	atomic.StoreInt64(&globalMetrics.totalQueryBytes, 0)
	
	globalMetrics.errorsMutex.Lock()
	globalMetrics.errorsByType = make(map[string]int64)
	globalMetrics.errorsMutex.Unlock()
	
	globalMetrics.startTime = time.Now()
}

// LogStats logs current statistics (useful for debugging)
func LogStats() Stats {
	return GetStats()
}