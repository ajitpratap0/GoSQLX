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
	tokenizeOperations int64 // Total tokenization operations
	tokenizeErrors     int64 // Total tokenization errors
	tokenizeDuration   int64 // Total tokenization time in nanoseconds
	lastTokenizeTime   int64 // Last tokenization timestamp

	// Parser metrics
	parseOperations   int64 // Total parse operations
	parseErrors       int64 // Total parse errors
	parseDuration     int64 // Total parse time in nanoseconds
	lastParseTime     int64 // Last parse timestamp
	statementsCreated int64 // Total statements parsed

	// AST pool metrics
	astPoolGets  int64 // AST pool retrievals
	astPoolPuts  int64 // AST pool returns
	stmtPoolGets int64 // Statement pool retrievals
	stmtPoolPuts int64 // Statement pool returns
	exprPoolGets int64 // Expression pool retrievals
	exprPoolPuts int64 // Expression pool returns

	// Memory metrics (tokenizer pool)
	poolGets   int64 // Total pool retrievals
	poolPuts   int64 // Total pool returns
	poolMisses int64 // Pool misses (had to create new)

	// Query size metrics
	minQuerySize    int64 // Minimum query size processed
	maxQuerySize    int64 // Maximum query size processed
	totalQueryBytes int64 // Total bytes of SQL processed

	// Error tracking
	errorsByType map[string]int64
	errorsMutex  sync.RWMutex

	// Configuration - use atomic for thread safety
	enabled   int32        // 0 = disabled, 1 = enabled (atomic)
	startTime atomic.Value // time.Time stored atomically
}

// Global metrics instance
var globalMetrics = &Metrics{
	enabled:      0, // 0 = disabled
	errorsByType: make(map[string]int64),
	minQuerySize: -1, // -1 means not set yet
}

func init() {
	globalMetrics.startTime.Store(time.Now())
}

// Enable activates metrics collection
func Enable() {
	atomic.StoreInt32(&globalMetrics.enabled, 1)
	globalMetrics.startTime.Store(time.Now())
}

// Disable deactivates metrics collection
func Disable() {
	atomic.StoreInt32(&globalMetrics.enabled, 0)
}

// IsEnabled returns whether metrics collection is active
func IsEnabled() bool {
	return atomic.LoadInt32(&globalMetrics.enabled) == 1
}

// RecordTokenization records a tokenization operation
func RecordTokenization(duration time.Duration, querySize int, err error) {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
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
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}

	atomic.AddInt64(&globalMetrics.poolGets, 1)
	if !fromPool {
		atomic.AddInt64(&globalMetrics.poolMisses, 1)
	}
}

// RecordPoolPut records a tokenizer pool return
func RecordPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}

	atomic.AddInt64(&globalMetrics.poolPuts, 1)
}

// RecordParse records a parse operation
func RecordParse(duration time.Duration, statementCount int, err error) {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}

	// Record operation
	atomic.AddInt64(&globalMetrics.parseOperations, 1)
	atomic.AddInt64(&globalMetrics.parseDuration, int64(duration))
	atomic.StoreInt64(&globalMetrics.lastParseTime, time.Now().UnixNano())
	atomic.AddInt64(&globalMetrics.statementsCreated, int64(statementCount))

	// Record errors
	if err != nil {
		atomic.AddInt64(&globalMetrics.parseErrors, 1)

		// Record error by type
		errorType := "parse:" + err.Error()
		globalMetrics.errorsMutex.Lock()
		globalMetrics.errorsByType[errorType]++
		globalMetrics.errorsMutex.Unlock()
	}
}

// RecordASTPoolGet records an AST pool retrieval
func RecordASTPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.astPoolGets, 1)
}

// RecordASTPoolPut records an AST pool return
func RecordASTPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.astPoolPuts, 1)
}

// RecordStatementPoolGet records a statement pool retrieval
func RecordStatementPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.stmtPoolGets, 1)
}

// RecordStatementPoolPut records a statement pool return
func RecordStatementPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.stmtPoolPuts, 1)
}

// RecordExpressionPoolGet records an expression pool retrieval
func RecordExpressionPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.exprPoolGets, 1)
}

// RecordExpressionPoolPut records an expression pool return
func RecordExpressionPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.exprPoolPuts, 1)
}

// Stats represents current performance statistics
type Stats struct {
	// Tokenization counts
	TokenizeOperations int64   `json:"tokenize_operations"`
	TokenizeErrors     int64   `json:"tokenize_errors"`
	TokenizeErrorRate  float64 `json:"tokenize_error_rate"`

	// Parser counts
	ParseOperations   int64   `json:"parse_operations"`
	ParseErrors       int64   `json:"parse_errors"`
	ParseErrorRate    float64 `json:"parse_error_rate"`
	StatementsCreated int64   `json:"statements_created"`

	// Tokenization performance metrics
	AverageTokenizeDuration     time.Duration `json:"average_tokenize_duration"`
	TokenizeOperationsPerSecond float64       `json:"tokenize_operations_per_second"`

	// Parser performance metrics
	AverageParseDuration     time.Duration `json:"average_parse_duration"`
	ParseOperationsPerSecond float64       `json:"parse_operations_per_second"`

	// Tokenizer pool metrics
	PoolGets     int64   `json:"pool_gets"`
	PoolPuts     int64   `json:"pool_puts"`
	PoolBalance  int64   `json:"pool_balance"`
	PoolMissRate float64 `json:"pool_miss_rate"`

	// AST pool metrics
	ASTPoolGets    int64 `json:"ast_pool_gets"`
	ASTPoolPuts    int64 `json:"ast_pool_puts"`
	ASTPoolBalance int64 `json:"ast_pool_balance"`

	// Statement pool metrics
	StmtPoolGets    int64 `json:"stmt_pool_gets"`
	StmtPoolPuts    int64 `json:"stmt_pool_puts"`
	StmtPoolBalance int64 `json:"stmt_pool_balance"`

	// Expression pool metrics
	ExprPoolGets    int64 `json:"expr_pool_gets"`
	ExprPoolPuts    int64 `json:"expr_pool_puts"`
	ExprPoolBalance int64 `json:"expr_pool_balance"`

	// Query size metrics
	MinQuerySize        int64   `json:"min_query_size"`
	MaxQuerySize        int64   `json:"max_query_size"`
	AverageQuerySize    float64 `json:"average_query_size"`
	TotalBytesProcessed int64   `json:"total_bytes_processed"`

	// Timing
	Uptime            time.Duration `json:"uptime"`
	LastOperationTime time.Time     `json:"last_operation_time"`

	// Error breakdown
	ErrorsByType map[string]int64 `json:"errors_by_type"`

	// Legacy field for backwards compatibility
	ErrorRate float64 `json:"error_rate"`
}

// GetStats returns current performance statistics
func GetStats() Stats {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return Stats{}
	}

	// Tokenization metrics
	tokenizeOps := atomic.LoadInt64(&globalMetrics.tokenizeOperations)
	tokenizeErrs := atomic.LoadInt64(&globalMetrics.tokenizeErrors)
	tokenizeDur := atomic.LoadInt64(&globalMetrics.tokenizeDuration)
	lastTokenizeTime := atomic.LoadInt64(&globalMetrics.lastTokenizeTime)

	// Parser metrics
	parseOps := atomic.LoadInt64(&globalMetrics.parseOperations)
	parseErrs := atomic.LoadInt64(&globalMetrics.parseErrors)
	parseDur := atomic.LoadInt64(&globalMetrics.parseDuration)
	lastParseTime := atomic.LoadInt64(&globalMetrics.lastParseTime)
	stmtsCreated := atomic.LoadInt64(&globalMetrics.statementsCreated)

	// Pool metrics
	poolGets := atomic.LoadInt64(&globalMetrics.poolGets)
	poolPuts := atomic.LoadInt64(&globalMetrics.poolPuts)
	poolMisses := atomic.LoadInt64(&globalMetrics.poolMisses)

	// AST pool metrics
	astPoolGets := atomic.LoadInt64(&globalMetrics.astPoolGets)
	astPoolPuts := atomic.LoadInt64(&globalMetrics.astPoolPuts)
	stmtPoolGets := atomic.LoadInt64(&globalMetrics.stmtPoolGets)
	stmtPoolPuts := atomic.LoadInt64(&globalMetrics.stmtPoolPuts)
	exprPoolGets := atomic.LoadInt64(&globalMetrics.exprPoolGets)
	exprPoolPuts := atomic.LoadInt64(&globalMetrics.exprPoolPuts)

	// Query size metrics
	minSize := atomic.LoadInt64(&globalMetrics.minQuerySize)
	maxSize := atomic.LoadInt64(&globalMetrics.maxQuerySize)
	totalBytes := atomic.LoadInt64(&globalMetrics.totalQueryBytes)

	// Load start time atomically
	startTime := globalMetrics.startTime.Load().(time.Time)

	stats := Stats{
		// Tokenization
		TokenizeOperations: tokenizeOps,
		TokenizeErrors:     tokenizeErrs,

		// Parser
		ParseOperations:   parseOps,
		ParseErrors:       parseErrs,
		StatementsCreated: stmtsCreated,

		// Tokenizer pool
		PoolGets:    poolGets,
		PoolPuts:    poolPuts,
		PoolBalance: poolGets - poolPuts,

		// AST pools
		ASTPoolGets:     astPoolGets,
		ASTPoolPuts:     astPoolPuts,
		ASTPoolBalance:  astPoolGets - astPoolPuts,
		StmtPoolGets:    stmtPoolGets,
		StmtPoolPuts:    stmtPoolPuts,
		StmtPoolBalance: stmtPoolGets - stmtPoolPuts,
		ExprPoolGets:    exprPoolGets,
		ExprPoolPuts:    exprPoolPuts,
		ExprPoolBalance: exprPoolGets - exprPoolPuts,

		// Query size
		MinQuerySize:        minSize,
		MaxQuerySize:        maxSize,
		TotalBytesProcessed: totalBytes,
		Uptime:              time.Since(startTime),
	}

	// Calculate tokenization rates and averages
	if tokenizeOps > 0 {
		stats.TokenizeErrorRate = float64(tokenizeErrs) / float64(tokenizeOps)
		stats.AverageTokenizeDuration = time.Duration(tokenizeDur / tokenizeOps)
		stats.AverageQuerySize = float64(totalBytes) / float64(tokenizeOps)

		// Operations per second
		uptime := time.Since(startTime).Seconds()
		if uptime > 0 {
			stats.TokenizeOperationsPerSecond = float64(tokenizeOps) / uptime
		}
	}

	// Calculate parse rates and averages
	if parseOps > 0 {
		stats.ParseErrorRate = float64(parseErrs) / float64(parseOps)
		stats.AverageParseDuration = time.Duration(parseDur / parseOps)

		// Operations per second
		uptime := time.Since(startTime).Seconds()
		if uptime > 0 {
			stats.ParseOperationsPerSecond = float64(parseOps) / uptime
		}
	}

	// Calculate pool miss rate
	if poolGets > 0 {
		stats.PoolMissRate = float64(poolMisses) / float64(poolGets)
	}

	// Legacy error rate (combined)
	totalOps := tokenizeOps + parseOps
	totalErrs := tokenizeErrs + parseErrs
	if totalOps > 0 {
		stats.ErrorRate = float64(totalErrs) / float64(totalOps)
	}

	// Determine last operation time (most recent of tokenize or parse)
	lastOpTime := lastTokenizeTime
	if lastParseTime > lastOpTime {
		lastOpTime = lastParseTime
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
	// Tokenization metrics
	atomic.StoreInt64(&globalMetrics.tokenizeOperations, 0)
	atomic.StoreInt64(&globalMetrics.tokenizeErrors, 0)
	atomic.StoreInt64(&globalMetrics.tokenizeDuration, 0)
	atomic.StoreInt64(&globalMetrics.lastTokenizeTime, 0)

	// Parser metrics
	atomic.StoreInt64(&globalMetrics.parseOperations, 0)
	atomic.StoreInt64(&globalMetrics.parseErrors, 0)
	atomic.StoreInt64(&globalMetrics.parseDuration, 0)
	atomic.StoreInt64(&globalMetrics.lastParseTime, 0)
	atomic.StoreInt64(&globalMetrics.statementsCreated, 0)

	// Tokenizer pool metrics
	atomic.StoreInt64(&globalMetrics.poolGets, 0)
	atomic.StoreInt64(&globalMetrics.poolPuts, 0)
	atomic.StoreInt64(&globalMetrics.poolMisses, 0)

	// AST pool metrics
	atomic.StoreInt64(&globalMetrics.astPoolGets, 0)
	atomic.StoreInt64(&globalMetrics.astPoolPuts, 0)
	atomic.StoreInt64(&globalMetrics.stmtPoolGets, 0)
	atomic.StoreInt64(&globalMetrics.stmtPoolPuts, 0)
	atomic.StoreInt64(&globalMetrics.exprPoolGets, 0)
	atomic.StoreInt64(&globalMetrics.exprPoolPuts, 0)

	// Query size metrics
	atomic.StoreInt64(&globalMetrics.minQuerySize, -1)
	atomic.StoreInt64(&globalMetrics.maxQuerySize, 0)
	atomic.StoreInt64(&globalMetrics.totalQueryBytes, 0)

	// Error tracking
	globalMetrics.errorsMutex.Lock()
	globalMetrics.errorsByType = make(map[string]int64)
	globalMetrics.errorsMutex.Unlock()

	globalMetrics.startTime.Store(time.Now())
}

// LogStats logs current statistics (useful for debugging)
func LogStats() Stats {
	return GetStats()
}
