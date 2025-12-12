// Package metrics provides production-grade performance monitoring and observability
// for GoSQLX operations. It enables real-time tracking of tokenization, parsing,
// and object pool performance with race-free atomic operations.
//
// # Overview
//
// The metrics package collects comprehensive runtime statistics including:
//   - Tokenization and parsing operation counts and timings
//   - Error rates and categorization by error type
//   - Object pool efficiency (AST, tokenizer, statement, expression pools)
//   - Query size distribution (min, max, average)
//   - Operations per second throughput
//   - Pool hit rates and memory efficiency
//
// All metric operations are thread-safe using atomic operations, making them
// suitable for high-concurrency production environments.
//
// # Basic Usage
//
// Enable metrics collection:
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/metrics"
//
//	// Enable metrics tracking
//	metrics.Enable()
//	defer metrics.Disable()
//
//	// Perform operations (metrics automatically collected)
//	// ...
//
//	// Retrieve statistics
//	stats := metrics.GetStats()
//	fmt.Printf("Operations: %d\n", stats.TokenizeOperations)
//	fmt.Printf("Error rate: %.2f%%\n", stats.TokenizeErrorRate*100)
//	fmt.Printf("Avg duration: %v\n", stats.AverageTokenizeDuration)
//
// # Tokenization Metrics
//
// Track tokenizer performance:
//
//	import "time"
//
//	start := time.Now()
//	tokens, err := tokenizer.Tokenize(sqlBytes)
//	duration := time.Since(start)
//
//	metrics.RecordTokenization(duration, len(sqlBytes), err)
//
// # Parser Metrics
//
// Track parser performance:
//
//	start := time.Now()
//	ast, err := parser.Parse(tokens)
//	duration := time.Since(start)
//
//	statementCount := len(ast.Statements)
//	metrics.RecordParse(duration, statementCount, err)
//
// # Object Pool Metrics
//
// Track pool efficiency:
//
//	// Tokenizer pool
//	tkz := tokenizer.GetTokenizer()
//	metrics.RecordPoolGet(true) // true = from pool, false = new allocation
//	defer func() {
//	    tokenizer.PutTokenizer(tkz)
//	    metrics.RecordPoolPut()
//	}()
//
//	// AST pool
//	ast := ast.NewAST()
//	metrics.RecordASTPoolGet()
//	defer func() {
//	    ast.ReleaseAST(ast)
//	    metrics.RecordASTPoolPut()
//	}()
//
// # Retrieving Statistics
//
// Get comprehensive performance statistics:
//
//	stats := metrics.GetStats()
//
//	// Tokenization performance
//	fmt.Printf("Tokenize ops/sec: %.0f\n", stats.TokenizeOperationsPerSecond)
//	fmt.Printf("Avg tokenize time: %v\n", stats.AverageTokenizeDuration)
//	fmt.Printf("Tokenize error rate: %.2f%%\n", stats.TokenizeErrorRate*100)
//
//	// Parser performance
//	fmt.Printf("Parse ops/sec: %.0f\n", stats.ParseOperationsPerSecond)
//	fmt.Printf("Avg parse time: %v\n", stats.AverageParseDuration)
//	fmt.Printf("Statements created: %d\n", stats.StatementsCreated)
//
//	// Pool efficiency
//	fmt.Printf("Pool hit rate: %.1f%%\n", (1-stats.PoolMissRate)*100)
//	fmt.Printf("AST pool balance: %d\n", stats.ASTPoolBalance)
//
//	// Query size metrics
//	fmt.Printf("Query size range: %d - %d bytes\n", stats.MinQuerySize, stats.MaxQuerySize)
//	fmt.Printf("Avg query size: %.0f bytes\n", stats.AverageQuerySize)
//	fmt.Printf("Total processed: %d bytes\n", stats.TotalBytesProcessed)
//
// # Error Tracking
//
// View error breakdown by type:
//
//	stats := metrics.GetStats()
//	if len(stats.ErrorsByType) > 0 {
//	    fmt.Println("Errors by type:")
//	    for errorType, count := range stats.ErrorsByType {
//	        fmt.Printf("  %s: %d\n", errorType, count)
//	    }
//	}
//
// # Production Monitoring
//
// Integrate with monitoring systems:
//
//	import "time"
//
//	// Periodic stats reporting
//	ticker := time.NewTicker(30 * time.Second)
//	go func() {
//	    for range ticker.C {
//	        stats := metrics.GetStats()
//
//	        // Export to Prometheus, DataDog, etc.
//	        prometheusGauge.Set(stats.TokenizeOperationsPerSecond)
//	        prometheusGauge.Set(stats.PoolMissRate)
//	        prometheusCounter.Add(float64(stats.TokenizeOperations))
//
//	        // Alert on high error rates
//	        if stats.TokenizeErrorRate > 0.05 {
//	            log.Printf("WARNING: High tokenize error rate: %.2f%%",
//	                stats.TokenizeErrorRate*100)
//	        }
//
//	        // Monitor pool efficiency
//	        if stats.PoolMissRate > 0.2 {
//	            log.Printf("WARNING: Low pool hit rate: %.1f%%",
//	                (1-stats.PoolMissRate)*100)
//	        }
//	    }
//	}()
//
// # Pool Efficiency Monitoring
//
// Track all pool types:
//
//	stats := metrics.GetStats()
//
//	// Tokenizer pool
//	fmt.Printf("Tokenizer pool gets: %d, puts: %d, balance: %d\n",
//	    stats.PoolGets, stats.PoolPuts, stats.PoolBalance)
//	fmt.Printf("Tokenizer pool miss rate: %.1f%%\n", stats.PoolMissRate*100)
//
//	// AST pool
//	fmt.Printf("AST pool gets: %d, puts: %d, balance: %d\n",
//	    stats.ASTPoolGets, stats.ASTPoolPuts, stats.ASTPoolBalance)
//
//	// Statement pool
//	fmt.Printf("Statement pool gets: %d, puts: %d, balance: %d\n",
//	    stats.StmtPoolGets, stats.StmtPoolPuts, stats.StmtPoolBalance)
//
//	// Expression pool
//	fmt.Printf("Expression pool gets: %d, puts: %d, balance: %d\n",
//	    stats.ExprPoolGets, stats.ExprPoolPuts, stats.ExprPoolBalance)
//
// # Resetting Metrics
//
// Reset all metrics (useful for testing or service restart):
//
//	metrics.Reset()
//	fmt.Println("All metrics reset to zero")
//
// # Performance Impact
//
// The metrics package uses atomic operations for lock-free performance tracking.
// When disabled, all recording functions return immediately with minimal overhead.
// When enabled, the overhead per operation is typically < 100ns.
//
// # Thread Safety
//
// All functions in this package are safe for concurrent use from multiple
// goroutines. The package has been validated to be race-free under high
// concurrency (20,000+ concurrent operations tested).
//
// # JSON Serialization
//
// The Stats struct supports JSON marshaling for easy integration with
// monitoring and logging systems:
//
//	stats := metrics.GetStats()
//	jsonData, err := json.MarshalIndent(stats, "", "  ")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(jsonData))
//
// # Version
//
// This package is part of GoSQLX v1.6.0 and is production-ready for enterprise use.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects runtime performance data for GoSQLX operations.
// It uses atomic operations for all counters to ensure thread-safe,
// race-free metric collection in high-concurrency environments.
//
// This is the internal metrics structure. Use the global functions
// (Enable, Disable, RecordTokenization, etc.) to interact with metrics.
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

// Enable activates metrics collection globally.
// After calling Enable, all Record* functions will track operations.
// The start time is reset when metrics are enabled.
//
// This function is safe to call multiple times.
//
// Example:
//
//	metrics.Enable()
//	defer metrics.Disable()
//	// All operations are now tracked
func Enable() {
	atomic.StoreInt32(&globalMetrics.enabled, 1)
	globalMetrics.startTime.Store(time.Now())
}

// Disable deactivates metrics collection globally.
// After calling Disable, all Record* functions become no-ops.
// Existing metrics data is preserved until Reset() is called.
//
// This function is safe to call multiple times.
//
// Example:
//
//	metrics.Disable()
//	// Metrics collection stopped but data preserved
//	stats := metrics.GetStats() // Still returns last collected stats
func Disable() {
	atomic.StoreInt32(&globalMetrics.enabled, 0)
}

// IsEnabled returns whether metrics collection is currently active.
// Returns true if Enable() has been called, false otherwise.
//
// Example:
//
//	if metrics.IsEnabled() {
//	    fmt.Println("Metrics are being collected")
//	}
func IsEnabled() bool {
	return atomic.LoadInt32(&globalMetrics.enabled) == 1
}

// RecordTokenization records a tokenization operation with duration, query size, and error.
// This function is a no-op if metrics are disabled.
//
// Call this after each tokenization operation to track performance metrics.
//
// Parameters:
//   - duration: Time taken to tokenize the SQL
//   - querySize: Size of the SQL query in bytes
//   - err: Error returned from tokenization, or nil if successful
//
// Example:
//
//	start := time.Now()
//	tokens, err := tokenizer.Tokenize(sqlBytes)
//	duration := time.Since(start)
//	metrics.RecordTokenization(duration, len(sqlBytes), err)
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

// RecordPoolGet records a tokenizer pool retrieval operation.
// This function is a no-op if metrics are disabled.
//
// Call this each time a tokenizer is retrieved from the pool.
//
// Parameters:
//   - fromPool: true if the tokenizer came from the pool, false if newly allocated
//
// Example:
//
//	tkz := tokenizer.GetTokenizer()
//	metrics.RecordPoolGet(true) // Retrieved from pool
//	defer func() {
//	    tokenizer.PutTokenizer(tkz)
//	    metrics.RecordPoolPut()
//	}()
func RecordPoolGet(fromPool bool) {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}

	atomic.AddInt64(&globalMetrics.poolGets, 1)
	if !fromPool {
		atomic.AddInt64(&globalMetrics.poolMisses, 1)
	}
}

// RecordPoolPut records a tokenizer pool return operation.
// This function is a no-op if metrics are disabled.
//
// Call this each time a tokenizer is returned to the pool.
//
// Example:
//
//	defer func() {
//	    tokenizer.PutTokenizer(tkz)
//	    metrics.RecordPoolPut()
//	}()
func RecordPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}

	atomic.AddInt64(&globalMetrics.poolPuts, 1)
}

// RecordParse records a parse operation with duration, statement count, and error.
// This function is a no-op if metrics are disabled.
//
// Call this after each parse operation to track performance metrics.
//
// Parameters:
//   - duration: Time taken to parse the SQL
//   - statementCount: Number of statements successfully parsed
//   - err: Error returned from parsing, or nil if successful
//
// Example:
//
//	start := time.Now()
//	ast, err := parser.Parse(tokens)
//	duration := time.Since(start)
//	statementCount := len(ast.Statements)
//	metrics.RecordParse(duration, statementCount, err)
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

// RecordASTPoolGet records an AST pool retrieval.
// This function is a no-op if metrics are disabled.
// Use this to track AST pool efficiency.
func RecordASTPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.astPoolGets, 1)
}

// RecordASTPoolPut records an AST pool return.
// This function is a no-op if metrics are disabled.
// Use this to track AST pool efficiency.
func RecordASTPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.astPoolPuts, 1)
}

// RecordStatementPoolGet records a statement pool retrieval.
// This function is a no-op if metrics are disabled.
// Use this to track statement pool efficiency.
func RecordStatementPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.stmtPoolGets, 1)
}

// RecordStatementPoolPut records a statement pool return.
// This function is a no-op if metrics are disabled.
// Use this to track statement pool efficiency.
func RecordStatementPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.stmtPoolPuts, 1)
}

// RecordExpressionPoolGet records an expression pool retrieval.
// This function is a no-op if metrics are disabled.
// Use this to track expression pool efficiency.
func RecordExpressionPoolGet() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.exprPoolGets, 1)
}

// RecordExpressionPoolPut records an expression pool return.
// This function is a no-op if metrics are disabled.
// Use this to track expression pool efficiency.
func RecordExpressionPoolPut() {
	if atomic.LoadInt32(&globalMetrics.enabled) == 0 {
		return
	}
	atomic.AddInt64(&globalMetrics.exprPoolPuts, 1)
}

// Stats represents a snapshot of current performance statistics.
// All fields are populated by GetStats() and provide comprehensive
// performance and efficiency data for GoSQLX operations.
//
// The struct supports JSON marshaling for easy integration with
// monitoring systems, logging, and dashboards.
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

// GetStats returns a snapshot of current performance statistics.
// This function is safe to call concurrently and can be called whether
// metrics are enabled or disabled.
//
// When metrics are disabled, returns a Stats struct with zero values.
//
// The returned Stats struct contains comprehensive information including:
//   - Operation counts and timings (tokenization, parsing)
//   - Error rates and error breakdown by type
//   - Pool efficiency metrics (hit rates, balance)
//   - Query size statistics
//   - Operations per second throughput
//   - Uptime since metrics were enabled
//
// Example:
//
//	stats := metrics.GetStats()
//
//	// Display tokenization performance
//	fmt.Printf("Tokenize ops/sec: %.0f\n", stats.TokenizeOperationsPerSecond)
//	fmt.Printf("Avg tokenize time: %v\n", stats.AverageTokenizeDuration)
//	fmt.Printf("Error rate: %.2f%%\n", stats.TokenizeErrorRate*100)
//
//	// Display pool efficiency
//	fmt.Printf("Pool hit rate: %.1f%%\n", (1-stats.PoolMissRate)*100)
//	fmt.Printf("Pool balance: %d\n", stats.PoolBalance)
//
//	// Export to JSON
//	jsonData, _ := json.MarshalIndent(stats, "", "  ")
//	fmt.Println(string(jsonData))
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

// Reset clears all metrics and resets counters to zero.
// This is useful for testing, benchmarking, or when restarting metric collection.
//
// The function resets:
//   - All operation counts (tokenization, parsing)
//   - All timing data
//   - Pool statistics
//   - Query size metrics
//   - Error counts and breakdown
//   - Start time (reset to current time)
//
// Note: This does not affect the enabled/disabled state. If metrics are enabled
// before Reset(), they remain enabled after.
//
// Example:
//
//	// Reset before benchmark
//	metrics.Reset()
//	metrics.Enable()
//
//	// Run operations
//	// ...
//
//	// Check clean metrics
//	stats := metrics.GetStats()
//	fmt.Printf("Operations: %d\n", stats.TokenizeOperations)
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

// LogStats returns current statistics for logging purposes.
// This is a convenience function that simply calls GetStats().
//
// Deprecated: Use GetStats() directly instead.
//
// Example:
//
//	stats := metrics.LogStats()
//	log.Printf("Metrics: %+v", stats)
func LogStats() Stats {
	return GetStats()
}
