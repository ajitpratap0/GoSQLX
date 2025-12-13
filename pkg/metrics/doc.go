// Package metrics provides production-grade performance monitoring and observability
// for GoSQLX operations. It enables real-time tracking of tokenization, parsing,
// and object pool performance with race-free atomic operations.
//
// This package is designed for enterprise production environments requiring detailed
// performance insights, SLA monitoring, and operational observability. All operations
// are thread-safe and validated to be race-free under high concurrency.
//
// # Core Features
//
//   - Tokenization and parsing operation counts and timings
//   - Error rates and categorization by error type
//   - Object pool efficiency tracking (AST, tokenizer, statement, expression pools)
//   - Query size distribution (min, max, average bytes processed)
//   - Operations per second throughput metrics
//   - Pool hit rates and memory efficiency statistics
//   - Zero-overhead when disabled (immediate return from all Record* functions)
//
// # Performance Characteristics
//
// GoSQLX v1.6.0 metrics system:
//
//   - Thread-Safe: All operations use atomic counters and RWMutex for safe concurrency
//   - Race-Free: Validated with 20,000+ concurrent operations (go test -race)
//   - Low Overhead: < 100ns per metric recording operation when enabled
//   - Lock-Free: Atomic operations for all counters (no contention)
//   - Zero Cost: When disabled, all Record* functions return immediately
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
//	// Record tokenization metrics
//	metrics.RecordTokenization(duration, len(sqlBytes), err)
//
// Automatic integration with tokenizer:
//
//	// The tokenizer package automatically records metrics when enabled
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize(sqlBytes)
//	// Metrics recorded automatically if metrics.Enable() was called
//
// # Parser Metrics
//
// Track parser performance:
//
//	start := time.Now()
//	ast, err := parser.Parse(tokens)
//	duration := time.Since(start)
//
//	// Record parser metrics
//	statementCount := len(ast.Statements)
//	metrics.RecordParse(duration, statementCount, err)
//
// # Object Pool Metrics
//
// Track pool efficiency for all pool types:
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
//	// Statement pool (SELECT, INSERT, UPDATE, DELETE)
//	stmt := ast.NewSelectStatement()
//	metrics.RecordStmtPoolGet()
//	defer func() {
//	    ast.ReleaseSelectStatement(stmt)
//	    metrics.RecordStmtPoolPut()
//	}()
//
//	// Expression pool (identifiers, literals, binary expressions)
//	expr := ast.NewIdentifier("column_name")
//	metrics.RecordExprPoolGet()
//	defer func() {
//	    ast.ReleaseIdentifier(expr)
//	    metrics.RecordExprPoolPut()
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
//	poolHitRate := (1 - stats.PoolMissRate) * 100
//	fmt.Printf("Pool hit rate: %.1f%%\n", poolHitRate)
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
// Record errors with categorization:
//
//	// Tokenization error
//	err := tokenizer.Tokenize(sqlBytes)
//	if err != nil {
//	    metrics.RecordError("E1001") // Error code from pkg/errors
//	}
//
//	// Parser error
//	ast, err := parser.Parse(tokens)
//	if err != nil {
//	    metrics.RecordError("E2001")
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
//	        // Export to Prometheus, DataDog, New Relic, etc.
//	        prometheusGauge.WithLabelValues("tokenize_ops_per_sec").Set(stats.TokenizeOperationsPerSecond)
//	        prometheusGauge.WithLabelValues("pool_miss_rate").Set(stats.PoolMissRate)
//	        prometheusCounter.WithLabelValues("tokenize_total").Add(float64(stats.TokenizeOperations))
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
//
//	        // Check pool balance (gets should roughly equal puts)
//	        if abs(stats.ASTPoolBalance) > 1000 {
//	            log.Printf("WARNING: AST pool imbalance: %d", stats.ASTPoolBalance)
//	        }
//	    }
//	}()
//
// # Pool Efficiency Monitoring
//
// Track all pool types independently:
//
//	stats := metrics.GetStats()
//
//	// Tokenizer pool (sync.Pool for tokenizer instances)
//	fmt.Printf("Tokenizer pool gets: %d, puts: %d, balance: %d\n",
//	    stats.PoolGets, stats.PoolPuts, stats.PoolBalance)
//	fmt.Printf("Tokenizer pool miss rate: %.1f%%\n", stats.PoolMissRate*100)
//
//	// AST pool (main AST container objects)
//	fmt.Printf("AST pool gets: %d, puts: %d, balance: %d\n",
//	    stats.ASTPoolGets, stats.ASTPoolPuts, stats.ASTPoolBalance)
//
//	// Statement pool (SELECT/INSERT/UPDATE/DELETE statements)
//	fmt.Printf("Statement pool gets: %d, puts: %d, balance: %d\n",
//	    stats.StmtPoolGets, stats.StmtPoolPuts, stats.StmtPoolBalance)
//
//	// Expression pool (identifiers, binary expressions, literals)
//	fmt.Printf("Expression pool gets: %d, puts: %d, balance: %d\n",
//	    stats.ExprPoolGets, stats.ExprPoolPuts, stats.ExprPoolBalance)
//
// Pool balance interpretation:
//
//   - Balance = 0: Perfect equilibrium (gets == puts)
//   - Balance > 0: More gets than puts (potential leak or objects still in use)
//   - Balance < 0: More puts than gets (should never happen - indicates bug)
//
// # Resetting Metrics
//
// Reset all metrics (useful for testing or service restart):
//
//	metrics.Reset()
//	fmt.Println("All metrics reset to zero")
//
// Note: Reset() preserves the enabled/disabled state but clears all counters.
// The start time is also reset to the current time.
//
// # SLA Monitoring
//
// Track service level objectives:
//
//	stats := metrics.GetStats()
//
//	// P99 latency approximation (average as baseline)
//	if stats.AverageTokenizeDuration > 10*time.Millisecond {
//	    log.Printf("WARNING: High tokenize latency: %v", stats.AverageTokenizeDuration)
//	}
//
//	// Throughput SLO
//	if stats.TokenizeOperationsPerSecond < 100000 {
//	    log.Printf("WARNING: Low throughput: %.0f ops/sec", stats.TokenizeOperationsPerSecond)
//	}
//
//	// Error rate SLO
//	if stats.TokenizeErrorRate > 0.01 { // 1% error threshold
//	    log.Printf("CRITICAL: Error rate %.2f%% exceeds SLO", stats.TokenizeErrorRate*100)
//	}
//
// # Performance Impact
//
// The metrics package uses atomic operations for lock-free performance tracking.
//
// Overhead measurements (on modern x86_64):
//
//   - When disabled: ~1-2ns per Record* call (immediate return)
//   - When enabled: ~50-100ns per Record* call (atomic increment)
//   - GetStats(): ~1-2μs (copies all counters with read lock)
//
// For reference, GoSQLX v1.6.0 tokenization takes ~700ns for typical queries,
// so metrics overhead is < 15% even when enabled.
//
// # Thread Safety
//
// All functions in this package are safe for concurrent use from multiple
// goroutines:
//
//   - Enable/Disable: Safe to call from any goroutine
//   - Record* functions: Use atomic operations for counters
//   - GetStats: Uses RWMutex to safely copy all metrics
//   - Reset: Uses write lock to safely clear all metrics
//
// The package has been validated to be race-free under high concurrency
// with 20,000+ concurrent operations tested using go test -race.
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
// Example output:
//
//	{
//	  "tokenize_operations": 150000,
//	  "tokenize_operations_per_second": 1380000.0,
//	  "average_tokenize_duration": "724ns",
//	  "tokenize_error_rate": 0.002,
//	  "pool_miss_rate": 0.05,
//	  "pool_reuse": 95.0,
//	  "average_query_size": 1024.5
//	}
//
// # Stats Structure
//
// The Stats struct provides comprehensive metrics:
//
//	type Stats struct {
//	    // Tokenization metrics
//	    TokenizeOperations          int64         // Total tokenization calls
//	    TokenizeErrors              int64         // Total tokenization errors
//	    TokenizeOperationsPerSecond float64       // Ops/sec throughput
//	    AverageTokenizeDuration     time.Duration // Average tokenization time
//	    TokenizeErrorRate           float64       // Error rate (0.0-1.0)
//	    LastTokenizeTime            time.Time     // Timestamp of last tokenization
//
//	    // Parser metrics
//	    ParseOperations          int64         // Total parse calls
//	    ParseErrors              int64         // Total parse errors
//	    ParseOperationsPerSecond float64       // Ops/sec throughput
//	    AverageParseDuration     time.Duration // Average parse time
//	    ParseErrorRate           float64       // Error rate (0.0-1.0)
//	    StatementsCreated        int64         // Total statements parsed
//	    LastParseTime            time.Time     // Timestamp of last parse
//
//	    // Pool metrics (tokenizer pool)
//	    PoolGets    int64   // Total pool retrievals
//	    PoolPuts    int64   // Total pool returns
//	    PoolMisses  int64   // Pool misses (new allocations)
//	    PoolBalance int64   // Gets - Puts (should be ~0)
//	    PoolMissRate float64 // Miss rate (0.0-1.0)
//	    PoolReuse    float64 // Reuse percentage (0-100)
//
//	    // AST pool metrics
//	    ASTPoolGets    int64 // AST pool retrievals
//	    ASTPoolPuts    int64 // AST pool returns
//	    ASTPoolBalance int64 // Gets - Puts
//
//	    // Statement pool metrics
//	    StmtPoolGets    int64 // Statement pool retrievals
//	    StmtPoolPuts    int64 // Statement pool returns
//	    StmtPoolBalance int64 // Gets - Puts
//
//	    // Expression pool metrics
//	    ExprPoolGets    int64 // Expression pool retrievals
//	    ExprPoolPuts    int64 // Expression pool returns
//	    ExprPoolBalance int64 // Gets - Puts
//
//	    // Query size metrics
//	    MinQuerySize        int64   // Smallest query processed (bytes)
//	    MaxQuerySize        int64   // Largest query processed (bytes)
//	    TotalBytesProcessed int64   // Total SQL bytes processed
//	    AverageQuerySize    float64 // Average query size (bytes)
//
//	    // Error tracking
//	    ErrorsByType map[string]int64 // Error counts by error code
//
//	    // Timing
//	    StartTime time.Time     // When metrics were enabled/reset
//	    Uptime    time.Duration // Duration since start
//	}
//
// # Integration Examples
//
// Prometheus exporter:
//
//	func exportPrometheusMetrics() {
//	    stats := metrics.GetStats()
//
//	    // Gauges for current rates
//	    tokenizeOpsPerSec.Set(stats.TokenizeOperationsPerSecond)
//	    parseOpsPerSec.Set(stats.ParseOperationsPerSecond)
//	    poolMissRate.Set(stats.PoolMissRate)
//
//	    // Counters for totals
//	    tokenizeTotal.Add(float64(stats.TokenizeOperations))
//	    parseTotal.Add(float64(stats.ParseOperations))
//	    tokenizeErrors.Add(float64(stats.TokenizeErrors))
//	    parseErrors.Add(float64(stats.ParseErrors))
//
//	    // Histograms for latencies
//	    tokenizeLatency.Observe(stats.AverageTokenizeDuration.Seconds())
//	    parseLatency.Observe(stats.AverageParseDuration.Seconds())
//	}
//
// DataDog exporter:
//
//	func exportDataDogMetrics() {
//	    stats := metrics.GetStats()
//
//	    statsd.Gauge("gosqlx.tokenize.ops_per_second", stats.TokenizeOperationsPerSecond, nil, 1)
//	    statsd.Gauge("gosqlx.parse.ops_per_second", stats.ParseOperationsPerSecond, nil, 1)
//	    statsd.Gauge("gosqlx.pool.miss_rate", stats.PoolMissRate, nil, 1)
//	    statsd.Gauge("gosqlx.pool.hit_rate", 1-stats.PoolMissRate, nil, 1)
//	    statsd.Count("gosqlx.tokenize.total", stats.TokenizeOperations, nil, 1)
//	    statsd.Count("gosqlx.parse.total", stats.ParseOperations, nil, 1)
//	    statsd.Histogram("gosqlx.tokenize.duration", float64(stats.AverageTokenizeDuration), nil, 1)
//	}
//
// # Design Principles
//
// The metrics package follows GoSQLX design philosophy:
//
//   - Zero Dependencies: Only depends on Go standard library
//   - Thread-Safe: All operations safe for concurrent use
//   - Low Overhead: Minimal impact on performance (< 15% when enabled)
//   - Atomic Operations: Lock-free counters for high concurrency
//   - Comprehensive: Tracks all major subsystems (tokenizer, parser, pools)
//   - Production-Ready: Validated race-free under high load
//
// # Testing and Quality
//
// The package maintains high quality standards:
//
//   - Comprehensive test coverage for all functions
//   - Race detection validation (go test -race)
//   - Concurrent access testing (20,000+ operations)
//   - Performance benchmarks for all operations
//   - Real-world usage validation in production environments
//
// # Version
//
// This package is part of GoSQLX v1.6.0 and is production-ready for enterprise use.
//
// For complete examples and advanced usage, see:
//   - docs/GETTING_STARTED.md - Quick start guide
//   - docs/USAGE_GUIDE.md - Comprehensive usage documentation
//   - examples/ directory - Production-ready examples
package metrics
