// Package monitor provides lightweight performance monitoring for GoSQLX operations.
//
// This package is a simpler alternative to pkg/metrics, designed for applications
// that need basic performance tracking without the full feature set. It focuses on
// core metrics: tokenizer/parser timings, pool efficiency, and memory statistics.
//
// For comprehensive production monitoring with error tracking, query size distribution,
// and detailed pool metrics, use pkg/metrics instead.
//
// # Overview
//
// The monitor package tracks:
//
//   - Tokenizer call counts and cumulative duration
//   - Parser call counts and cumulative duration
//   - Object pool hit/miss rates and reuse percentages
//   - Basic memory allocation statistics
//   - Error counts for tokenizer and parser operations
//
// All operations are thread-safe using atomic counters and RWMutex for safe
// concurrent access from multiple goroutines.
//
// # Basic Usage
//
// Enable monitoring:
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/sql/monitor"
//
//	// Enable metrics collection
//	monitor.Enable()
//	defer monitor.Disable()
//
//	// Perform operations
//	// ...
//
//	// Get metrics snapshot
//	metrics := monitor.GetMetrics()
//	fmt.Printf("Tokenizer calls: %d\n", metrics.TokenizerCalls)
//	fmt.Printf("Parser calls: %d\n", metrics.ParserCalls)
//	fmt.Printf("Pool reuse: %.1f%%\n", metrics.PoolReuse)
//
// # Recording Operations
//
// Record tokenizer operations:
//
//	start := time.Now()
//	tokens, err := tokenizer.Tokenize(sqlBytes)
//	duration := time.Since(start)
//
//	monitor.RecordTokenizerCall(duration, len(tokens), err)
//
// Record parser operations:
//
//	start := time.Now()
//	ast, err := parser.Parse(tokens)
//	duration := time.Since(start)
//
//	monitor.RecordParserCall(duration, err)
//
// # Pool Tracking
//
// Record pool hits and misses:
//
//	// Successful pool retrieval
//	monitor.RecordPoolHit()
//
//	// Pool miss (new allocation required)
//	monitor.RecordPoolMiss()
//
// Example with tokenizer pool:
//
//	tkz := tokenizer.GetTokenizer()
//	if tkz != nil {
//	    monitor.RecordPoolHit()
//	} else {
//	    monitor.RecordPoolMiss()
//	}
//	defer tokenizer.PutTokenizer(tkz)
//
// # Metrics Snapshot
//
// Retrieve current metrics:
//
//	metrics := monitor.GetMetrics()
//
//	// Tokenizer metrics
//	fmt.Printf("Tokenizer calls: %d\n", metrics.TokenizerCalls)
//	fmt.Printf("Tokenizer duration: %v\n", metrics.TokenizerDuration)
//	fmt.Printf("Tokens processed: %d\n", metrics.TokensProcessed)
//	fmt.Printf("Tokenizer errors: %d\n", metrics.TokenizerErrors)
//
//	// Parser metrics
//	fmt.Printf("Parser calls: %d\n", metrics.ParserCalls)
//	fmt.Printf("Parser duration: %v\n", metrics.ParserDuration)
//	fmt.Printf("Statements processed: %d\n", metrics.StatementsProcessed)
//	fmt.Printf("Parser errors: %d\n", metrics.ParserErrors)
//
//	// Pool metrics
//	fmt.Printf("Pool hits: %d\n", metrics.PoolHits)
//	fmt.Printf("Pool misses: %d\n", metrics.PoolMisses)
//	fmt.Printf("Pool reuse rate: %.1f%%\n", metrics.PoolReuse)
//
//	// Uptime
//	fmt.Printf("Monitoring started: %v\n", metrics.StartTime)
//
// # Performance Summary
//
// Get aggregated performance summary:
//
//	summary := monitor.GetSummary()
//
//	fmt.Printf("Uptime: %v\n", summary.Uptime)
//	fmt.Printf("Total operations: %d\n", summary.TotalOperations)
//	fmt.Printf("Operations/sec: %.0f\n", summary.OperationsPerSecond)
//	fmt.Printf("Tokens/sec: %.0f\n", summary.TokensPerSecond)
//	fmt.Printf("Avg tokenizer latency: %v\n", summary.AvgTokenizerLatency)
//	fmt.Printf("Avg parser latency: %v\n", summary.AvgParserLatency)
//	fmt.Printf("Error rate: %.2f%%\n", summary.ErrorRate)
//	fmt.Printf("Pool efficiency: %.1f%%\n", summary.PoolEfficiency)
//
// # Resetting Metrics
//
// Clear all metrics:
//
//	monitor.Reset()
//	fmt.Println("Metrics reset")
//
// # Uptime Tracking
//
// Get time since monitoring started or was reset:
//
//	uptime := monitor.Uptime()
//	fmt.Printf("Monitoring for: %v\n", uptime)
//
// # Enable/Disable Control
//
// Check if monitoring is enabled:
//
//	if monitor.IsEnabled() {
//	    fmt.Println("Monitoring is active")
//	} else {
//	    fmt.Println("Monitoring is disabled")
//	}
//
// Enable/disable on demand:
//
//	// Enable for specific section
//	monitor.Enable()
//	// ... operations to monitor ...
//	monitor.Disable()
//
// # Comparison with pkg/metrics
//
// Use pkg/monitor when:
//
//   - You need simple performance tracking
//   - You want minimal overhead and dependencies
//   - You don't need error categorization by type
//   - You don't need query size distribution
//   - You don't need separate pool tracking (AST, stmt, expr pools)
//
// Use pkg/metrics when:
//
//   - You need comprehensive production monitoring
//   - You want detailed error tracking by error code
//   - You need query size distribution (min/max/avg)
//   - You need separate metrics for all pool types
//   - You want integration with Prometheus/DataDog/etc.
//
// # Thread Safety
//
// All functions in this package are safe for concurrent use:
//
//   - Enable/Disable: Atomic flag for thread-safe enable/disable
//   - Record* functions: Use atomic operations for counters
//   - GetMetrics: Uses RWMutex for safe concurrent reads
//   - Reset: Uses write lock to safely clear all metrics
//
// The package has been validated to be race-free under concurrent access.
//
// # Performance Impact
//
// When disabled:
//
//   - All Record* functions check atomic flag and return immediately
//   - Overhead: ~1-2ns per call (negligible)
//
// When enabled:
//
//   - Atomic increment operations for counters
//   - Mutex-protected duration updates
//   - Overhead: ~50-100ns per call (minimal)
//
// # Production Integration
//
// Example with periodic reporting:
//
//	import "time"
//
//	ticker := time.NewTicker(60 * time.Second)
//	go func() {
//	    for range ticker.C {
//	        summary := monitor.GetSummary()
//
//	        log.Printf("Performance: %.0f ops/sec, %.2f%% errors, %.1f%% pool efficiency",
//	            summary.OperationsPerSecond,
//	            summary.ErrorRate,
//	            summary.PoolEfficiency)
//
//	        // Alert on performance degradation
//	        if summary.OperationsPerSecond < 100000 {
//	            log.Printf("WARNING: Low throughput detected")
//	        }
//	        if summary.ErrorRate > 5.0 {
//	            log.Printf("WARNING: High error rate detected")
//	        }
//	        if summary.PoolEfficiency < 80.0 {
//	            log.Printf("WARNING: Low pool efficiency")
//	        }
//	    }
//	}()
//
// # Design Principles
//
// The monitor package follows GoSQLX design philosophy:
//
//   - Simplicity: Focused on core metrics only
//   - Low Overhead: Minimal performance impact
//   - Thread-Safe: Safe for concurrent use
//   - Zero Dependencies: Only uses Go standard library
//
// # Version
//
// This package is part of GoSQLX v1.6.0 and is production-ready for use.
//
// For complete examples, see:
//   - docs/USAGE_GUIDE.md - Comprehensive usage documentation
//   - examples/ directory - Production-ready examples
package monitor
