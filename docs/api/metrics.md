# metrics package

Production counters and timings for tokenizer and parser operations.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/metrics` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/metrics))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Configuration

### `Enable()`
Enable metrics collection.

```go
metrics.Enable()
```

### `Disable()`
Disable metrics collection.

### `IsEnabled() bool`
Check if enabled.

### `Reset()`
Reset all metrics.

## Recording Functions

### `RecordTokenization(querySize int, tokenCount int)`
Record tokenization metrics.

### `RecordParsing(success bool, duration time.Duration)`
Record parsing metrics.

### `RecordPoolGet(poolName string)`
Record pool get operation.

### `RecordPoolPut(poolName string)`
Record pool put operation.

### `RecordPoolHit(poolName string)`
Record pool cache hit.

### `RecordPoolMiss(poolName string)`
Record pool cache miss.

### `RecordError(errType string)`
Record error occurrence.

## Query Functions

### `GetSnapshot() MetricsSnapshot`
Get current metrics snapshot.

```go
snapshot := metrics.GetSnapshot()
fmt.Printf("Total queries: %d\n", snapshot.TotalQueries)
fmt.Printf("Success rate: %.2f%%\n", snapshot.SuccessRate)
```

### `MetricsSnapshot`
```go
type MetricsSnapshot struct {
    TotalQueries      int64
    SuccessfulQueries int64
    FailedQueries     int64
    SuccessRate       float64
    TotalTokens       int64
    AvgTokensPerQuery float64
    PoolStats         map[string]PoolStats
    ErrorCounts       map[string]int64
}
```

### `PoolStats`
```go
type PoolStats struct {
    Gets    int64
    Puts    int64
    Hits    int64
    Misses  int64
    HitRate float64
}
```

**v1.6.0 Enhancements:**
- Parser operation metrics (duration, errors, statement counts)
- AST pool metrics (gets/puts/balance)
- Statement pool metrics
- Expression pool metrics
- Tokenizer pool metrics with hit rate tracking
- Thread-safe atomic counters
