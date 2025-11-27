---
name: Performance issue
about: Report performance problems or suggest optimizations
title: '[PERF] '
labels: 'performance'
assignees: ''
---

## Performance Issue Description
Describe the performance issue you're experiencing.

## Benchmark Results
```
// Include your benchmark results
// go test -bench=. -benchmem
```

## Test Case
```go
// Provide a reproducible test case
```

## SQL Queries Used
```sql
-- Include the SQL queries that exhibit poor performance
```

## Performance Metrics
- **Operations/sec**: 
- **Memory usage**: 
- **Allocations**: 
- **Query size**: 
- **Concurrency level**: 

## Environment
- **OS**: [e.g. macOS, Linux, Windows]
- **CPU**: [e.g. Intel i7, M1]
- **RAM**: [e.g. 16GB]
- **Go Version**: [e.g. 1.24]
- **GoSQLX Version**: [e.g. v1.0.0]

## Expected Performance
What performance levels were you expecting?

## Actual Performance
What performance are you actually seeing?

## Profiling Data
If you have pprof or other profiling data, please attach or link to it.

## Suggested Optimizations
Any ideas on how to improve performance?