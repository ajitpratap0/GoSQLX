# Performance Regression Testing

## Overview

GoSQLX includes a comprehensive performance regression test suite to prevent performance degradation over time. The suite tracks key performance metrics against established baselines and alerts developers to regressions.

## Running Performance Tests

### Quick Test (Recommended for CI/CD)

```bash
go test -v ./pkg/sql/parser/ -run TestPerformanceRegression
```

**Execution Time:** ~8 seconds
**Coverage:** 5 critical query types

### Baseline Benchmark (For Establishing New Baselines)

```bash
go test -bench=BenchmarkPerformanceBaseline -benchmem -count=5 ./pkg/sql/parser/
```

**Use Case:** After significant parser changes or optimizations to establish new performance baselines.

## Performance Baselines

Current baselines are stored in `performance_baselines.json` at the project root:

### Tracked Metrics

1. **SimpleSelect** (280 ns/op baseline)
   - Basic SELECT query: `SELECT id, name FROM users`
   - Current: ~265 ns/op (9 allocs, 536 B/op)

2. **ComplexQuery** (1100 ns/op baseline)
   - Complex SELECT with JOIN, WHERE, ORDER BY, LIMIT
   - Current: ~1020 ns/op (36 allocs, 1433 B/op)

3. **WindowFunction** (450 ns/op baseline)
   - Window function: `ROW_NUMBER() OVER (PARTITION BY ... ORDER BY ...)`
   - Current: ~400 ns/op (14 allocs, 760 B/op)

4. **CTE** (450 ns/op baseline)
   - Common Table Expression with WITH clause
   - Current: ~395 ns/op (14 allocs, 880 B/op)

5. **INSERT** (350 ns/op baseline)
   - Simple INSERT statement
   - Current: ~310 ns/op (14 allocs, 536 B/op)

### Tolerance Levels

- **Failure Threshold:** 20% degradation from baseline
- **Warning Threshold:** 10% degradation from baseline (half of tolerance)

## Test Output

### Successful Run

```
================================================================================
PERFORMANCE REGRESSION TEST SUMMARY
================================================================================
✓ All performance tests passed with no warnings

Baseline Version: 1.4.0
Baseline Updated: 2025-01-17
Tests Run: 5
Failures: 0
Warnings: 0
================================================================================
```

### Regression Detected

```
REGRESSIONS DETECTED:
  ✗ ComplexQuery: 25.5% slower (actual: 1381 ns/op, baseline: 1100 ns/op)

WARNINGS (approaching threshold):
  ⚠ SimpleSelect: 12.3% slower (approaching threshold)

Tests Run: 5
Failures: 1
Warnings: 1
```

## Updating Baselines

### When to Update

Update baselines when:
- Intentional optimizations improve performance significantly
- Parser architecture changes fundamentally alter performance characteristics
- New SQL features are added that affect parsing speed

### How to Update

1. Run the baseline benchmark:
   ```bash
   go test -bench=BenchmarkPerformanceBaseline -benchmem -count=5 ./pkg/sql/parser/
   ```

2. Calculate new conservative baselines (add 10-15% buffer to measured values)

3. Update `performance_baselines.json`:
   ```json
   {
     "SimpleSelect": {
       "ns_per_op": <new_baseline>,
       "tolerance_percent": 20,
       "description": "...",
       "current_performance": "<measured_value> ns/op"
     }
   }
   ```

4. Update the `updated` timestamp in the JSON file

5. Commit changes with a clear explanation of why baselines were updated

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Performance Regression Tests
  run: |
    go test -v ./pkg/sql/parser/ -run TestPerformanceRegression
  timeout-minutes: 2
```

### Exit Codes

- **0:** All tests passed
- **1:** Performance regression detected (test failure)

## Troubleshooting

### Test Timing Variance

Performance tests can show variance due to:
- System load
- CPU thermal throttling
- Background processes

**Solution:** Run tests multiple times and average results. The suite uses `testing.Benchmark` which automatically adjusts iteration count for stable measurements.

### False Positives

If you see intermittent failures:
1. Check system load during test execution
2. Run the test 3-5 times to confirm consistency
3. Consider increasing tolerance for that specific baseline

### Baseline Drift

Over time, minor optimizations may accumulate. If current performance is consistently better:
1. Document the improvements
2. Update baselines to reflect the new performance level
3. Keep tolerance at 20% to catch future regressions

## Performance Metrics Guide

### ns/op (Nanoseconds per Operation)
- Lower is better
- Measures parsing speed for a single query
- Most sensitive metric for detecting regressions

### B/op (Bytes per Operation)
- Memory allocated per parse operation
- Tracked in benchmarks but not in regression tests
- Useful for identifying memory leaks

### allocs/op (Allocations per Operation)
- Number of heap allocations per parse
- Lower indicates better object pool efficiency
- Critical for GC pressure

## Related Documentation

- [Benchmark Guide](../CLAUDE.md#performance-testing-new-features)
- [Development Workflow](../CLAUDE.md#common-development-workflows)
- [Production Metrics](../pkg/metrics/README.md)

## Version History

- **v1.4.0** (2025-01-17): Initial performance regression suite
  - 5 baseline metrics established
  - 20% tolerance threshold
  - ~8 second execution time
