# Fuzz Testing Guide

GoSQLX includes comprehensive fuzz testing for the tokenizer and parser components. Fuzz testing automatically generates test inputs to discover edge cases, security vulnerabilities, and unexpected behaviors.

## Quick Start

### Run Fuzz Tests

```bash
# Fuzz specific tokenizer function for 30 seconds
go test -fuzz='^FuzzTokenizer$' -fuzztime=30s ./pkg/sql/tokenizer/
go test -fuzz='^FuzzTokenizerUTF8Boundary$' -fuzztime=30s ./pkg/sql/tokenizer/
go test -fuzz='^FuzzTokenizerNumericLiterals$' -fuzztime=30s ./pkg/sql/tokenizer/
go test -fuzz='^FuzzTokenizerStringLiterals$' -fuzztime=30s ./pkg/sql/tokenizer/

# Run all tokenizer fuzz tests
go test -run=^Fuzz -fuzztime=30s ./pkg/sql/tokenizer/
```

## Available Fuzz Tests

### Tokenizer Fuzz Tests

All tokenizer fuzz tests are located in `pkg/sql/tokenizer/tokenizer_fuzz_test.go`:

- **FuzzTokenizer**: Main fuzzer testing valid queries, SQL injection patterns, nested structures, Unicode, malformed input
- **FuzzTokenizerUTF8Boundary**: UTF-8 boundary conditions with multi-byte characters, emoji, international text
- **FuzzTokenizerNumericLiterals**: Numeric parsing with scientific notation, negative numbers, floating point edge cases
- **FuzzTokenizerStringLiterals**: String parsing with escaped quotes, empty strings, special characters
- **FuzzTokenizerOperators**: Operator tokenization (comparison, arithmetic, logical, concatenation)
- **FuzzTokenizerComments**: Comment handling (single-line `--` and block `/* */` comments)
- **FuzzTokenizerWhitespace**: Whitespace variations (spaces, tabs, newlines, mixed combinations)

### Parser Fuzz Tests

**Note**: Parser fuzz tests are currently implemented via the tokenizer fuzz tests. Parser validation includes all statement types through comprehensive seed corpus testing covering JOINs, CTEs, set operations, window functions, and nested expressions.

## Understanding Fuzz Output

### Successful Run
```
fuzz: elapsed: 15s, execs: 3066334 (209594/sec), new interesting: 387 (total: 387)
PASS
ok  	github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer	16.077s
```

- `elapsed`: Time spent fuzzing
- `execs`: Number of test executions
- `execs/sec`: Throughput
- `new interesting`: Unique code paths discovered
- `PASS`: No crashes found

### Failed Run (Crash Detected)
```
fuzz: elapsed: 5s, execs: 50000, new interesting: 100
--- FAIL: FuzzTokenizer (5.03s)
    fuzzing process hung or terminated unexpectedly: exit status 2
    Failing input written to testdata/fuzz/FuzzTokenizer/1234567890abcdef
```

When a crash is found:
1. Failing input is saved to `testdata/fuzz/`
2. Add the input to `TestFuzzCrashRegression`
3. Fix the underlying issue
4. Verify the regression test passes

## Seed Corpus

The fuzz tests include comprehensive seed corpus covering valid SQL, SQL injection patterns, nested structures, international characters, and complex queries (CTEs, window functions, JOINs). Seed cases are defined in `tokenizer_fuzz_test.go` lines 17-105.

## Adding New Seed Corpus

Add test cases in `FuzzTokenizer` using `f.Add()`:

```go
f.Add([]byte("SELECT * FROM new_test_case"))
```

Seed cases should cover edge cases, novel SQL patterns, or previously discovered crashes.

## Handling Discovered Crashes

When fuzzing discovers a crash:

### 1. Locate the Failing Input
```bash
# Fuzzing will save the input to:
ls pkg/sql/tokenizer/testdata/fuzz/FuzzTokenizer/
```

### 2. Add to Regression Tests
```go
func TestFuzzCrashRegression(t *testing.T) {
    testCases := []struct {
        name  string
        input []byte
    }{
        {
            name: "crash_discovered_2025_11_06",
            input: []byte("...failing input..."),
        },
    }
    // Test logic...
}
```

### 3. Fix the Issue
Debug and fix the underlying vulnerability in tokenizer or parser.

### 4. Verify Fix
```bash
# Run regression test
go test -run=TestFuzzCrashRegression ./pkg/sql/tokenizer/

# Re-run fuzz test
go test -fuzz='^FuzzTokenizer$' -fuzztime=1m ./pkg/sql/tokenizer/
```

## CI/CD Integration

Fuzz tests can be run in CI pipelines. For example, in pre-PR checks:

```bash
# Quick fuzz (30 seconds)
go test -run=^Fuzz -fuzztime=30s ./pkg/sql/tokenizer/

# Extended fuzz for releases (5+ minutes)
go test -run=^Fuzz -fuzztime=5m ./pkg/sql/tokenizer/
```

For weekly continuous fuzzing, configure schedule jobs to run with extended duration (`-fuzztime=1h+`).

## Best Practices

1. **Run regularly**: Daily during development (1m), pre-release (30m+)
2. **Use race detection**: `go test -race -run=^Fuzz -fuzztime=30s ./pkg/sql/tokenizer/`
3. **Monitor metrics**: Track executions/sec and new interesting cases discovered
4. **Manage corpus**: Commit valuable corpus entries to repo; prune redundant cases periodically
5. **Document crashes**: Add detailed comments to regression tests explaining the crash, cause, and fix

## Troubleshooting

**Slow tests**: Reduce duration with `-fuzztime=10s` or parallelism with `-parallel=4`

**Out of memory**: Run `go clean -fuzzcache` or set `GOCACHE_MAXSIZE=100MB`

**Too many workers**: Control with `GOMAXPROCS=4` environment variable

## Advanced Usage

**Custom duration**: Use `-fuzztime=10m` for time-based or `-fuzztime=1000000x` for execution-based fuzzing

**OSS-Fuzz integration**: For continuous fuzzing, submit project to [OSS-Fuzz](https://github.com/google/oss-fuzz)

## Resources

- [Go Fuzzing Documentation](https://go.dev/doc/fuzz/)
- [Go Security Fuzzing Guide](https://go.dev/security/fuzz/)

## Contributing

1. Run fuzz tests before submitting PR: `go test -run=^Fuzz -fuzztime=1m ./pkg/sql/tokenizer/`
2. Add seed corpus for new features via `f.Add()` in the appropriate fuzz function
3. Document discovered edge cases in regression tests with detailed comments
4. Update `TestFuzzCrashRegression` for any crashes found

---

**Last Updated**: 2025-11-28
**GoSQLX Version**: 1.5.1+
**Fuzz Test File**: `pkg/sql/tokenizer/tokenizer_fuzz_test.go` (441 lines, 7 fuzz functions)
