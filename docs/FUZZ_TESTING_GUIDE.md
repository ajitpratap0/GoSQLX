# Fuzz Testing Guide

This guide explains how to use and extend the fuzz testing infrastructure in GoSQLX.

## Overview

GoSQLX includes comprehensive fuzz testing for the tokenizer and parser components. Fuzz testing automatically generates test inputs to discover edge cases, security vulnerabilities, and unexpected behaviors.

## Quick Start

### Run Basic Fuzz Tests

```bash
# Fuzz tokenizer for 30 seconds
go test -fuzz=FuzzTokenizer -fuzztime=30s ./pkg/sql/tokenizer/

# Fuzz parser for 30 seconds
go test -fuzz=FuzzParser -fuzztime=30s ./pkg/sql/parser/
```

### Run All Fuzz Tests

```bash
# Tokenizer tests
go test -fuzz=FuzzTokenizer$ -fuzztime=30s -run=^Fuzz ./pkg/sql/tokenizer/
go test -fuzz=FuzzTokenizerUTF8Boundary -fuzztime=30s -run=^Fuzz ./pkg/sql/tokenizer/
go test -fuzz=FuzzTokenizerNumericLiterals -fuzztime=30s -run=^Fuzz ./pkg/sql/tokenizer/

# Parser tests
go test -fuzz=FuzzParser$ -fuzztime=30s -run=^Fuzz ./pkg/sql/parser/
go test -fuzz=FuzzParserRecursionDepth -fuzztime=30s -run=^Fuzz ./pkg/sql/parser/
```

## Available Fuzz Tests

### Tokenizer Fuzz Tests

#### FuzzTokenizer
Main tokenizer fuzzing function that tests:
- Valid SQL queries
- SQL injection patterns
- Deeply nested structures
- Unicode/international characters
- Edge cases and malformed input

#### FuzzTokenizerUTF8Boundary
Tests UTF-8 boundary conditions:
- Multi-byte characters
- Emoji handling
- International text
- Character encoding edge cases

#### FuzzTokenizerNumericLiterals
Tests numeric parsing:
- Scientific notation
- Negative numbers
- Floating point
- Edge cases like `.123` or `123.`

#### FuzzTokenizerStringLiterals
Tests string parsing:
- Escaped quotes
- Empty strings
- Special characters
- Multi-line strings

#### FuzzTokenizerOperators
Tests operator tokenization:
- Comparison operators (=, !=, <>, <, >)
- Arithmetic operators (+, -, *, /, %)
- Logical operators (AND, OR, NOT)
- String concatenation (||)

#### FuzzTokenizerComments
Tests comment handling:
- Single-line comments (`--`)
- Block comments (`/* */`)
- Nested comments
- Comments with special characters

#### FuzzTokenizerWhitespace
Tests whitespace handling:
- Spaces, tabs, newlines
- Mixed whitespace
- Multiple consecutive whitespace

### Parser Fuzz Tests

#### FuzzParser
Main parser fuzzing function that tests:
- All SQL statement types
- Complex queries with JOINs, CTEs, set operations
- Window functions
- Deeply nested expressions
- Malformed AST structures

#### FuzzParserRecursionDepth
Tests recursion depth limits:
- Deeply nested subqueries
- MaxRecursionDepth enforcement
- Stack overflow prevention

#### FuzzParserExpressions
Tests expression parsing:
- Arithmetic expressions
- Logical expressions
- Function calls
- CASE statements

#### FuzzParserOperatorPrecedence
Tests operator precedence:
- Mixed arithmetic and logical operators
- Parenthesized expressions
- Precedence validation

#### FuzzParserWindowFunctions
Tests window function parsing:
- OVER clause variations
- PARTITION BY
- ORDER BY
- Frame specifications

#### FuzzParserCTEs
Tests CTE parsing:
- Simple CTEs
- Recursive CTEs
- Multiple CTEs
- CTE with column specifications

#### FuzzParserJoins
Tests JOIN parsing:
- All JOIN types
- Multi-table joins
- JOIN conditions
- USING clause

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

## Seed Corpus Examples

The fuzz tests include comprehensive seed corpus covering:

### Valid SQL Queries
```sql
SELECT * FROM users
SELECT id, name FROM users WHERE active = true
INSERT INTO users (name, email) VALUES ('John', 'john@example.com')
UPDATE users SET name = 'Jane' WHERE id = 1
DELETE FROM users WHERE id = 1
```

### SQL Injection Patterns
```sql
' OR 1=1 --
'; DROP TABLE users; --
1' UNION SELECT * FROM users --
admin'--
' OR 'a'='a
```

### Deeply Nested Structures
```sql
SELECT (((((((((1)))))))))
SELECT * FROM (SELECT * FROM (SELECT * FROM users))
```

### International Characters
```sql
-- French
SELECT * FROM utilisateurs WHERE nom = 'François'

-- Japanese
SELECT * FROM ユーザー WHERE 名前 = '太郎'

-- Arabic
SELECT * FROM مستخدمين WHERE اسم = 'أحمد'
```

### Complex Queries
```sql
-- CTE
WITH RECURSIVE cte AS (
  SELECT 1
  UNION ALL
  SELECT n+1 FROM cte WHERE n < 10
) SELECT * FROM cte

-- Window Function
SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees

-- Multiple JOINs
SELECT * FROM a LEFT JOIN b ON a.id = b.a_id RIGHT JOIN c ON b.id = c.b_id
```

## Adding New Seed Corpus

To add new test cases to the seed corpus:

```go
func FuzzTokenizer(f *testing.F) {
    // Add your new seed case
    f.Add([]byte("SELECT * FROM new_test_case"))

    // Existing seeds...
    f.Add([]byte("SELECT * FROM users"))

    f.Fuzz(func(t *testing.T, data []byte) {
        // Fuzzing logic...
    })
}
```

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
go test -fuzz=FuzzTokenizer -fuzztime=1m ./pkg/sql/tokenizer/
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Fuzz Testing

on:
  schedule:
    # Run weekly
    - cron: '0 2 * * 0'
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Fuzz Tokenizer
        run: |
          go test -fuzz=FuzzTokenizer -fuzztime=5m ./pkg/sql/tokenizer/

      - name: Fuzz Parser
        run: |
          go test -fuzz=FuzzParser -fuzztime=5m ./pkg/sql/parser/

      - name: Upload Corpus
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: fuzz-corpus
          path: |
            pkg/sql/tokenizer/testdata/fuzz/
            pkg/sql/parser/testdata/fuzz/
```

### Pre-Commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running quick fuzz tests..."
go test -fuzz=FuzzTokenizer -fuzztime=30s ./pkg/sql/tokenizer/ || exit 1
go test -fuzz=FuzzParser -fuzztime=30s ./pkg/sql/parser/ || exit 1
echo "Fuzz tests passed!"
```

## Best Practices

### 1. Run Fuzz Tests Regularly
```bash
# Daily development
go test -fuzz=FuzzTokenizer -fuzztime=1m ./pkg/sql/tokenizer/

# Before release
go test -fuzz=FuzzTokenizer -fuzztime=30m ./pkg/sql/tokenizer/
```

### 2. Use Race Detection
```bash
go test -race -fuzz=FuzzTokenizer -fuzztime=30s ./pkg/sql/tokenizer/
```

### 3. Monitor Performance
Track fuzzing metrics over time:
- Executions per second
- New interesting cases discovered
- Corpus size growth

### 4. Keep Corpus Manageable
- Commit valuable corpus entries to repo
- Prune redundant cases periodically
- Balance coverage vs. corpus size

### 5. Document Findings
Add comments to regression tests explaining:
- What input caused the crash
- Why it crashed
- How it was fixed

## Troubleshooting

### Fuzz Test Takes Too Long
```bash
# Reduce fuzz time
go test -fuzz=FuzzTokenizer -fuzztime=10s ./pkg/sql/tokenizer/

# Reduce parallelism
go test -fuzz=FuzzTokenizer -fuzztime=30s -parallel=4 ./pkg/sql/tokenizer/
```

### Out of Memory
```bash
# Limit corpus size
export GOCACHE_MAXSIZE=100MB

# Or clear cache
go clean -fuzzcache
```

### Too Many Workers
```bash
# Control worker count
GOMAXPROCS=4 go test -fuzz=FuzzTokenizer -fuzztime=30s ./pkg/sql/tokenizer/
```

## Advanced Usage

### Continuous Fuzzing with OSS-Fuzz

For production projects, integrate with [OSS-Fuzz](https://github.com/google/oss-fuzz):

1. Submit project to OSS-Fuzz
2. OSS-Fuzz runs fuzz tests continuously
3. Automatically files issues for crashes
4. Provides detailed crash reports

### Custom Fuzzing Duration

```bash
# Fuzz for specific time
go test -fuzz=FuzzTokenizer -fuzztime=10m ./pkg/sql/tokenizer/

# Fuzz for specific executions
go test -fuzz=FuzzTokenizer -fuzztime=1000000x ./pkg/sql/tokenizer/
```

### Parallel Fuzzing

```bash
# Run multiple fuzz tests in parallel
parallel -j4 go test -fuzz={} -fuzztime=5m ./pkg/sql/{}/  ::: \
    FuzzTokenizer:tokenizer \
    FuzzParser:parser \
    FuzzTokenizerUTF8Boundary:tokenizer \
    FuzzParserRecursionDepth:parser
```

## Resources

- [Go Fuzzing Documentation](https://go.dev/doc/fuzz/)
- [Fuzzing Tutorial](https://go.dev/security/fuzz/)
- [GoSQLX Test Report](../TEST-004_FUZZ_TESTING_REPORT.md)

## Contributing

When contributing to GoSQLX:

1. Run fuzz tests before submitting PR
2. Add seed corpus for new features
3. Document any discovered edge cases
4. Update regression tests as needed

```bash
# Pre-PR checklist
go test -fuzz=FuzzTokenizer -fuzztime=1m ./pkg/sql/tokenizer/
go test -fuzz=FuzzParser -fuzztime=1m ./pkg/sql/parser/
go test ./...
```

---

**Last Updated**: 2025-11-06
**GoSQLX Version**: 1.4.0+
**Fuzzing Coverage**: Comprehensive (938 lines of fuzz code)
