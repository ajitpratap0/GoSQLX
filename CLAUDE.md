# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoSQLX is a **production-ready**, **race-free**, high-performance SQL parsing SDK for Go that provides lexing, parsing, and AST generation with zero-copy optimizations. The library is designed for enterprise use with comprehensive object pooling for memory efficiency.

**Requirements**: Go 1.24+


### **Production Status**: ✅ **VALIDATED FOR PRODUCTION DEPLOYMENT** (v1.6.0+)
- **Thread Safety**: Confirmed race-free through comprehensive concurrent testing
- **Performance**: 1.38M+ operations/second sustained, up to 1.5M peak with memory-efficient object pooling
- **International**: Full Unicode support for global SQL processing
- **Reliability**: 95%+ success rate on real-world SQL queries
- **Standards**: Multi-dialect SQL compatibility (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- **SQL Compliance**: ~80-85% SQL-99 compliance (includes window functions, CTEs, set operations)
- **Test Coverage**: AST package 73.4%, Models package 100% coverage

## Architecture

### Core Components

- **Tokenizer** (`pkg/sql/tokenizer/`): Zero-copy SQL lexer that converts SQL text into tokens
- **Parser** (`pkg/sql/parser/`): Recursive descent parser that builds AST from tokens
- **AST** (`pkg/sql/ast/`): Abstract Syntax Tree nodes with comprehensive SQL statement support
- **Keywords** (`pkg/sql/keywords/`): Categorized SQL keyword definitions across dialects
- **Models** (`pkg/models/`): Core data structures (tokens, spans, locations, errors) - 100% test coverage
- **Errors** (`pkg/errors/`): Structured error handling system with error codes and position tracking
- **Metrics** (`pkg/metrics/`): Production performance monitoring and observability
- **Security** (`pkg/sql/security/`): SQL injection detection with pattern scanning and severity classification
- **Linter** (`pkg/linter/`): SQL linting engine with 10 built-in rules (L001-L010) for style enforcement
- **CLI** (`cmd/gosqlx/`): Production-ready command-line tool for SQL validation, formatting, and analysis
- **LSP** (`pkg/lsp/`): Language Server Protocol server for IDE integration (diagnostics, hover, completion, formatting)

### Object Pooling Architecture

The codebase uses extensive object pooling for performance optimization:
- **AST Pool**: `ast.NewAST()` / `ast.ReleaseAST()` - Main AST container management
- **Tokenizer Pool**: `tokenizer.GetTokenizer()` / `tokenizer.PutTokenizer()` - Tokenizer instance reuse
- **Statement Pools**: Individual pools for SELECT, INSERT, UPDATE, DELETE statements
- **Expression Pools**: Pools for identifiers, binary expressions, literal values
- **Buffer Pool**: Internal buffer reuse in tokenizer operations

### Token Processing Flow

1. **Input**: Raw SQL bytes → `tokenizer.Tokenize()` → `[]models.TokenWithSpan`
2. **Conversion**: Token conversion → `parser.ConvertTokensForParser()` → `[]token.Token`
3. **Parsing**: Parser consumption → `parser.Parse()` → `*ast.AST`
4. **Cleanup**: Release pooled objects back to pools when done

## Development Commands

This project uses [Task](https://taskfile.dev) as the task runner. Install with:
```bash
go install github.com/go-task/task/v3/cmd/task@latest
# Or: brew install go-task (macOS)
```

### Building and Testing
```bash
# Show all available tasks
task

# Build all packages
task build

# Build the CLI binary
task build:cli

# Build CLI for all platforms
task build:cli:all

# Install CLI globally
task install

# Run all tests
task test

# Run tests with race detection (CRITICAL)
task test:race

# Run tests for specific package
task test:pkg PKG=./pkg/sql/parser

# Run tests in short mode
task test:short

# Run tests with coverage report
task coverage

# Show coverage by function
task coverage:func

# Run benchmarks
task bench

# Run benchmarks with CPU profiling
task bench:cpu

# Run fuzz tests
task fuzz
```

### Code Quality
```bash
# Format code
task fmt

# Check formatting (fails if not formatted)
task fmt:check

# Run go vet
task vet

# Run golangci-lint
task lint

# Run golangci-lint with auto-fix
task lint:fix

# Run staticcheck
task staticcheck

# Run all quality checks (fmt, vet, lint)
task quality

# Full check suite (format, vet, lint, test:race)
task check

# CRITICAL: Always run race detection during development
task test:race
```

### Pre-commit Hooks
The repository has pre-commit hooks that automatically run on every commit:
1. `go fmt` - Code formatting check
2. `go vet` - Static analysis
3. `go test -short` - Short test suite

If a commit fails pre-commit checks, fix the issues and retry the commit.

### Security
```bash
# Run security vulnerability scan
task security:scan

# Validate security setup
task security:validate
```

### CI/CD
```bash
# Run full CI pipeline
task ci

# Quick CI check (no race detection)
task ci:quick
```

### Running Examples
```bash
# Run basic example
task examples

# Run example tests
task examples:test

# Or run directly:
go run ./examples/cmd/example.go
```

### CLI Tool Usage (v1.4.0+)
```bash
# Validate SQL syntax
./gosqlx validate "SELECT * FROM users WHERE active = true"

# Format SQL files with intelligent indentation
./gosqlx format -i query.sql

# Analyze SQL structure and complexity
./gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"

# Parse SQL to AST representation (JSON format)
./gosqlx parse -f json complex_query.sql

# Start LSP server for IDE integration
./gosqlx lsp
./gosqlx lsp --log /tmp/lsp.log  # With debug logging

# Install globally
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
```

### Additional Documentation
- `docs/GETTING_STARTED.md` - Quick start guide for new users
- `docs/USAGE_GUIDE.md` - Comprehensive usage guide
- `docs/LSP_GUIDE.md` - Complete LSP server documentation and IDE integration
- `docs/LINTING_RULES.md` - All 10 linting rules (L001-L010) reference
- `docs/CONFIGURATION.md` - Configuration file (.gosqlx.yml) guide
- `docs/SQL_COMPATIBILITY.md` - SQL dialect compatibility matrix

## Key Implementation Details

### Memory Management (CRITICAL FOR PERFORMANCE)
**Always use `defer` with pool return functions** - prevents resource leaks and maintains performance:

```go
// CORRECT usage pattern for tokenizer
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY

// CORRECT usage pattern for AST
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)       // MANDATORY

// Use objects
tokens, err := tkz.Tokenize(sqlBytes)
result, err := parser.Parse(tokens)
```

- **Performance Impact**: Object pooling provides 60-80% memory reduction
- **Thread Safety**: All pool operations are race-condition free (validated)
- **Pool Efficiency**: 95%+ hit rate in production workloads

### Parser Architecture
- **Type**: Recursive descent parser with one-token lookahead
- **Location**: `pkg/sql/parser/parser.go` 
- **Statement Support**: DDL (CREATE, ALTER, DROP) and DML (SELECT, INSERT, UPDATE, DELETE)
- **Phase 2.5 Window Functions**: Complete SQL-99 window function support:
  - `parseFunctionCall()` - Function calls with OVER clause detection
  - `parseWindowSpec()` - PARTITION BY, ORDER BY, frame clause parsing
  - `parseWindowFrame()` - ROWS/RANGE frame specifications
  - `parseFrameBound()` - Individual frame bound parsing with expressions
- **Phase 2 Advanced Features**: CTEs (WITH clause), recursive CTEs, set operations (UNION/EXCEPT/INTERSECT)
- **Phase 1 JOIN Support**: All JOIN types with proper left-associative tree logic

### AST Node Hierarchy
- **Base Interface**: All nodes implement `Node` interface (TokenLiteral, Children methods)
- **Statement Interface**: `Statement` extends `Node` for SQL statements
- **Expression Interface**: `Expression` extends `Node` for SQL expressions  
- **Visitor Pattern**: Support in `pkg/sql/ast/visitor.go` for tree traversal
- **Pool Integration**: All major node types have dedicated pool management

### Tokenizer Features
- **Zero-Copy Operations**: Direct byte slice operations without string allocation
- **Position Tracking**: Line/column information for error reporting
- **Token Types**: String literals, numbers, operators, keywords with proper categorization
- **Unicode Support**: Full UTF-8 support for international SQL queries
- **Dialect Support**: Multi-database keyword handling (PostgreSQL, MySQL, etc.)

### Error Handling System (`pkg/errors/`)
- **Structured Errors**: Error codes with categorization (syntax, semantic, etc.)
- **Position Information**: Precise line/column tracking for error location
- **Context Preservation**: Error messages include relevant SQL context
- **Error Recovery**: Parser can recover from certain errors and continue parsing
- **Usage Pattern**: Always check errors returned from tokenizer and parser operations

### Performance Monitoring Integration
- **Package**: `pkg/metrics/` provides production monitoring capabilities
- **Atomic Counters**: Lock-free performance tracking across components
- **Pool Metrics**: Tracks pool hit rates, gets/puts, memory efficiency
- **Query Metrics**: Size tracking, operation counts, error categorization

## Production Readiness Status

### ✅ **FULLY VALIDATED FOR PRODUCTION USE**
GoSQLX has passed comprehensive enterprise-grade testing:

- **Race Detection**: ✅ ZERO race conditions (20,000+ concurrent operations tested)
- **Performance**: ✅ 1.5M ops/sec peak, 1.38M+ sustained, memory efficient with pooling
- **Unicode Support**: ✅ Full international compliance (8 languages tested)  
- **SQL Compatibility**: ✅ Multi-dialect support with 115+ real-world queries validated
- **Memory Management**: ✅ Zero leaks detected, stable under extended load
- **Error Handling**: ✅ Robust error recovery with position information

### Quality Metrics
- **Thread Safety**: ⭐⭐⭐⭐⭐ Race-free codebase confirmed
- **Performance**: ⭐⭐⭐⭐⭐ 1.38M+ ops/sec sustained, 1.5M peak, 8M tokens/sec
- **Reliability**: ⭐⭐⭐⭐⭐ 95%+ success rate on real-world SQL
- **Memory Efficiency**: ⭐⭐⭐⭐⭐ 60-80% reduction with pooling
- **Latency**: ⭐⭐⭐⭐⭐ <1μs for complex queries with window functions

## Testing Methodology

### **Always Use Race Detection**
Race detection is mandatory during development and CI/CD:

```bash
# MANDATORY: Always run tests with race detection
go test -race ./...
go test -race -timeout 30s ./pkg/...
go test -race -timeout 60s -v ./...
```

### Testing Structure
Tests are organized with comprehensive coverage (30+ test files, 6 benchmark files):

- **Unit Tests**: `*_test.go` files for component testing
- **Integration Tests**: Real-world SQL query validation in examples
- **Performance Tests**: `*_bench_test.go` files with memory allocation tracking
- **Race Detection**: Concurrent usage validation across all components
- **Memory Tests**: Pool efficiency and leak detection
- **Scalability Tests**: Load testing with sustained throughput validation

### Coverage Status by Package
- **pkg/models/**: 100% coverage - All core data structures fully tested
- **pkg/sql/ast/**: 73.4% coverage - AST nodes with comprehensive edge case testing
- **pkg/sql/tokenizer/**: High coverage - Zero-copy operations validated
- **pkg/sql/parser/**: High coverage - All SQL features tested including window functions
- **pkg/sql/keywords/**: High coverage - Multi-dialect keyword recognition
- **pkg/metrics/**: High coverage - Concurrent metric tracking validated

### Component-Specific Testing
```bash
# Run a single test by name
go test -v -run TestSpecificTestName ./pkg/sql/parser/

# Run tests matching a pattern
go test -v -run "TestParser_Window.*" ./pkg/sql/parser/

# Core library testing with race detection
go test -race ./pkg/sql/tokenizer/ -v
go test -race ./pkg/sql/parser/ -v
go test -race ./pkg/sql/ast/ -v
go test -race ./pkg/sql/keywords/ -v
go test -race ./pkg/models/ -v
go test -race ./pkg/errors/ -v
go test -race ./pkg/metrics/ -v

# Performance benchmarking with memory tracking
go test -bench=. -benchmem ./pkg/...

# Window functions specific testing (Phase 2.5)
go test -v -run TestParser_.*Window.* ./pkg/sql/parser/

# Test coverage for specific packages
go test -coverprofile=coverage.out ./pkg/models/ && go tool cover -func=coverage.out
go test -coverprofile=coverage.out ./pkg/sql/ast/ && go tool cover -func=coverage.out

# Comprehensive validation
go test -race -timeout 60s ./...
```

### Production Deployment Requirements
1. **Race Detection**: Always run with race detection during development and CI/CD
2. **Memory Monitoring**: Object pools should maintain stable memory usage
3. **Load Testing**: Validate with realistic SQL workloads matching application usage
4. **Unicode Validation**: Test international character handling if applicable
5. **Concurrent Patterns**: Test access patterns matching production usage

## Common Development Workflows

### Adding a New SQL Feature
1. **Update Token Types** (if needed): Add new tokens to `pkg/models/token.go`
2. **Update Keywords** (if needed): Add keywords to `pkg/sql/keywords/`
3. **Extend AST Nodes**: Add new node types to `pkg/sql/ast/`
4. **Update Parser**: Add parsing logic to `pkg/sql/parser/parser.go`
5. **Add Tests**: Create comprehensive tests covering edge cases
6. **Run Validation**: `go test -race ./... && go test -bench=. -benchmem ./...`
7. **Update Documentation**: Update CHANGELOG.md and relevant docs

### Debugging Parsing Issues
```bash
# Enable verbose output for tokenizer
go test -v -run TestTokenizer_YourTest ./pkg/sql/tokenizer/

# Debug parser with specific SQL
go test -v -run TestParser_YourTest ./pkg/sql/parser/

# Check token generation
# Write a small test in pkg/sql/tokenizer/ to print tokens

# Verify AST structure
# Use the visitor pattern in pkg/sql/ast/visitor.go to traverse and inspect
```

### Performance Testing New Features
```bash
# Benchmark specific feature
go test -bench=BenchmarkYourFeature -benchmem -cpuprofile=cpu.prof ./pkg/sql/parser/

# Analyze profile
go tool pprof cpu.prof

# Memory profiling
go test -bench=BenchmarkYourFeature -benchmem -memprofile=mem.prof ./pkg/sql/parser/
go tool pprof mem.prof

# Race detection during benchmark
go test -race -bench=BenchmarkYourFeature ./pkg/sql/parser/
```

## High-Level Architecture

### Cross-Component Interactions

The architecture follows a pipeline design with well-defined interfaces:

1. **Input Processing Pipeline**:
   - Raw SQL bytes → `tokenizer.Tokenize()` → `[]models.TokenWithSpan`
   - Token conversion → `parser.convertTokens()` → `[]token.Token`
   - Parser processing → `parser.Parse()` → `*ast.AST`

2. **Object Pooling Strategy**:
   - **Tokenizer Pool**: `tokenizerPool` manages reusable tokenizer instances
   - **AST Pool**: `astPool` manages AST container objects
   - **Statement Pools**: Individual pools for each statement type (SELECT, INSERT, etc.)
   - **Expression Pools**: Pools for identifiers, binary expressions, literals
   - **Buffer Pool**: Internal byte buffer reuse for tokenization operations

3. **Error Propagation**:
   - Tokenizer errors include detailed position information (`models.Location`)
   - Parser errors maintain token context for debugging
   - All errors bubble up with context preservation for troubleshooting

4. **Performance Monitoring**:
   - `pkg/metrics` package tracks atomic metrics across all components
   - Pool hit rates, operation counts, error categorization
   - Race-free metric collection with `MetricsSnapshot`

### Critical Design Patterns

1. **Zero-Copy Operations**: Tokenizer operates on byte slices without string allocation
2. **Object Pooling**: Extensive use of sync.Pool for all major data structures
3. **Visitor Pattern**: AST nodes support traversal via `ast.Visitor` interface
4. **Recursive Descent**: Parser uses predictive parsing with one-token lookahead
5. **Token Categorization**: Keywords module provides dialect-specific classification

### Module Dependencies

Clean dependency hierarchy with minimal coupling:
- `models` → Core types (no dependencies, 100% test coverage)
- `errors` → Structured error handling (depends on `models`)
- `keywords` → Depends on `models` only
- `tokenizer` → Depends on `models`, `keywords`, `metrics`
- `parser` → Depends on `tokenizer`, `ast`, `token`, `errors`
- `ast` → Depends on `token` only (minimal coupling, 73.4% test coverage)
- `metrics` → Standalone monitoring (no dependencies)
- `cmd/gosqlx` → CLI tool (depends on all packages)

## Release Workflow (CRITICAL - Follow This Process)

### **CORRECT Release Process**
Based on lessons learned from previous releases - main branch is protected:

```bash
# 1. Feature development in PR branch
git checkout feature/branch-name

# 2. Update documentation in PR branch (mark as [Unreleased])
# - Update CHANGELOG.md with comprehensive feature documentation
# - Update README.md with performance highlights and new features
# - DO NOT create version tags yet - this is done post-merge
git add CHANGELOG.md README.md
git commit -m "feat: implement major features (mark as unreleased)"

# 3. Push PR branch and request review
git push origin feature/branch-name
# Create PR via GitHub interface or gh cli

# 4. After PR is merged, create release from main branch
git checkout main && git pull origin main

# 5. Create documentation PR for release finalization
git checkout -b docs/vX.Y.Z-release-updates
# Update CHANGELOG.md to mark as released version with date
git add CHANGELOG.md
git commit -m "docs: finalize vX.Y.Z release documentation"
git push origin docs/vX.Y.Z-release-updates
# Create PR for documentation updates

# 6. After docs PR merged, create release tag
git checkout main && git pull origin main
git tag vX.Y.Z -a -m "vX.Y.Z: Release Title with detailed notes"
git push origin vX.Y.Z

# 7. Create GitHub release from tag
gh release create vX.Y.Z --title "vX.Y.Z: Release Title" --notes "..."
```

**CRITICAL**: Never create version tags in feature PR branches - only after successful merge to main.

### **❌ WRONG Process (Don't Do This)**
These mistakes have been made before - avoid them:
- Creating version tags in PR branches before merge
- Pushing tags before PR is approved and merged  
- Direct commits to main for documentation (main branch is protected)
- Creating releases before proper testing and validation

### **Benefits of Correct Process**
- ✅ All feature changes reviewed together in PR before any release actions
- ✅ Version tags only created on stable, merged, tested code in main branch
- ✅ Clean git history with proper separation of development and release
- ✅ Respects protected main branch rules (enforced by GitHub)
- ✅ Allows for comprehensive testing and validation before tagging
- ✅ Enables rollback if critical issues are found before release

## Current SQL Feature Support (v1.6.0)

### GROUPING SETS, ROLLUP, CUBE (SQL-99 T431) - Complete ✅
```sql
-- GROUPING SETS - explicit grouping combinations
SELECT region, product, SUM(sales)
FROM orders
GROUP BY GROUPING SETS ((region), (product), (region, product), ());

-- ROLLUP - hierarchical subtotals
SELECT year, quarter, month, SUM(revenue)
FROM sales
GROUP BY ROLLUP (year, quarter, month);

-- CUBE - all possible combinations
SELECT region, product, SUM(amount)
FROM sales
GROUP BY CUBE (region, product);
```

### MERGE Statements (SQL:2003 F312) - Complete ✅
```sql
MERGE INTO target_table t
USING source_table s ON t.id = s.id
WHEN MATCHED THEN
    UPDATE SET t.name = s.name, t.value = s.value
WHEN NOT MATCHED THEN
    INSERT (id, name, value) VALUES (s.id, s.name, s.value);
```

### Materialized Views - Complete ✅
```sql
CREATE MATERIALIZED VIEW sales_summary AS
SELECT region, SUM(amount) as total FROM sales GROUP BY region;

REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary;

DROP MATERIALIZED VIEW IF EXISTS sales_summary;
```

### Expression Operators (BETWEEN, IN, LIKE, IS NULL) - Complete ✅
```sql
-- BETWEEN with expressions
SELECT * FROM orders WHERE amount BETWEEN 100 AND 500;

-- IN with subquery
SELECT * FROM users WHERE id IN (SELECT user_id FROM admins);

-- LIKE with pattern matching
SELECT * FROM products WHERE name LIKE '%widget%';

-- IS NULL / IS NOT NULL
SELECT * FROM users WHERE deleted_at IS NULL;

-- NULLS FIRST/LAST ordering (SQL-99 F851)
SELECT * FROM users ORDER BY last_login DESC NULLS LAST;
```

### Window Functions (Phase 2.5) - Complete ✅
```sql
-- Ranking functions
SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees;
SELECT dept, name, RANK() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees;
SELECT name, DENSE_RANK() OVER (ORDER BY score), NTILE(4) OVER (ORDER BY score) FROM tests;

-- Analytic functions with offsets
SELECT name, salary, LAG(salary, 1) OVER (ORDER BY hire_date) as prev_salary FROM employees;
SELECT date, amount, LEAD(amount, 2, 0) OVER (ORDER BY date) as future_amount FROM transactions;

-- Window frames
SELECT date, amount, 
       SUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as rolling_sum,
       AVG(amount) OVER (ORDER BY date RANGE UNBOUNDED PRECEDING) as running_avg
FROM transactions;

-- Complex window specifications
SELECT dept, name, salary,
       FIRST_VALUE(salary) OVER (PARTITION BY dept ORDER BY salary DESC) as dept_max,
       LAST_VALUE(salary) OVER (PARTITION BY dept ORDER BY salary RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) as dept_min
FROM employees;
```

### CTEs and Set Operations (Phase 2) - Complete ✅
```sql
-- Recursive CTE with proper termination
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level FROM employees WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, eh.level + 1 
    FROM employees e JOIN employee_hierarchy eh ON e.manager_id = eh.id
    WHERE eh.level < 10  -- Prevent infinite recursion
)
SELECT * FROM employee_hierarchy ORDER BY level, name;

-- Complex set operations with proper precedence
SELECT product FROM inventory 
UNION SELECT product FROM orders
EXCEPT SELECT product FROM discontinued
INTERSECT SELECT product FROM active_catalog;

-- CTE with set operations
WITH active_products AS (
    SELECT product_id, product_name FROM products WHERE active = true
),
recent_orders AS (
    SELECT product_id, COUNT(*) as order_count FROM orders 
    WHERE order_date > '2023-01-01' GROUP BY product_id
)
SELECT ap.product_name, ro.order_count
FROM active_products ap
LEFT JOIN recent_orders ro ON ap.product_id = ro.product_id;
```

### JOINs (Phase 1) - Complete ✅
```sql
-- Complex JOIN combinations with proper left-associative parsing
SELECT u.name, o.order_date, p.product_name, c.category_name
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
INNER JOIN products p ON o.product_id = p.id
RIGHT JOIN categories c ON p.category_id = c.id
NATURAL JOIN user_preferences up
WHERE u.active = true AND o.order_date > '2023-01-01'
ORDER BY o.order_date DESC;

-- JOIN with USING clause
SELECT u.name, p.title FROM users u
JOIN posts p USING (user_id)
WHERE p.published = true;
```

### PostgreSQL Extensions (v1.6.0) - Complete ✅
```sql
-- LATERAL JOIN - correlated subqueries in FROM clause
SELECT u.name, r.order_date FROM users u,
LATERAL (SELECT * FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 3) r;

-- JSON/JSONB Operators (->/->>/#>/#>>/@>/<@/?/?|/?&/#-)
SELECT data->>'name' AS name, data->'address'->>'city' AS city FROM users;
SELECT * FROM products WHERE attributes @> '{"color": "red"}';
SELECT * FROM users WHERE profile ? 'email';

-- DISTINCT ON - PostgreSQL-specific row selection
SELECT DISTINCT ON (dept_id) dept_id, name, salary
FROM employees ORDER BY dept_id, salary DESC;

-- FILTER Clause - conditional aggregation (SQL:2003)
SELECT COUNT(*) FILTER (WHERE status = 'active') AS active_count,
       SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
FROM transactions;

-- RETURNING Clause - return modified rows
INSERT INTO users (name, email) VALUES ('John', 'john@example.com') RETURNING id, created_at;
UPDATE products SET price = price * 1.1 WHERE category = 'Electronics' RETURNING id, price;
DELETE FROM sessions WHERE expired_at < NOW() RETURNING user_id;
```

### DDL and DML Operations - Complete ✅
```sql
-- Table operations
CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(255));
ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
DROP TABLE temp_data;

-- Data manipulation with comprehensive expression support
INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com');
UPDATE users SET email = 'newemail@example.com' WHERE id = 1;
DELETE FROM users WHERE created_at < '2023-01-01';
```