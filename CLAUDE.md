# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoSQLX is a **production-ready**, **race-free**, high-performance SQL parsing SDK for Go that provides lexing, parsing, and AST generation with zero-copy optimizations. The library is designed for enterprise use with comprehensive object pooling for memory efficiency.

### **Production Status**: ✅ **VALIDATED FOR PRODUCTION DEPLOYMENT**
- **Thread Safety**: Confirmed race-free through comprehensive concurrent testing
- **Performance**: 1.38M+ operations/second sustained, up to 1.5M peak with memory-efficient object pooling
- **International**: Full Unicode support for global SQL processing  
- **Reliability**: 95%+ success rate on real-world SQL queries
- **Standards**: Multi-dialect SQL compatibility (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- **SQL Compliance**: ~80-85% SQL-99 compliance (includes window functions, CTEs, set operations)

## Architecture

### Core Components

- **Tokenizer** (`pkg/sql/tokenizer/`): Zero-copy SQL lexer that converts SQL text into tokens
- **Parser** (`pkg/sql/parser/`): Recursive descent parser that builds AST from tokens
- **AST** (`pkg/sql/ast/`): Abstract Syntax Tree nodes with comprehensive SQL statement support
- **Keywords** (`pkg/sql/keywords/`): Categorized SQL keyword definitions across dialects
- **Models** (`pkg/models/`): Core data structures (tokens, spans, locations, errors)
- **Metrics** (`pkg/metrics/`): Production performance monitoring and observability

### Object Pooling Architecture

The codebase uses extensive object pooling for performance optimization:
- **AST Pool**: `ast.NewAST()` / `ast.ReleaseAST()` - Main AST container management
- **Tokenizer Pool**: `tokenizer.GetTokenizer()` / `tokenizer.PutTokenizer()` - Tokenizer instance reuse
- **Statement Pools**: Individual pools for SELECT, INSERT, UPDATE, DELETE statements
- **Expression Pools**: Pools for identifiers, binary expressions, literal values
- **Buffer Pool**: Internal buffer reuse in tokenizer operations

### Token Processing Flow

1. **Input**: Raw SQL bytes → `tokenizer.Tokenize()` → `[]models.TokenWithSpan`
2. **Conversion**: Token conversion → `parser.convertTokens()` → `[]token.Token` 
3. **Parsing**: Parser consumption → `parser.Parse()` → `*ast.AST`
4. **Cleanup**: Release pooled objects back to pools when done

## Development Commands

### Building and Testing
```bash
# Build the project
make build
go build -v ./...

# Run all tests
make test
go test -v ./...

# Run a single test by pattern
go test -v -run TestTokenizer_SimpleSelect ./pkg/sql/tokenizer/
go test -v -run TestParser_.*Window.* ./pkg/sql/parser/

# Run tests for specific packages
go test -v ./pkg/sql/tokenizer/
go test -v ./pkg/sql/parser/
go test -v ./pkg/sql/ast/

# Run tests with coverage report
make coverage
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run benchmarks
go test -bench=. -benchmem ./...
go test -bench=BenchmarkTokenizer -benchmem ./pkg/sql/tokenizer/
go test -bench=BenchmarkParser -benchmem ./pkg/sql/parser/
```

### Code Quality
```bash
# Format code
make fmt
go fmt ./...

# Vet code
make vet  
go vet ./...

# Run linting (requires golint installation)
make lint
golint ./...

# Run all quality checks
make quality

# CRITICAL: Always run race detection during development
go test -race ./...
go test -race -benchmem ./...
go test -race -timeout 30s ./pkg/...
```

### Running Examples
```bash
# Basic example (demonstrates tokenization and parsing)
cd examples/cmd/
go run example.go

# SQL validator example
cd examples/sql-validator/
go run main.go

# SQL formatter example  
cd examples/sql-formatter/
go run main.go

# Run example tests
cd examples/cmd/
go test -v example_test.go
```

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
Tests are organized with comprehensive coverage (24 test files, 6 benchmark files):

- **Unit Tests**: `*_test.go` files for component testing
- **Integration Tests**: Real-world SQL query validation in examples
- **Performance Tests**: `*_bench_test.go` files with memory allocation tracking
- **Race Detection**: Concurrent usage validation across all components
- **Memory Tests**: Pool efficiency and leak detection
- **Scalability Tests**: Load testing with sustained throughput validation

### Component-Specific Testing
```bash
# Core library testing with race detection
go test -race ./pkg/sql/tokenizer/ -v
go test -race ./pkg/sql/parser/ -v
go test -race ./pkg/sql/ast/ -v
go test -race ./pkg/sql/keywords/ -v
go test -race ./pkg/metrics/ -v

# Performance benchmarking with memory tracking
go test -bench=. -benchmem ./pkg/...

# Window functions specific testing (Phase 2.5)
go test -v -run TestParser_.*Window.* ./pkg/sql/parser/

# Comprehensive validation
go test -race -timeout 60s ./...
```

### Production Deployment Requirements
1. **Race Detection**: Always run with race detection during development and CI/CD
2. **Memory Monitoring**: Object pools should maintain stable memory usage
3. **Load Testing**: Validate with realistic SQL workloads matching application usage
4. **Unicode Validation**: Test international character handling if applicable
5. **Concurrent Patterns**: Test access patterns matching production usage

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
- `models` → Core types (no dependencies)
- `keywords` → Depends on `models` only
- `tokenizer` → Depends on `models`, `keywords`, `metrics`
- `parser` → Depends on `tokenizer`, `ast`, `token`
- `ast` → Depends on `token` only (minimal coupling)
- `metrics` → Standalone monitoring (no dependencies)

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

## Current SQL Feature Support (v1.3.0)

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