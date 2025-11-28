# GoSQLX Architecture Documentation

## Table of Contents
- [System Overview](#system-overview)
- [Package Structure](#package-structure)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Memory Management](#memory-management)
- [Concurrency Model](#concurrency-model)
- [Design Patterns](#design-patterns)
- [Performance Architecture](#performance-architecture)

## System Overview

GoSQLX is a production-ready, high-performance SQL parsing library with comprehensive dialect support, security scanning, and LSP integration.

### Core Design Principles

1. **Zero-Copy Operations**: Minimize memory allocations by working directly with byte slices
2. **Object Pooling**: Reuse expensive objects through sync.Pool
3. **Immutable Tokens**: Tokens are immutable once created
4. **Stateless Parsing**: Parser maintains no global state
5. **Unicode-First**: Full UTF-8 support throughout
6. **Multi-Dialect**: Support for PostgreSQL, MySQL, SQL Server, Oracle, SQLite

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Application Layer & Tools                   │
│         (CLI, LSP Server, Linter, Security)              │
├─────────────────────────────────────────────────────────┤
│                    GoSQLX API (pkg/gosqlx)               │
├──────────────┬────────────────┬────────────────────────┤
│   Tokenizer  │     Parser     │        AST              │
├──────────────┼────────────────┼────────────────────────┤
│  Object Pool │  Token Stream  │   Node Factory          │
├──────────────┴────────────────┴────────────────────────┤
│        Core Models & Error Handling & Metrics            │
└─────────────────────────────────────────────────────────┘
```

## Package Structure

The codebase is organized into focused packages with clear responsibilities:

### Core Packages

- **pkg/models** (100% coverage): Core data structures (tokens, spans, locations)
- **pkg/errors** (91.9% coverage): Structured error handling with position tracking
- **pkg/metrics** (73.9% coverage): Performance monitoring and observability
- **pkg/config** (81.8% coverage): Configuration management

### SQL Processing

- **pkg/sql/tokenizer** (75.3% coverage): Zero-copy SQL lexer
- **pkg/sql/parser** (76.1% coverage): Recursive descent parser
- **pkg/sql/ast** (80.3% coverage): Abstract Syntax Tree nodes
- **pkg/sql/token** (68.8% coverage): Token type definitions
- **pkg/sql/keywords** (100% coverage): SQL keyword categorization
- **pkg/sql/security** (90.2% coverage): SQL injection detection
- **pkg/sql/monitor** (98.6% coverage): Query monitoring

### Tools & Integration

- **pkg/gosqlx** (65.6% coverage): Main API surface
- **pkg/lsp** (70.2% coverage): Language Server Protocol implementation
- **pkg/linter** (96.7% coverage): SQL linting and style checking
- **pkg/compatibility**: Compatibility layer

### Supported SQL Statements (14 types)

ALTER, ALTER TABLE, CREATE INDEX, CREATE MATERIALIZED VIEW, CREATE TABLE,
CREATE VIEW, DELETE, DROP, INSERT, MERGE, REFRESH MATERIALIZED VIEW,
SELECT, TRUNCATE, UPDATE

## Component Architecture

### Tokenizer Component

The tokenizer is responsible for lexical analysis, converting raw SQL bytes into tokens.

```
┌──────────────────────────────────────┐
│           Tokenizer                   │
├──────────────────────────────────────┤
│  ┌──────────────────────────────┐    │
│  │    Input Buffer ([]byte)      │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    Scanner State Machine      │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    Token Recognition          │    │
│  │  - Keywords                   │    │
│  │  - Identifiers                │    │
│  │  - Literals                   │    │
│  │  - Operators                  │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    Position Tracking          │    │
│  │  - Line/Column                │    │
│  │  - Byte Offset                │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    Token Stream Output        │    │
│  └──────────────────────────────┘    │
└──────────────────────────────────────┘
```

**Key Components:**

1. **Scanner State Machine**
   - Handles character-by-character processing
   - Manages state transitions
   - Optimized fast paths for common tokens

2. **Token Recognition Engine**
   - Map-based keyword lookup (O(1))
   - Unicode-aware identifier processing
   - Multi-dialect operator support

3. **Position Tracker**
   - Maintains current position (line, column, byte offset)
   - Handles newline detection
   - Provides error location information

### Parser Component

The parser builds Abstract Syntax Trees from token streams.

```
┌──────────────────────────────────────┐
│            Parser                     │
├──────────────────────────────────────┤
│  ┌──────────────────────────────┐    │
│  │    Token Stream Input         │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    Recursive Descent Parser   │    │
│  │  - Statement Parser           │    │
│  │  - Expression Parser          │    │
│  │  - Clause Parser              │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    AST Node Construction      │    │
│  │  - Node Factory               │    │
│  │  - Type Validation            │    │
│  └──────────┬───────────────────┘    │
│             ▼                         │
│  ┌──────────────────────────────┐    │
│  │    AST Output                 │    │
│  └──────────────────────────────┘    │
└──────────────────────────────────────┘
```

**Parser Modular Architecture:**

The parser is organized into focused modules for maintainability:

```
pkg/sql/parser/
├── parser.go          # Core parser, entry points, and utilities
├── select.go          # SELECT statement parsing
├── dml.go             # INSERT, UPDATE, DELETE, MERGE parsing
├── cte.go             # Common Table Expressions (WITH clause)
├── expressions.go     # Expression parsing (BETWEEN, IN, LIKE, etc.)
├── window.go          # Window functions (OVER, PARTITION BY)
├── grouping.go        # GROUPING SETS, ROLLUP, CUBE
├── alter.go           # ALTER TABLE statements
├── ddl.go             # DDL statements (CREATE, DROP, REFRESH, TRUNCATE)
└── token_converter.go # Token format conversion with position tracking
```

**Statement Parsing Methods:**

The parser supports 14 SQL statement types via these entry points:

```
parseStatement()
├── parseWithStatement()              # WITH (CTEs)
├── parseSelectWithSetOperations()    # SELECT + UNION/EXCEPT/INTERSECT
├── parseInsertStatement()            # INSERT
├── parseUpdateStatement()            # UPDATE
├── parseDeleteStatement()            # DELETE
├── parseMergeStatement()             # MERGE
├── parseCreateStatement()            # CREATE (TABLE, VIEW, MATERIALIZED VIEW, INDEX)
├── parseAlterTableStmt()             # ALTER TABLE
├── parseDropStatement()              # DROP
├── parseRefreshStatement()           # REFRESH MATERIALIZED VIEW
└── parseTruncateStatement()          # TRUNCATE
```

### AST Component

The Abstract Syntax Tree provides structured representation of SQL statements.

**Core Interfaces:**
- `Node`: Base interface for all AST nodes (TokenLiteral, Children methods)
- `Statement`: Extends Node for SQL statements
- `Expression`: Extends Node for SQL expressions

**Statement Types (14 total):**

```go
// DML Statements
SelectStatement             // SELECT with JOINs, window functions, CTEs
InsertStatement            // INSERT with multiple value sets
UpdateStatement            // UPDATE with WHERE clause
DeleteStatement            // DELETE with WHERE clause
MergeStatement             // MERGE with MATCHED/NOT MATCHED clauses
TruncateStatement          // TRUNCATE TABLE

// DDL Statements
CreateTableStatement       // CREATE TABLE with columns, constraints
CreateViewStatement        // CREATE VIEW
CreateMaterializedViewStatement  // CREATE MATERIALIZED VIEW
CreateIndexStatement       // CREATE INDEX
AlterTableStatement        // ALTER TABLE (add/drop columns, constraints)
AlterStatement             // Generic ALTER (roles, policies, etc.)
DropStatement              // DROP (tables, views, indexes)
RefreshMaterializedViewStatement // REFRESH MATERIALIZED VIEW

// Query Composition
WithClause                 // WITH (CTEs) - can contain any statement
SetOperation               // UNION/EXCEPT/INTERSECT
```

**Expression Types:**

```go
// Basic Expressions
Identifier                 // Table/column names
Literal                    // String, number, boolean literals
BinaryExpression          // a + b, a = b, etc.
UnaryExpression           // NOT, -x, etc.

// Complex Expressions
FunctionCall              // func(args) with optional OVER clause
WindowSpec                // Window function specification
BetweenExpression         // x BETWEEN a AND b
InExpression              // x IN (values) or x IN (subquery)
LikeExpression            // x LIKE pattern
IsNullExpression          // x IS NULL / IS NOT NULL
CaseExpression            // CASE WHEN ... THEN ... END

// Grouping
GroupingSet               // Individual grouping set
RollupGrouping            // ROLLUP(columns)
CubeGrouping              // CUBE(columns)
```

## Data Flow

### End-to-End Processing Pipeline

```
SQL Text ([]byte)
         │
         ▼
┌─────────────────────┐
│   Tokenizer         │ ← tokenizer.GetTokenizer()
├─────────────────────┤
│ Lexical Analysis    │
│ - Zero-copy ops     │
│ - Position tracking │
└──────────┬──────────┘
           │ []models.TokenWithSpan (with Location)
           ▼
┌─────────────────────┐
│  Token Converter    │
├─────────────────────┤
│ Models → AST tokens │
│ Position mapping    │
└──────────┬──────────┘
           │ []token.Token + positions
           ▼
┌─────────────────────┐
│      Parser         │ ← parser.GetParser()
├─────────────────────┤
│ Recursive Descent   │
│ AST Construction    │
└──────────┬──────────┘
           │ *ast.AST
           ▼
┌─────────────────────┐
│  Application Use    │
│ - Validation        │
│ - Transformation    │
│ - Code Generation   │
└──────────┬──────────┘
           │
           ▼
    Return to Pools
    (PutTokenizer, PutParser, ReleaseAST)
```

### Token Flow Example

```go
// 1. Input SQL
sql := "SELECT * FROM users"

// 2. Tokenization (pkg/sql/tokenizer)
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens, err := tkz.Tokenize([]byte(sql))
// Returns: []models.TokenWithSpan with position info
// [{Token: SELECT, Start: {Line:1, Col:1}, End: {Line:1, Col:6}}, ...]

// 3. Token conversion (pkg/sql/parser/token_converter.go)
converted, err := parser.ConvertTokensForParser(tokens)
// Returns: []token.Token for parser consumption

// 4. Parsing (pkg/sql/parser)
p := parser.GetParser()
defer parser.PutParser(p)

ast, err := p.Parse(converted)
// Returns: *ast.AST containing statements

// 5. Access parsed structure
selectStmt := ast.Statements[0].(*ast.SelectStatement)
// selectStmt.Columns contains parsed column expressions
// selectStmt.From contains table references
```

## Memory Management

### Object Pool Architecture

GoSQLX uses sync.Pool extensively for performance:

**Pooled Components:**

1. **Tokenizer Pool** (pkg/sql/tokenizer)
   - Pre-allocated token buffers
   - Reusable scanners
   - Access: `tokenizer.GetTokenizer()` / `tokenizer.PutTokenizer()`

2. **Parser Pool** (pkg/sql/parser)
   - Parser instances with state
   - Access: `parser.GetParser()` / `parser.PutParser()`

3. **AST Pool** (pkg/sql/ast)
   - AST container objects
   - Access: `ast.NewAST()` / `ast.ReleaseAST()`

**Critical Usage Pattern:**

```go
// CORRECT - Always use defer for cleanup
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY

p := parser.GetParser()
defer parser.PutParser(p)           // MANDATORY

astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)        // MANDATORY

// Use the objects...
```

**Performance Benefits:**
- 60-80% memory reduction vs non-pooled
- 95%+ pool hit rate in production
- Zero race conditions (validated via race detector)

### Memory Optimization Strategies

1. **Zero-Copy Tokenization**
```go
// Tokens reference original input bytes
type Token struct {
    Type  TokenType
    Value string // Points to original input
}

// No copying during tokenization
func (t *Tokenizer) readIdentifier() Token {
    start := t.pos
    // Scan without copying
    for isIdentifierChar(t.peek()) {
        t.advance()
    }
    // Reference original bytes
    return Token{
        Type:  TokenTypeIdentifier,
        Value: string(t.input[start:t.pos]), // Single allocation
    }
}
```

2. **Buffer Reuse**
```go
type Tokenizer struct {
    // Reusable buffers
    buffer []byte
    tokens []TokenWithSpan
}

func (t *Tokenizer) Reset() {
    // Clear without deallocating
    t.buffer = t.buffer[:0]
    t.tokens = t.tokens[:0]
    t.pos = 0
}
```

3. **Capacity Pre-allocation**
```go
func ProcessLargeQuery(sql string) {
    estimatedTokens := len(sql) / 5 // Heuristic
    
    tokens := make([]Token, 0, estimatedTokens)
    // Avoids reallocation during append
}
```

## Concurrency Model

### Thread Safety

1. **Pool Operations**: Thread-safe via sync.Pool
2. **Tokenizer/Parser Instances**: Not thread-safe - use one per goroutine
3. **Tokens & AST**: Immutable after creation - safe for concurrent reads
4. **Metrics**: Atomic operations - safe for concurrent updates

### Concurrent Usage Pattern

```go
// Process multiple queries concurrently
func ProcessConcurrent(queries []string) []Result {
    results := make([]Result, len(queries))
    var wg sync.WaitGroup

    for i, sql := range queries {
        wg.Add(1)
        go func(idx int, query string) {
            defer wg.Done()

            // Each goroutine gets its own instances from pool
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)

            p := parser.GetParser()
            defer parser.PutParser(p)

            tokens, _ := tkz.Tokenize([]byte(query))
            converted, _ := parser.ConvertTokensForParser(tokens)
            ast, _ := p.Parse(converted)

            results[idx] = Result{AST: ast}
        }(i, sql)
    }

    wg.Wait()
    return results
}
```

**Key Points:**
- Lock-free design: Each goroutine uses its own pooled instances
- Zero race conditions: Validated with 20,000+ concurrent operations
- High throughput: 1.38M+ ops/sec sustained

## Design Patterns

The codebase employs several design patterns for maintainability:

### 1. Object Pool Pattern
- **Purpose**: Reduce allocation overhead
- **Implementation**: sync.Pool for Tokenizer, Parser, AST
- **Benefit**: 60-80% memory reduction

### 2. Visitor Pattern
- **Purpose**: AST traversal and transformation
- **Location**: `pkg/sql/ast/visitor.go`
- **Use Cases**: Query analysis, optimization, code generation

### 3. Recursive Descent
- **Purpose**: Predictive parsing with lookahead
- **Implementation**: Parser methods call each other recursively
- **Safety**: Max recursion depth limit (100) to prevent stack overflow

### 4. Multi-Dialect Strategy
- **Purpose**: Support multiple SQL dialects
- **Location**: `pkg/sql/keywords/`
- **Dialects**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite

## Performance Architecture

### Optimization Techniques

1. **Fast Path Token Recognition**
   - Single-character tokens: O(1) switch-case
   - Keywords: O(1) map lookup
   - Common patterns optimized first

2. **Zero-Copy Operations**
   - Tokenizer works on byte slices directly
   - Token values reference original input
   - No intermediate string allocations

3. **ModelType Fast Dispatch**
   - Parser uses integer token types for O(1) switching
   - Jump table compilation for statement routing
   - Avoids string comparisons in hot path

4. **Pre-allocation Strategies**
   - Estimate buffer sizes based on input length
   - Reuse slices with `slice[:0]` pattern
   - Pool warming for common object sizes

### Benchmarking

GoSQLX includes comprehensive benchmarks (6 benchmark files):
- Component-level: Tokenizer, Parser, AST operations
- Integration: Full pipeline end-to-end
- Memory profiling: Allocation tracking with `-benchmem`
- Concurrency: Race detection with `-race` flag

Run with: `go test -bench=. -benchmem ./pkg/...`

## Performance Monitoring

GoSQLX includes built-in metrics collection for production observability.

### Metrics Package (pkg/metrics)

The metrics package provides atomic counters for lock-free performance tracking:

```go
// Available metrics
type Metrics struct {
    QueriesParsed     int64  // Total queries processed
    TokensGenerated   int64  // Total tokens created
    BytesProcessed    int64  // Total SQL bytes scanned
    Errors            int64  // Parsing errors encountered
    PoolHits          int64  // Pool reuse count
    PoolMisses        int64  // Pool allocations
}

// Usage
snapshot := metrics.GetSnapshot()
fmt.Printf("Queries: %d, Pool hit rate: %.2f%%\n",
    snapshot.QueriesParsed,
    float64(snapshot.PoolHits) / float64(snapshot.PoolHits + snapshot.PoolMisses) * 100)
```

### Security Scanning (pkg/sql/security)

Built-in SQL injection detection with severity classification:

```go
// Scan for security issues
issues := security.ScanQuery(sqlBytes)
for _, issue := range issues {
    fmt.Printf("Security: %s - %s (severity: %s)\n",
        issue.Type, issue.Description, issue.Severity)
}
```

### Query Monitoring (pkg/sql/monitor)

Track query patterns and performance characteristics:

```go
// Monitor query execution
monitor := monitor.New()
monitor.RecordQuery(sql, duration, err)

stats := monitor.GetStats()
fmt.Printf("Avg duration: %v, Error rate: %.2f%%\n",
    stats.AvgDuration, stats.ErrorRate*100)
```

## Scalability Characteristics

The architecture supports high-throughput production workloads:

1. **Stateless Design**: Enables horizontal scaling across multiple instances
2. **Lock-Free Operations**: Each goroutine uses its own pooled instances
3. **Concurrent Safety**: Zero race conditions (validated with race detector)
4. **Memory Efficiency**: Object pooling reduces GC pressure
5. **Performance**: 1.38M+ operations/sec sustained, 1.5M peak throughput

This architecture has been validated for production use with comprehensive testing:
- 20,000+ concurrent operations (race detection)
- 115+ real-world SQL queries
- 8 international languages (Unicode compliance)
- Extended load testing with stable memory profiles