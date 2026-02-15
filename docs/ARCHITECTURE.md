# GoSQLX Architecture Documentation

**Version**: v1.6.0
**Last Updated**: December 2025

## Table of Contents
- [System Overview](#system-overview)
- [Package Structure](#package-structure)
- [Component Architecture](#component-architecture)
- [Token Type System (ARCH-002)](#token-type-system-arch-002)
- [Data Flow](#data-flow)
- [Memory Management](#memory-management)
- [Concurrency Model](#concurrency-model)
- [Design Patterns](#design-patterns)
- [Performance Architecture](#performance-architecture)
- [LSP Architecture](#lsp-architecture)
- [Linter Architecture](#linter-architecture)
- [Security Scanner Architecture](#security-scanner-architecture)

## System Overview

GoSQLX is a production-ready, high-performance SQL parsing library with comprehensive dialect support, security scanning, linting capabilities, and full Language Server Protocol (LSP) integration for IDE tooling.

### Core Design Principles

1. **Zero-Copy Operations**: Minimize memory allocations by working directly with byte slices
2. **Object Pooling**: Reuse expensive objects through sync.Pool (60-80% memory reduction)
3. **Immutable Tokens**: Tokens are immutable once created - safe for concurrent access
4. **Stateless Parsing**: Parser maintains no global state - enables horizontal scaling
5. **Unicode-First**: Full UTF-8 support throughout (8 languages validated)
6. **Multi-Dialect**: Support for PostgreSQL, MySQL, SQL Server, Oracle, SQLite
7. **Type-Safe Dispatch**: O(1) integer-based token type comparisons (14x faster)
8. **Lock-Free Metrics**: Atomic counters for production observability

### High-Level Architecture (v1.6.0)

```
┌───────────────────────────────────────────────────────────────────┐
│                    Application Layer & Tools                      │
│  ┌─────────────┬──────────────┬──────────────┬─────────────────┐ │
│  │ CLI Tool    │ LSP Server   │  Linter      │  Security       │ │
│  │ (validate,  │ (JSON-RPC    │  (10 rules:  │  Scanner        │ │
│  │  format,    │  handler,    │   L001-L010, │  (8 patterns,   │ │
│  │  analyze,   │  rate limit, │   whitespace,│   injection     │ │
│  │  parse)     │  doc mgmt)   │   style)     │   detection)    │ │
│  └─────────────┴──────────────┴──────────────┴─────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                    GoSQLX API (pkg/gosqlx)                        │
│  High-level API providing SQL parsing, validation, formatting     │
└───────────────────────────────────────────────────────────────────┘
                                ▼
┌──────────────┬────────────────────────┬──────────────────────────┐
│  Tokenizer   │      Parser            │         AST              │
│  (zero-copy, │  (recursive descent,   │  (14 statement types,    │
│   120+ token │   14 statement types,  │   pooled nodes,          │
│   types,     │   PostgreSQL features, │   visitor pattern)       │
│   dialect    │   window functions)    │                          │
│   support)   │                        │                          │
├──────────────┼────────────────────────┼──────────────────────────┤
│  Object Pool │    Token Stream        │    Node Factory          │
│  (tokenizer, │  (position tracking,   │  (statement/expression   │
│   parser,    │   conversion layer)    │   pooling)               │
│   AST pools) │                        │                          │
└──────────────┴────────────────────────┴──────────────────────────┘
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│       Core Models, Error Handling, Metrics & Keywords             │
│  ┌──────────┬──────────┬──────────┬──────────┬─────────────────┐ │
│  │ Models   │ Errors   │ Metrics  │ Keywords │ Configuration   │ │
│  │ (Token,  │ (codes,  │ (atomic  │ (5 SQL   │ (YAML-based,    │ │
│  │  Span,   │  pos.    │  counters│  dialects│  linter, format │ │
│  │  Loc.)   │  track)  │  lock-   │  120+    │  security opts) │ │
│  │  100%    │  91.9%   │  free)   │  kwds)   │  81.8% coverage │ │
│  │  coverage│  coverage│  73.9%   │  100%    │                 │ │
│  └──────────┴──────────┴──────────┴──────────┴─────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

## Package Structure

The codebase is organized into focused packages with clear responsibilities and high test coverage:

### Core Packages (Foundation Layer)

- **pkg/models** (100% coverage): Core data structures
  - Token, TokenType with 120+ types and helper methods (IsKeyword, IsOperator, etc.)
  - Span, Location for position tracking
  - Whitespace types (space, newline, tab, comments)
  - O(1) token type categorization

- **pkg/errors** (91.9% coverage): Structured error handling
  - Error codes (PARSE-001 through PARSE-010)
  - Position tracking with line/column information
  - Context preservation for debugging
  - Integration with LSP diagnostics

- **pkg/metrics** (73.9% coverage): Performance monitoring
  - Atomic counters (lock-free, race-free)
  - Pool hit rate tracking
  - Query/token/byte counters
  - Production observability integration

- **pkg/config** (81.8% coverage): Configuration management
  - YAML-based configuration (.gosqlx.yml)
  - Format options (indent, keyword case, line length)
  - Linter rule configuration
  - Security scanning options
  - Multi-dialect settings

### SQL Processing (Core Engine)

- **pkg/sql/tokenizer** (75.3% coverage): Zero-copy SQL lexer
  - 120+ token types with range-based categorization
  - Multi-dialect keyword recognition (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
  - Unicode-aware identifier processing
  - Position tracking (line, column, byte offset)
  - Object pooling for performance

- **pkg/sql/parser** (76.1% coverage): Recursive descent parser
  - Modular architecture (9 files: parser.go, select.go, dml.go, cte.go, expressions.go, window.go, grouping.go, alter.go, ddl.go)
  - 14 SQL statement types
  - PostgreSQL-specific features (LATERAL, DISTINCT ON, FILTER, JSON operators)
  - Window functions (OVER, PARTITION BY, frame clauses)
  - CTEs and set operations (UNION, EXCEPT, INTERSECT)
  - GROUPING SETS, ROLLUP, CUBE support
  - Max recursion depth protection (100 levels)

- **pkg/sql/ast** (80.3% coverage): Abstract Syntax Tree
  - 14 statement types, 20+ expression types
  - Visitor pattern for tree traversal
  - Object pooling for nodes
  - Immutable design for concurrent access

- **pkg/sql/token** (68.8% coverage): Token type definitions
  - Internal token representation for parser
  - Token conversion layer (models.Token → token.Token)

- **pkg/sql/keywords** (100% coverage): SQL keyword categorization
  - 5 SQL dialect support
  - 120+ keywords organized by category
  - O(1) keyword lookup via maps
  - Reserved/non-reserved classification

- **pkg/sql/security** (90.2% coverage): SQL injection detection
  - 8 pattern types (tautologies, comment bypasses, UNION-based, stacked queries, time-based, out-of-band, dangerous functions, boolean-based)
  - 4 severity levels (CRITICAL, HIGH, MEDIUM, LOW)
  - Pre-compiled regex patterns (sync.Once initialization)
  - AST-based analysis
  - Integration with CLI analyze command

- **pkg/sql/monitor** (98.6% coverage): Query monitoring
  - Query pattern tracking
  - Duration metrics
  - Error rate calculation
  - Production performance analysis

### Tools & Integration (Application Layer)

- **pkg/gosqlx** (65.6% coverage): Main API surface
  - High-level API for parsing, validation, formatting
  - Convenience wrappers around core components
  - Error handling and recovery

- **pkg/lsp** (70.2% coverage): Language Server Protocol implementation
  - **Architecture**: Server → Handler → Documents
  - **server.go**: JSON-RPC 2.0 message handling over stdio
  - **handler.go**: Request/notification dispatcher (8 methods: initialize, hover, completion, formatting, documentSymbol, signatureHelp, codeAction, shutdown)
  - **documents.go**: Document manager with incremental sync
  - **protocol.go**: LSP type definitions (requests, responses, diagnostics)
  - **Features**: Rate limiting (100 req/sec), content limits (10MB messages, 5MB documents), UTF-8 safe position handling
  - **Integration**: Used by VSCode extension and other LSP clients

- **pkg/linter** (96.7% coverage): SQL linting and style checking
  - **Architecture**: Linter → Rules → Context
  - **linter.go**: Linting engine with file/directory support
  - **rule.go**: Rule interface (Check, Fix, CanAutoFix methods)
  - **context.go**: Linting context with tokens, AST, and SQL content
  - **10 Built-in Rules (L001-L010)**:
    - **Whitespace** (5 rules): L001 (trailing), L002 (mixed indentation), L003 (long lines), L004 (consecutive blank lines), L005 (redundant whitespace)
    - **Keywords** (1 rule): L006 (keyword case consistency)
    - **Style** (4 rules): L007 (comma placement), L008 (aliasing consistency), L009 (column alignment), L010 (indentation depth)
  - **Auto-fix Support**: 7/10 rules support automatic fixes
  - **Integration**: Used by CLI lint command and LSP code actions

- **pkg/compatibility**: Compatibility layer for API evolution

### Command-Line Interface

- **cmd/gosqlx**: Production-ready CLI tool
  - Commands: validate, format, analyze, parse, lsp, lint, config
  - Multi-file and directory support
  - Exit codes for CI/CD integration
  - Progress indicators and colored output
  - Configuration file support (.gosqlx.yml)

### Supported SQL Statements (14 types)

**DML (6)**: SELECT, INSERT, UPDATE, DELETE, MERGE, TRUNCATE

**DDL (8)**: CREATE TABLE, CREATE VIEW, CREATE MATERIALIZED VIEW, CREATE INDEX,
ALTER TABLE, ALTER (generic), DROP, REFRESH MATERIALIZED VIEW

**Query Composition (2)**: WITH (CTEs), Set Operations (UNION/EXCEPT/INTERSECT)

## Token Type System (ARCH-002)

**Design Decision**: v1.6.0 introduces a comprehensive token type system with 120+ distinct token types for O(1) categorization and 14x performance improvement over string comparisons.

### Token Type Architecture

```go
// TokenType represents the type of a SQL token
type TokenType int

// Range-based categorization for O(1) type checking
const (
    // Token ranges (non-overlapping for fast dispatch)
    TokenRangeBasicStart      TokenType = 10   // Basic tokens
    TokenRangeBasicEnd        TokenType = 30
    TokenRangeStringStart     TokenType = 30   // String literals
    TokenRangeStringEnd       TokenType = 50
    TokenRangeOperatorStart   TokenType = 50   // Operators
    TokenRangeOperatorEnd     TokenType = 150
    TokenRangeKeywordStart    TokenType = 200  // SQL keywords
    TokenRangeKeywordEnd      TokenType = 500
    TokenRangeDataTypeStart   TokenType = 430  // Data types
    TokenRangeDataTypeEnd     TokenType = 450
)
```

### Token Categories (120+ types)

1. **Special Tokens (2)**
   - EOF, Unknown

2. **Basic Tokens (6)**
   - Word, Number, Char, Whitespace, Identifier, Placeholder

3. **String Literals (10)**
   - SingleQuotedString, DoubleQuotedString, TripleSingleQuoted, TripleDoubleQuoted
   - DollarQuotedString, ByteString, NationalString, EscapedString, UnicodeString, HexString

4. **Operators (75)**
   - **Arithmetic**: Plus, Minus, Mul, Div, Mod, DuckIntDiv
   - **Comparison**: Eq, DoubleEq, Neq, Lt, Gt, LtEq, GtEq, Spaceship
   - **Logical**: And, Or, Not
   - **Bitwise**: Ampersand, Pipe, Caret, ShiftLeft, ShiftRight
   - **JSON/JSONB (PostgreSQL)**: Arrow (->), LongArrow (->>), HashArrow (#>), HashLongArrow (#>>), AtArrow (@>), ArrowAt (<@), QuestionPipe (?|), QuestionAnd (?&)
   - **String**: StringConcat (||)
   - **Punctuation**: Comma, Period, Colon, DoubleColon, Semicolon, LParen, RParen, LBracket, RBracket, LBrace, RBrace

5. **SQL Keywords (100+)**
   - **DML**: SELECT, INSERT, UPDATE, DELETE, FROM, WHERE, JOIN, GROUP BY, ORDER BY
   - **DDL**: CREATE, ALTER, DROP, TABLE, INDEX, VIEW, COLUMN, DATABASE
   - **CTE/Set Ops**: WITH, RECURSIVE, UNION, EXCEPT, INTERSECT, ALL
   - **Window Functions**: OVER, PARTITION, ROWS, RANGE, UNBOUNDED, PRECEDING, FOLLOWING, CURRENT, FILTER
   - **Joins**: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL, LATERAL, USING
   - **Constraints**: PRIMARY, KEY, FOREIGN, REFERENCES, UNIQUE, CHECK, DEFAULT
   - **Aggregates**: COUNT, SUM, AVG, MIN, MAX
   - **Data Types**: INT, VARCHAR, TEXT, TIMESTAMP, BOOLEAN, JSON, JSONB

### Helper Methods (O(1) categorization)

```go
// Fast token type classification (14x faster than string comparisons)
func (t TokenType) IsKeyword() bool {
    return t >= TokenRangeKeywordStart && t < TokenRangeKeywordEnd
}

func (t TokenType) IsOperator() bool {
    return t >= TokenRangeOperatorStart && t < TokenRangeOperatorEnd
}

func (t TokenType) IsLiteral() bool {
    return (t >= TokenRangeStringStart && t < TokenRangeStringEnd) ||
           t == TokenTypeNumber
}

func (t TokenType) IsDMLKeyword() bool {
    return t == TokenTypeSelect || t == TokenTypeInsert ||
           t == TokenTypeUpdate || t == TokenTypeDelete
}

func (t TokenType) IsDDLKeyword() bool {
    return t == TokenTypeCreate || t == TokenTypeAlter || t == TokenTypeDrop
}

func (t TokenType) IsJoinKeyword() bool {
    return t >= TokenTypeJoin && t <= TokenTypeUsing
}

func (t TokenType) IsWindowKeyword() bool {
    return t >= TokenTypeOver && t <= TokenTypeExclude
}

func (t TokenType) IsAggregateFunction() bool {
    return t >= TokenTypeCount && t <= TokenTypeMax
}

func (t TokenType) IsDataType() bool {
    return t >= TokenRangeDataTypeStart && t < TokenRangeDataTypeEnd
}

func (t TokenType) IsConstraint() bool {
    return t >= TokenTypePrimary && t <= TokenTypeNullable
}

func (t TokenType) IsSetOperation() bool {
    return t == TokenTypeUnion || t == TokenTypeExcept || t == TokenTypeIntersect
}
```

### Performance Benefits

1. **14x Faster Type Checking**: Integer comparisons vs string matching
2. **O(1) Categorization**: Range checks for all categories
3. **Jump Table Optimization**: Compiler optimizes switch statements on integers
4. **Cache Friendly**: Integer comparisons have better cache locality
5. **Type Safety**: Compile-time type checking prevents errors

### PostgreSQL Extension Tokens (v1.6.0)

```go
// JSON/JSONB operators
TokenTypeArrow         // -> (field access, returns JSON)
TokenTypeLongArrow     // ->> (field access, returns text)
TokenTypeHashArrow     // #> (path access, returns JSON)
TokenTypeHashLongArrow // #>> (path access, returns text)
TokenTypeAtArrow       // @> (contains)
TokenTypeArrowAt       // <@ (contained by)
TokenTypeHashMinus     // #- (delete at path)
TokenTypeQuestionPipe  // ?| (key exists any)
TokenTypeQuestionAnd   // ?& (key exists all)

// Keywords
TokenTypeLateral       // LATERAL (correlated subquery in FROM)
TokenTypeFilter        // FILTER (conditional aggregation)
TokenTypeDistinct      // DISTINCT (with ON support)
```

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
└── token_conversion.go # Internal token conversion (unexported)
```

**Statement Parsing Methods:**

The parser supports 14 SQL statement types via these entry points:

```
parseStatement()  # Fast ModelType (int) dispatch with O(1) switching
├── parseWithStatement()              # WITH (CTEs)
├── parseSelectWithSetOperations()    # SELECT + UNION/EXCEPT/INTERSECT
├── parseInsertStatement()            # INSERT (with RETURNING)
├── parseUpdateStatement()            # UPDATE (with RETURNING)
├── parseDeleteStatement()            # DELETE (with RETURNING)
├── parseMergeStatement()             # MERGE
├── parseCreateStatement()            # CREATE (TABLE, VIEW, MATERIALIZED VIEW, INDEX)
├── parseAlterTableStmt()             # ALTER TABLE
├── parseDropStatement()              # DROP
├── parseRefreshStatement()           # REFRESH MATERIALIZED VIEW
└── parseTruncateStatement()          # TRUNCATE
```

**PostgreSQL-Specific Features (v1.6.0):**

```
parseSelectExpression()
├── parseDistinctOnClause()           # DISTINCT ON (col1, col2, ...)
└── parseLateralTableReference()      # LATERAL (subquery)

parseFunctionCall()
└── parseAggregateOrderBy()           # ORDER BY inside aggregates
    ├── STRING_AGG(expr, delim ORDER BY col)
    ├── ARRAY_AGG(expr ORDER BY col)
    └── JSON_AGG(expr ORDER BY col)

parseExpression()
├── parseJSONOperator()               # ->, ->>, #>, #>>, @>, <@, #-, ?, ?|, ?&
└── parseFilterClause()               # FILTER (WHERE condition)

parseReturningClause()                # RETURNING * | col1, col2 | expr AS alias
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

// 3. Token conversion (pkg/sql/parser/token_conversion.go)
p := parser.NewParser()
defer p.Release()
// Returns: []token.Token for parser consumption

// 4. Parsing (pkg/sql/parser)
p := parser.GetParser()
defer parser.PutParser(p)

ast, err := p.ParseFromModelTokens(tokens)
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
            p := parser.NewParser()
            defer p.Release()
            ast, _ := p.ParseFromModelTokens(tokens)

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

## LSP Architecture

**Language Server Protocol (LSP) Implementation** (v1.6.0) provides real-time IDE integration for SQL editing.

### LSP Component Design

```
┌─────────────────────────────────────────────────────────────┐
│                     LSP Server (pkg/lsp)                     │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────┐      ┌────────────┐      ┌──────────────┐  │
│  │  Server    │─────▶│  Handler   │─────▶│  Documents   │  │
│  │ (server.go)│      │(handler.go)│      │(documents.go)│  │
│  └────────────┘      └────────────┘      └──────────────┘  │
│        │                    │                     │          │
│        │                    │                     │          │
│   JSON-RPC 2.0        Request/Notify        Document        │
│   over stdio          Dispatcher            Manager         │
│        │                    │                     │          │
│        ▼                    ▼                     ▼          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Protocol Types (protocol.go)             │  │
│  │  - Request/Response                                   │  │
│  │  - Diagnostics (errors with positions)                │  │
│  │  - Completion (keywords, functions, snippets)         │  │
│  │  - Hover (documentation)                              │  │
│  │  - Formatting (indent, keyword case)                  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Core SQL Components (Tokenizer/Parser)          │
└─────────────────────────────────────────────────────────────┘
```

### LSP Server Component (server.go)

**Responsibilities:**
- JSON-RPC 2.0 message handling over stdio
- Content-Length header parsing
- Rate limiting (100 requests/second)
- Content size validation (10MB max per message, 5MB max per document)
- Concurrent request handling with write mutex
- Graceful shutdown on exit/shutdown requests

**Key Features:**
```go
type Server struct {
    reader    *bufio.Reader      // stdio reader
    writer    io.Writer           // stdio writer with mutex
    writeMu   sync.Mutex          // Thread-safe write
    documents *DocumentManager    // Open document tracking
    handler   *Handler            // Request dispatcher
    logger    *log.Logger         // Optional debug logging

    // Rate limiting (atomic counters)
    requestCount int64
    lastReset    time.Time
    rateMu       sync.Mutex
}
```

**Message Flow:**
1. Read Content-Length header from stdin
2. Read JSON-RPC message body
3. Unmarshal and validate JSON-RPC structure
4. Check rate limits (100 req/sec window)
5. Dispatch to handler based on method
6. Send response with Content-Length header
7. Log operations (if logger enabled)

### LSP Handler Component (handler.go)

**Responsibilities:**
- Request/notification routing to appropriate handlers
- SQL parsing and validation
- Keyword documentation lookup
- Code completion generation
- SQL formatting
- Diagnostic generation from parser errors

**Supported LSP Methods (8 requests + 4 notifications):**

**Requests (expect response):**
1. `initialize` - Server capabilities negotiation
2. `shutdown` - Graceful shutdown preparation
3. `textDocument/hover` - Keyword/function documentation (70+ keywords)
4. `textDocument/completion` - Autocomplete (100+ keywords, 23 snippets)
5. `textDocument/formatting` - SQL formatting with indent/case options
6. `textDocument/documentSymbol` - Statement outline for navigation
7. `textDocument/signatureHelp` - Function signature hints (15+ functions)
8. `textDocument/codeAction` - Quick fixes (add semicolon, uppercase keywords)

**Notifications (no response):**
1. `initialized` - Client initialization complete
2. `exit` - Server shutdown
3. `textDocument/didOpen` - Document opened in editor
4. `textDocument/didChange` - Document content changed (incremental sync)
5. `textDocument/didClose` - Document closed
6. `textDocument/didSave` - Document saved

**Completion Features:**
- **Keywords**: 100+ SQL keywords (SELECT, FROM, WHERE, JOIN, etc.)
- **Functions**: Aggregate (COUNT, SUM), window (ROW_NUMBER, RANK), string (CONCAT, SUBSTRING)
- **Snippets**: 23 templates (SELECT statement, JOIN, CTE, window function, etc.)
- **Caching**: 575x faster with LRU cache (100 entry limit)

**Hover Documentation:**
- 70+ SQL keywords with descriptions
- Function signatures and usage examples
- PostgreSQL-specific features (LATERAL, DISTINCT ON, FILTER)

### Document Manager Component (documents.go)

**Responsibilities:**
- Track open SQL documents by URI
- Incremental document synchronization
- UTF-8 safe position handling
- Line splitting and caching for fast lookups

**Data Structures:**
```go
type Document struct {
    URI        string      // file:// URI
    LanguageID string      // "sql" language identifier
    Version    int         // Document version (increments on change)
    Content    string      // Full SQL content
    Lines      []string    // Cached line splits for position lookup
}

type DocumentManager struct {
    mu        sync.RWMutex              // Thread-safe access
    documents map[string]*Document      // URI → Document mapping
}
```

**Incremental Sync:**
- Supports range-based edits (efficient for large files)
- Full document sync fallback
- Position → offset conversion for UTF-8 safety
- Line boundary handling (preserves newlines)

**Thread Safety:**
- RWMutex for concurrent reads
- Copy-on-Get prevents race conditions
- Safe for multi-threaded LSP server

### LSP Performance Characteristics

1. **Rate Limiting**: 100 requests/second (DoS protection)
2. **Content Limits**: 10MB messages, 5MB documents (memory protection)
3. **Caching**: 575x faster keyword suggestions with LRU cache
4. **Incremental Sync**: Efficient updates for large SQL files
5. **UTF-8 Safe**: Rune-based position handling (international support)

### LSP Integration Example

```go
// Start LSP server via CLI
$ gosqlx lsp
$ gosqlx lsp --log /tmp/lsp.log  // With debug logging

// VSCode integration (.vscode/settings.json)
{
  "gosqlx.lsp.enabled": true,
  "gosqlx.format.indent": 2,
  "gosqlx.format.uppercaseKeywords": true
}
```

## Linter Architecture

**SQL Linting Engine** (v1.6.0) provides style checking and automatic fixing with 10 built-in rules.

### Linter Component Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Linter (pkg/linter)                       │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────┐      ┌────────────┐      ┌──────────────┐  │
│  │   Linter   │─────▶│   Rules    │─────▶│   Context    │  │
│  │(linter.go) │      │ (rule.go)  │      │(context.go)  │  │
│  └────────────┘      └────────────┘      └──────────────┘  │
│        │                    │                     │          │
│        │                    │                     │          │
│   File/Dir/String      Rule Interface       SQL + Tokens    │
│   Linting Engine       (Check/Fix)          + AST Context   │
│        │                    │                     │          │
│        ▼                    ▼                     ▼          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                10 Built-in Rules                      │  │
│  │  Whitespace (5): L001-L005 (trailing, mixed, long,   │  │
│  │                  blank lines, redundant)              │  │
│  │  Keywords (1): L006 (case consistency)                │  │
│  │  Style (4): L007-L010 (comma, aliasing, alignment,   │  │
│  │             indentation depth)                        │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│       Tokenizer → Parser → AST (best-effort parsing)        │
└─────────────────────────────────────────────────────────────┘
```

### Linter Engine (linter.go)

**Responsibilities:**
- File, directory, and string linting
- Rule orchestration and execution
- Violation aggregation and formatting
- Multi-file batch processing

**API:**
```go
type Linter struct {
    rules []Rule  // Configured linting rules
}

// Create linter with specific rules
linter := linter.New(
    whitespace.NewTrailingWhitespace(),
    keywords.NewKeywordCase(true), // uppercase
    style.NewCommaPlacement("trailing"),
)

// Lint operations
fileResult := linter.LintFile("query.sql")
dirResult := linter.LintDirectory("./sql", "*.sql")
stringResult := linter.LintString(sqlContent, "inline.sql")
```

**Output:**
```go
type Result struct {
    Files           []FileResult  // Per-file results
    TotalFiles      int           // File count
    TotalViolations int           // Total violations across all files
}

type FileResult struct {
    Filename   string       // File path
    Violations []Violation  // All violations found
    Error      error        // Fatal error (if any)
}
```

### Rule Interface (rule.go)

**Design:**
```go
type Rule interface {
    ID() string                                    // L001, L002, etc.
    Name() string                                  // Human-readable name
    Description() string                           // What the rule checks
    Severity() Severity                            // error/warning/info
    Check(ctx *Context) ([]Violation, error)      // Find violations
    CanAutoFix() bool                              // Supports auto-fix?
    Fix(content string, v []Violation) (string, error)  // Apply fixes
}

type Violation struct {
    Rule       string          // Rule ID (e.g., "L001")
    RuleName   string          // Human-readable rule name
    Severity   Severity        // error/warning/info
    Message    string          // Violation description
    Location   models.Location // Line/column position
    Line       string          // Actual line content
    Suggestion string          // How to fix
    CanAutoFix bool            // Auto-fix available?
}
```

**BaseRule Helper:**
```go
type BaseRule struct {
    id, name, description string
    severity              Severity
    canAutoFix            bool
}

// Embed BaseRule to avoid boilerplate
type TrailingWhitespace struct {
    BaseRule
}
```

### Context (context.go)

**Linting Context:**
```go
type Context struct {
    SQL      string                    // Raw SQL content
    Filename string                    // Source filename
    Lines    []string                  // Line-by-line split
    Tokens   []models.TokenWithSpan    // Tokenizer output (optional)
    AST      *ast.AST                  // Parsed AST (optional)
    ParseErr error                     // Parser error (if any)
}

// Context builders
ctx := NewContext(sql, filename)
ctx.WithTokens(tokens)           // Add token stream
ctx.WithAST(astObj, parseErr)    // Add AST (best-effort)
```

**Best-Effort Parsing:**
- Tokenization always attempted
- Parsing attempted (failures don't stop linting)
- Token-only rules work without AST
- AST-aware rules skip on parse failure

### Built-in Rules (10 total)

#### Whitespace Rules (5)

**L001: Trailing Whitespace** (auto-fix)
- Detects spaces/tabs at end of lines
- Severity: warning
- Fix: Remove trailing whitespace

**L002: Mixed Indentation** (auto-fix)
- Detects mixed tabs and spaces
- Severity: error
- Fix: Convert tabs to spaces (or vice versa)

**L003: Long Lines** (info)
- Detects lines exceeding max length (default: 120)
- Severity: info
- No auto-fix (requires manual reflow)

**L004: Consecutive Blank Lines** (auto-fix)
- Detects 3+ consecutive blank lines
- Severity: warning
- Fix: Collapse to 2 blank lines max

**L005: Redundant Whitespace** (auto-fix)
- Detects multiple consecutive spaces
- Severity: warning
- Fix: Collapse to single space

#### Keyword Rules (1)

**L006: Keyword Case Consistency** (auto-fix)
- Detects inconsistent keyword casing
- Severity: warning
- Options: uppercase, lowercase, or consistent
- Fix: Normalize all keywords to chosen case

#### Style Rules (4)

**L007: Comma Placement** (auto-fix)
- Detects inconsistent comma placement
- Severity: warning
- Options: trailing (after item), leading (before item)
- Fix: Move commas to preferred position

**L008: Aliasing Consistency** (info)
- Detects inconsistent AS usage in aliases
- Severity: info
- Options: always-as, never-as, or consistent
- No auto-fix (semantic changes required)

**L009: Column Alignment** (info)
- Detects misaligned columns in SELECT list
- Severity: info
- No auto-fix (requires complex reformatting)

**L010: Indentation Depth** (info)
- Detects excessive nesting depth
- Severity: info
- Default max: 4 levels
- No auto-fix (requires query refactoring)

### Linter Usage Example

```bash
# CLI usage
$ gosqlx lint query.sql
$ gosqlx lint --fix query.sql           # Auto-fix violations
$ gosqlx lint --rules L001,L006 *.sql   # Specific rules only
$ gosqlx lint --config .gosqlx.yml ./   # With config file

# Configuration (.gosqlx.yml)
linter:
  rules:
    L001: { enabled: true }
    L006: { enabled: true, uppercase: true }
    L007: { enabled: true, style: "trailing" }
```

### Linter Performance

1. **Best-Effort Parsing**: Token-only rules work without AST
2. **Object Pooling**: Reuses tokenizer/parser instances
3. **Parallel File Processing**: Multi-file linting uses goroutines
4. **Incremental Fixes**: Auto-fix applies changes in single pass

## Security Scanner Architecture

**SQL Injection Detection** (v1.6.0) provides comprehensive pattern-based and AST-based security analysis.

### Security Scanner Design

```
┌─────────────────────────────────────────────────────────────┐
│               Security Scanner (pkg/sql/security)            │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────┐ │
│  │                Scanner (scanner.go)                     │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  Pattern Detection (8 types):                          │ │
│  │  1. Tautologies (1=1, 'a'='a')                         │ │
│  │  2. Comment Bypasses (--, /**/, #)                     │ │
│  │  3. UNION-based (UNION SELECT, information_schema)     │ │
│  │  4. Stacked Queries (; DROP, ; DELETE)                 │ │
│  │  5. Time-based (SLEEP, WAITFOR, pg_sleep)              │ │
│  │  6. Out-of-band (xp_cmdshell, LOAD_FILE)               │ │
│  │  7. Dangerous Functions (EXEC, sp_executesql)          │ │
│  │  8. Boolean-based (conditional logic exploitation)     │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│                              ▼                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │          Detection Methods (dual-layer):                │ │
│  │  - Regex Pattern Matching (pre-compiled, sync.Once)    │ │
│  │  - AST Analysis (structure-aware detection)            │ │
│  └────────────────────────────────────────────────────────┘ │
│                              │                               │
│                              ▼                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │          Severity Classification:                       │ │
│  │  CRITICAL: Definite injection (OR 1=1 --)              │ │
│  │  HIGH: Likely injection (suspicious patterns)          │ │
│  │  MEDIUM: Potentially unsafe (needs review)             │ │
│  │  LOW: Informational findings                           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      AST (for structure analysis)            │
└─────────────────────────────────────────────────────────────┘
```

### Scanner Component (scanner.go)

**Responsibilities:**
- Pattern-based injection detection (8 pattern types)
- AST-based structure analysis
- Severity classification (4 levels)
- Pre-compiled regex patterns (performance optimization)

**API:**
```go
type Scanner struct {
    minSeverity Severity  // Filter findings by severity
}

// Create scanner
scanner := security.NewScanner()
scanner.SetMinSeverity(security.SeverityHigh)  // Filter to HIGH+

// Scan AST
results := scanner.Scan(astObj)
for _, finding := range results.Findings {
    fmt.Printf("[%s] %s at line %d: %s\n",
        finding.Severity, finding.Pattern, finding.Line, finding.Description)
}
```

**Output:**
```go
type ScanResult struct {
    Findings        []Finding  // All detected issues
    CriticalCount   int        // Count by severity
    HighCount       int
    MediumCount     int
    LowCount        int
    ScannedAt       time.Time  // Scan timestamp
}

type Finding struct {
    Pattern     PatternType    // Injection pattern type
    Severity    Severity       // CRITICAL/HIGH/MEDIUM/LOW
    Description string         // Human-readable description
    Line        int            // Source line number
    Column      int            // Source column number
    Evidence    string         // Matched SQL fragment
    Suggestion  string         // How to fix
}
```

### Pattern Detection (8 types)

**1. Tautologies** (CRITICAL)
- Always-true conditions: `1=1`, `'a'='a'`, `1<2`
- Detection: AST-based literal comparison
- Example: `SELECT * FROM users WHERE 1=1 OR username='admin'`

**2. Comment Bypasses** (HIGH/MEDIUM)
- SQL comments to bypass validation: `--`, `/* */`, `#`
- Detection: Regex pattern matching
- Patterns: trailing comments, comment after quote, MySQL conditional comments
- Example: `SELECT * FROM users WHERE username='admin'--' AND password='x'`

**3. UNION-based Extraction** (HIGH)
- UNION SELECT for data exfiltration
- Detection: Regex + AST analysis
- Patterns: `UNION SELECT`, `information_schema` access
- Example: `SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin_users`

**4. Stacked Queries** (CRITICAL)
- Multiple statements (destructive operations)
- Detection: Regex for semicolon + dangerous keywords
- Patterns: `; DROP`, `; DELETE`, `; UPDATE`, `; EXEC`
- Example: `SELECT * FROM users WHERE id=1; DROP TABLE users--`

**5. Time-based Blind** (HIGH)
- Timing attacks for blind injection
- Detection: Regex for sleep functions
- Functions: `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `BENCHMARK()`, `DBMS_LOCK.SLEEP()`
- Example: `SELECT * FROM users WHERE id=1 AND SLEEP(5)`

**6. Out-of-band** (CRITICAL)
- OS command execution, file access
- Detection: Regex for dangerous functions
- Functions: `xp_cmdshell`, `LOAD_FILE()`, `INTO OUTFILE`, `UTL_HTTP`, `DBMS_LDAP`
- Example: `SELECT * FROM users WHERE id=1 AND xp_cmdshell('whoami')`

**7. Dangerous Functions** (HIGH)
- Dynamic SQL execution risks
- Detection: Regex for exec functions
- Functions: `EXEC()`, `EXECUTE IMMEDIATE`, `sp_executesql`, `PREPARE ... FROM`
- Example: `EXEC('DROP TABLE ' + @tableName)`

**8. Boolean-based** (MEDIUM)
- Conditional logic exploitation
- Detection: AST-based conditional analysis
- Complex boolean expressions with suspicious patterns

### Pre-compiled Patterns (Performance)

**Optimization Strategy:**
```go
// Package-level pattern compilation (sync.Once)
var (
    compiledPatterns     map[PatternType][]*regexp.Regexp
    compiledPatternsOnce sync.Once
)

func initCompiledPatterns() {
    compiledPatternsOnce.Do(func() {
        compiledPatterns = make(map[PatternType][]*regexp.Regexp)
        // Time-based patterns
        compiledPatterns[PatternTimeBased] = []*regexp.Regexp{
            regexp.MustCompile(`(?i)\bSLEEP\s*\(`),
            regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\b`),
            // ... more patterns
        }
        // ... other pattern types
    })
}
```

**Benefits:**
- Patterns compiled once at package initialization
- Thread-safe via sync.Once
- Zero allocation per scan
- Regex engine optimizations applied once

### Dual-Layer Detection

**1. Regex Layer (Fast Path)**
- Pre-compiled patterns
- Quick elimination of safe queries
- Low false positive rate

**2. AST Layer (Deep Analysis)**
- Structure-aware detection
- Context-sensitive analysis
- Accurate tautology detection
- Boolean expression analysis

### Security Scanner Usage

```bash
# CLI usage
$ gosqlx analyze query.sql
$ gosqlx analyze --security-only query.sql
$ gosqlx analyze --min-severity HIGH query.sql

# Programmatic usage
scanner := security.NewScanner()
scanner.SetMinSeverity(security.SeverityHigh)
results := scanner.Scan(ast)

for _, finding := range results.Findings {
    log.Printf("[%s] %s: %s", finding.Severity, finding.Pattern, finding.Description)
}
```

### Integration with CLI

The security scanner integrates with the `analyze` command:
```bash
$ gosqlx analyze suspicious.sql

Security Findings:
  [CRITICAL] Tautology at line 3: Always-true condition '1=1'
  [HIGH] Comment Bypass at line 5: Trailing comment may indicate injection

Suggestions:
  - Use parameterized queries instead of string concatenation
  - Validate and sanitize all user inputs
  - Implement prepared statements
```

## Scalability Characteristics

The architecture supports high-throughput production workloads:

1. **Stateless Design**: Enables horizontal scaling across multiple instances
2. **Lock-Free Operations**: Each goroutine uses its own pooled instances
3. **Concurrent Safety**: Zero race conditions (validated with race detector)
4. **Memory Efficiency**: Object pooling reduces GC pressure (60-80% reduction)
5. **Performance**: 1.38M+ operations/sec sustained, 1.5M peak throughput
6. **LSP Rate Limiting**: 100 req/sec prevents DoS attacks
7. **Atomic Metrics**: Lock-free counters for production observability

### Production Validation

This architecture has been validated for production use with comprehensive testing:
- **Concurrency**: 20,000+ concurrent operations (race detection)
- **Real-world SQL**: 115+ queries from production databases
- **Unicode Support**: 8 international languages (full UTF-8 compliance)
- **Load Testing**: Extended runs with stable memory profiles
- **LSP Stress**: 1000+ requests/min sustained (rate limited to 100/sec)
- **Security**: 50+ injection patterns tested across 8 attack categories