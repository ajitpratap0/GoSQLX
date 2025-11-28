# GoSQLX Architecture Documentation

## Table of Contents
- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Memory Management](#memory-management)
- [Concurrency Model](#concurrency-model)
- [Design Patterns](#design-patterns)
- [Performance Architecture](#performance-architecture)
- [Extension Points](#extension-points)

## System Overview

GoSQLX is designed as a high-performance, zero-copy SQL parsing library with a focus on memory efficiency and concurrent safety.

### Core Design Principles

1. **Zero-Copy Operations**: Minimize memory allocations by working directly with byte slices
2. **Object Pooling**: Reuse expensive objects through sync.Pool
3. **Immutable Tokens**: Tokens are immutable once created
4. **Stateless Parsing**: Parser maintains no global state
5. **Unicode-First**: Full UTF-8 support throughout
6. **Dialect Agnostic**: Core engine supports multiple SQL dialects

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├─────────────────────────────────────────────────────────┤
│                      GoSQLX API                          │
├──────────────┬────────────────┬────────────────────────┤
│   Tokenizer  │     Parser     │        AST              │
├──────────────┼────────────────┼────────────────────────┤
│  Object Pool │  Token Stream  │    Node Factory         │
├──────────────┴────────────────┴────────────────────────┤
│                   Core Models                            │
└─────────────────────────────────────────────────────────┘
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

**Parser Methods Hierarchy (v1.4+ Modular Architecture):**

The parser is organized into logical modules for maintainability:

```
pkg/sql/parser/
├── parser.go       # Core parser and entry points
├── select.go       # SELECT statement parsing
├── dml.go          # INSERT, UPDATE, DELETE parsing
├── cte.go          # Common Table Expressions (WITH clause)
├── expressions.go  # Expression parsing (BETWEEN, IN, LIKE, etc.)
├── window.go       # Window functions (OVER, PARTITION BY)
├── grouping.go     # GROUPING SETS, ROLLUP, CUBE
├── alter.go        # ALTER TABLE statements
├── create.go       # CREATE statements (TABLE, VIEW, INDEX)
├── drop.go         # DROP statements
├── merge.go        # MERGE statements (SQL:2003)
└── token_converter.go # Token format conversion
```

**Method Hierarchy:**

```
Parse()
├── parseStatement()
│   ├── parseWithStatement()          # CTEs (cte.go)
│   ├── parseSelectWithSetOperations() # SELECT + UNION/EXCEPT/INTERSECT (select.go)
│   │   ├── parseSelectClause()
│   │   ├── parseFromClause()
│   │   ├── parseJoinClause()
│   │   ├── parseWhereClause()
│   │   ├── parseGroupByClause()       # Includes GROUPING SETS (grouping.go)
│   │   ├── parseHavingClause()
│   │   └── parseOrderByClause()       # Includes NULLS FIRST/LAST
│   ├── parseInsertStatement()         # (dml.go)
│   ├── parseUpdateStatement()         # (dml.go)
│   ├── parseDeleteStatement()         # (dml.go)
│   ├── parseMergeStatement()          # (merge.go)
│   ├── parseCreateStatement()         # (create.go) - TABLE, VIEW, MATERIALIZED VIEW, INDEX
│   ├── parseAlterStatement()          # (alter.go)
│   └── parseDropStatement()           # (drop.go)
└── parseExpression()                   # (expressions.go)
    ├── parsePrimaryExpression()
    ├── parseBinaryExpression()
    ├── parseBetweenExpression()
    ├── parseInExpression()
    ├── parseLikeExpression()
    ├── parseIsNullExpression()
    ├── parseFunctionCall()
    │   └── parseWindowSpec()          # (window.go)
    └── parseSubquery()
```

### AST Component

The Abstract Syntax Tree represents the structure of SQL statements.

```
┌──────────────────────────────────────┐
│         AST Node Hierarchy            │
├──────────────────────────────────────┤
│            Node (interface)           │
│               ├── Statement           │
│               └── Expression          │
├──────────────────────────────────────┤
│           Statement Types             │
│  ┌────────────────────────────┐      │
│  │ SelectStatement            │      │
│  │ ├── Columns: []Expression  │      │
│  │ ├── From: []Table          │      │
│  │ ├── Where: Expression      │      │
│  │ ├── GroupBy: []GroupingElement │  │
│  │ └── ...                    │      │
│  └────────────────────────────┘      │
│  ┌────────────────────────────┐      │
│  │ DML Statements             │      │
│  │ ├── InsertStatement        │      │
│  │ ├── UpdateStatement        │      │
│  │ ├── DeleteStatement        │      │
│  │ └── MergeStatement (v1.4+) │      │
│  └────────────────────────────┘      │
│  ┌────────────────────────────┐      │
│  │ DDL Statements             │      │
│  │ ├── CreateTableStatement   │      │
│  │ ├── CreateViewStatement    │      │
│  │ ├── CreateMaterializedView │      │
│  │ ├── CreateIndexStatement   │      │
│  │ ├── AlterTableStatement    │      │
│  │ ├── DropTableStatement     │      │
│  │ └── RefreshMaterializedView│      │
│  └────────────────────────────┘      │
├──────────────────────────────────────┤
│          Expression Types             │
│  ┌────────────────────────────┐      │
│  │ BinaryExpression           │      │
│  │ UnaryExpression            │      │
│  │ FunctionCall               │      │
│  │ WindowFunction (v1.3+)     │      │
│  │ Identifier                 │      │
│  │ Literal                    │      │
│  │ BetweenExpression (v1.4+)  │      │
│  │ InExpression (v1.4+)       │      │
│  │ LikeExpression (v1.4+)     │      │
│  │ IsNullExpression (v1.4+)   │      │
│  │ Subquery                   │      │
│  │ CaseExpression             │      │
│  └────────────────────────────┘      │
│  ┌────────────────────────────┐      │
│  │ Grouping Types (v1.4+)     │      │
│  │ ├── GroupingSet            │      │
│  │ ├── RollupGrouping         │      │
│  │ └── CubeGrouping           │      │
│  └────────────────────────────┘      │
└──────────────────────────────────────┘
```

## Data Flow

### End-to-End Processing Pipeline

```
SQL Text (string/[]byte)
         │
         ▼
┌─────────────────┐
│   Tokenizer     │ ← Get from Pool
├─────────────────┤
│ Lexical Analysis│
└────────┬────────┘
         │ []TokenWithSpan
         ▼
┌─────────────────┐
│ Token Converter │
├─────────────────┤
│ Format Transform│
└────────┬────────┘
         │ []Token
         ▼
┌─────────────────┐
│     Parser      │ ← Get from Pool
├─────────────────┤
│ Syntax Analysis │
└────────┬────────┘
         │ AST Node
         ▼
┌─────────────────┐
│   Application   │
├─────────────────┤
│   Processing    │
└─────────────────┘
         │
         ▼
    Return to Pools
```

### Token Flow Detail

```go
// 1. Input SQL
sql := "SELECT * FROM users"

// 2. Byte conversion
bytes := []byte(sql)

// 3. Tokenization
tokens := []TokenWithSpan{
    {Token{Type: SELECT, Value: "SELECT"}, Location{1,1,0}, Location{1,6,6}},
    {Token{Type: STAR, Value: "*"}, Location{1,8,7}, Location{1,8,8}},
    {Token{Type: FROM, Value: "FROM"}, Location{1,10,9}, Location{1,13,13}},
    {Token{Type: IDENT, Value: "users"}, Location{1,15,14}, Location{1,19,19}},
    {Token{Type: EOF, Value: ""}, Location{1,20,19}, Location{1,20,19}},
}

// 4. Parser tokens
parserTokens := []Token{
    {Type: "201", Literal: "SELECT"},
    {Type: "62", Literal: "*"},
    {Type: "202", Literal: "FROM"},
    {Type: "14", Literal: "users"},
}

// 5. AST
ast := &SelectStatement{
    Columns: []Expression{&Star{}},
    From: []Table{&Identifier{Name: "users"}},
}
```

## Memory Management

### Object Pool Architecture

GoSQLX uses sync.Pool for efficient memory management:

```go
// Tokenizer Pool
var tokenizerPool = sync.Pool{
    New: func() interface{} {
        return &Tokenizer{
            // Pre-allocated buffers
            buffer: make([]byte, 0, 1024),
            tokens: make([]TokenWithSpan, 0, 100),
        }
    },
}

// Parser Pool
var parserPool = sync.Pool{
    New: func() interface{} {
        return &Parser{
            // Pre-allocated structures
            stack: make([]Node, 0, 50),
        }
    },
}

// AST Node Pools
var nodePool = sync.Pool{
    New: func() interface{} {
        return &SelectStatement{}
    },
}
```

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

### Thread Safety Guarantees

1. **Pool Operations**: Thread-safe via sync.Pool
2. **Tokenizer Instances**: Not thread-safe (use one per goroutine)
3. **Parser Instances**: Not thread-safe (use one per goroutine)
4. **Tokens**: Immutable and thread-safe
5. **AST Nodes**: Immutable after creation

### Concurrent Processing Pattern

```go
func ConcurrentPipeline(queries []string) []Result {
    // Stage 1: Tokenization
    tokenChan := make(chan []TokenWithSpan, len(queries))
    
    var wg sync.WaitGroup
    for _, sql := range queries {
        wg.Add(1)
        go func(q string) {
            defer wg.Done()
            
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, _ := tkz.Tokenize([]byte(q))
            tokenChan <- tokens
        }(sql)
    }
    
    go func() {
        wg.Wait()
        close(tokenChan)
    }()
    
    // Stage 2: Parsing
    results := make([]Result, 0, len(queries))
    for tokens := range tokenChan {
        p := parser.NewParser()
        ast, _ := p.Parse(convertTokens(tokens))
        p.Release()
        
        results = append(results, Result{AST: ast})
    }
    
    return results
}
```

### Lock-Free Design

The tokenizer and parser are designed to be lock-free:

```go
// No locks needed - each goroutine has its own instance
func ProcessParallel(queries []string) {
    parallel.ForEach(queries, func(sql string) {
        tkz := tokenizer.GetTokenizer() // No lock
        defer tokenizer.PutTokenizer(tkz)
        
        tokens, _ := tkz.Tokenize([]byte(sql))
        // Process...
    })
}
```

## Design Patterns

### 1. Object Pool Pattern

**Purpose**: Reduce allocation overhead

```go
type Pool struct {
    pool sync.Pool
}

func (p *Pool) Get() *Object {
    obj := p.pool.Get()
    if obj == nil {
        return &Object{}
    }
    return obj.(*Object)
}

func (p *Pool) Put(obj *Object) {
    obj.Reset()
    p.pool.Put(obj)
}
```

### 2. Builder Pattern

**Purpose**: Construct complex AST nodes

```go
type SelectBuilder struct {
    stmt *SelectStatement
}

func NewSelectBuilder() *SelectBuilder {
    return &SelectBuilder{
        stmt: &SelectStatement{},
    }
}

func (b *SelectBuilder) Columns(cols ...Expression) *SelectBuilder {
    b.stmt.Columns = cols
    return b
}

func (b *SelectBuilder) From(tables ...Table) *SelectBuilder {
    b.stmt.From = tables
    return b
}

func (b *SelectBuilder) Build() *SelectStatement {
    return b.stmt
}
```

### 3. Visitor Pattern

**Purpose**: Traverse and transform AST

```go
type Visitor interface {
    VisitSelectStatement(*SelectStatement) interface{}
    VisitIdentifier(*Identifier) interface{}
    // ...
}

type Node interface {
    Accept(Visitor) interface{}
}

func (s *SelectStatement) Accept(v Visitor) interface{} {
    return v.VisitSelectStatement(s)
}
```

### 4. Strategy Pattern

**Purpose**: Support multiple SQL dialects

```go
type Dialect interface {
    IsKeyword(string) bool
    IsOperator(string) bool
    QuoteIdentifier(string) string
}

type PostgreSQLDialect struct{}
type MySQLDialect struct{}

func (t *Tokenizer) SetDialect(d Dialect) {
    t.dialect = d
}
```

## Performance Architecture

### Fast Path Optimizations

1. **Common Token Fast Path**
```go
func (t *Tokenizer) nextToken() Token {
    ch := t.peek()
    
    // Fast path for common single-character tokens
    switch ch {
    case ',': return t.consumeToken(TokenTypeComma)
    case ';': return t.consumeToken(TokenTypeSemicolon)
    case '(': return t.consumeToken(TokenTypeLParen)
    case ')': return t.consumeToken(TokenTypeRParen)
    }
    
    // Slower path for complex tokens
    return t.scanComplexToken()
}
```

2. **Keyword Recognition**
```go
// O(1) map lookup instead of O(n) string comparison
var keywords = map[string]TokenType{
    "SELECT": TokenTypeSelect,
    "FROM":   TokenTypeFrom,
    // ...
}

func isKeyword(s string) (TokenType, bool) {
    typ, ok := keywords[strings.ToUpper(s)]
    return typ, ok
}
```

3. **Memory Layout Optimization**
```go
// Optimize struct field order for cache locality
type Token struct {
    Type  TokenType // 4 bytes
    _     [4]byte   // padding for alignment
    Value string    // 16 bytes (string header)
}

// Group frequently accessed fields
type Tokenizer struct {
    // Hot path fields
    input []byte
    pos   int
    
    // Cold path fields
    options Options
    metrics Metrics
}
```

### Benchmarking Architecture

```go
// Micro-benchmarks for components
func BenchmarkTokenizer(b *testing.B) {
    sql := []byte("SELECT * FROM users")
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        tkz := tokenizer.GetTokenizer()
        tokens, _ := tkz.Tokenize(sql)
        tokenizer.PutTokenizer(tkz)
        _ = tokens
    }
}

// End-to-end benchmarks
func BenchmarkFullPipeline(b *testing.B) {
    sql := "SELECT u.id FROM users u WHERE u.active = true"
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        result := ProcessSQL(sql)
        _ = result
    }
}
```

## Extension Points

### Adding New SQL Dialects

1. **Define Dialect Interface**
```go
type MyDialect struct{}

func (d *MyDialect) Keywords() map[string]TokenType {
    return map[string]TokenType{
        "MYSPECIAL": TokenTypeMySpecial,
    }
}

func (d *MyDialect) Operators() []string {
    return []string{":::", "<->"}
}
```

2. **Register Dialect**
```go
func init() {
    RegisterDialect("mydialect", &MyDialect{})
}
```

### Adding Custom Token Types

1. **Extend TokenType enum**
```go
const (
    // Existing types...
    
    // Custom types (use high numbers to avoid conflicts)
    TokenTypeCustomStart TokenType = 1000
    TokenTypeMyCustom    TokenType = 1001
)
```

2. **Update Tokenizer**
```go
func (t *Tokenizer) scanCustomToken() Token {
    if t.matchSequence("%%%") {
        return Token{
            Type:  TokenTypeMyCustom,
            Value: "%%%",
        }
    }
    // ...
}
```

### Adding AST Transformations

```go
type Transformer interface {
    Transform(Node) Node
}

type Optimizer struct{}

func (o *Optimizer) Transform(n Node) Node {
    switch node := n.(type) {
    case *SelectStatement:
        return o.optimizeSelect(node)
    default:
        return n
    }
}

func (o *Optimizer) optimizeSelect(s *SelectStatement) Node {
    // Optimization logic
    return s
}
```

### Custom Error Handlers

```go
type ErrorHandler interface {
    HandleTokenizerError(TokenizerError)
    HandleParserError(ParserError)
}

type LoggingErrorHandler struct {
    logger *log.Logger
}

func (h *LoggingErrorHandler) HandleTokenizerError(err TokenizerError) {
    h.logger.Printf("Tokenizer error at %d:%d: %s",
        err.Location.Line,
        err.Location.Column,
        err.Message)
}
```

## Performance Monitoring

### Metrics Collection

```go
type Metrics struct {
    TokensProcessed  int64
    BytesProcessed   int64
    ParseTime        time.Duration
    PoolHits         int64
    PoolMisses       int64
}

func (t *Tokenizer) collectMetrics() {
    atomic.AddInt64(&globalMetrics.TokensProcessed, int64(len(t.tokens)))
    atomic.AddInt64(&globalMetrics.BytesProcessed, int64(len(t.input)))
}
```

### Profiling Hooks

```go
type Profiler interface {
    StartOperation(name string) func()
}

type DefaultProfiler struct{}

func (p *DefaultProfiler) StartOperation(name string) func() {
    start := time.Now()
    return func() {
        duration := time.Since(start)
        recordMetric(name, duration)
    }
}

// Usage
func (t *Tokenizer) Tokenize(input []byte) ([]Token, error) {
    defer profiler.StartOperation("tokenize")()
    // ... tokenization logic
}
```

## Future Architecture Considerations

### Planned Enhancements

1. **Streaming Parser**: Handle very large SQL files
2. **Incremental Parsing**: Re-parse only changed portions
3. **Parallel Tokenization**: Split large queries for parallel processing
4. **Plugin System**: Dynamic loading of dialect support
5. **Query Plan Generation**: Convert AST to execution plans
6. **Schema Validation**: Validate against database schema

### Scalability Considerations

1. **Horizontal Scaling**: Stateless design enables easy scaling
2. **Caching Layer**: Cache tokenization/parsing results
3. **Distributed Processing**: Process queries across multiple nodes
4. **Memory Mapping**: Use mmap for very large files
5. **SIMD Optimizations**: Vectorized string operations

This architecture provides a solid foundation for a high-performance SQL parsing library with room for future enhancements and optimizations.