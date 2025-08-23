# GoSQLX API Reference

## Table of Contents
- [Package Overview](#package-overview)
- [Tokenizer API](#tokenizer-api)
- [Parser API](#parser-api)
- [AST API](#ast-api)
- [Models](#models)
- [Error Handling](#error-handling)
- [Performance Considerations](#performance-considerations)

## Package Overview

GoSQLX is organized into the following packages:

```
github.com/ajitpratap0/GoSQLX/
├── pkg/
│   ├── models/          # Core data structures
│   ├── sql/
│   │   ├── tokenizer/   # SQL lexical analysis
│   │   ├── parser/      # SQL syntax parsing
│   │   ├── ast/         # Abstract syntax tree
│   │   ├── keywords/    # SQL keyword definitions
│   │   └── token/       # Token types and utilities
│   └── metrics/         # Performance metrics
```

## Tokenizer API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer`

The tokenizer performs lexical analysis of SQL text, converting it into a stream of tokens.

### Functions

#### `GetTokenizer() *Tokenizer`
Retrieves a tokenizer instance from the object pool.

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // ALWAYS defer the return
```

**Returns:** A pointer to a Tokenizer instance  
**Thread-Safe:** Yes  
**Pool Behavior:** Reuses existing instances when available

#### `PutTokenizer(t *Tokenizer)`
Returns a tokenizer instance to the object pool for reuse.

```go
tokenizer.PutTokenizer(tkz)
```

**Parameters:**
- `t`: The tokenizer instance to return to the pool

**Thread-Safe:** Yes  
**Important:** Always call this when done with a tokenizer

### Type: `Tokenizer`

#### Method: `Tokenize(input []byte) ([]models.TokenWithSpan, error)`
Tokenizes SQL input into tokens with position information.

```go
tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
if err != nil {
    // Handle error
}
```

**Parameters:**
- `input`: SQL text as byte slice

**Returns:**
- `[]models.TokenWithSpan`: Array of tokens with position spans
- `error`: Tokenization error if any

**Features:**
- Zero-copy operation
- Unicode support (UTF-8)
- Position tracking (line, column)
- Dialect-specific tokens (PostgreSQL @>, MySQL backticks, etc.)

#### Method: `Reset()`
Resets the tokenizer state for reuse.

```go
tkz.Reset()
```

**Note:** Called automatically by the pool management

### Supported Token Types

| Token Type | Description | Example |
|------------|-------------|---------|
| `TokenTypeSelect` | SELECT keyword | `SELECT` |
| `TokenTypeFrom` | FROM keyword | `FROM` |
| `TokenTypeWhere` | WHERE keyword | `WHERE` |
| `TokenTypeIdentifier` | Column/table names | `users`, `id` |
| `TokenTypeNumber` | Numeric literals | `42`, `3.14` |
| `TokenTypeSingleQuotedString` | String literals | `'hello'` |
| `TokenTypeDoubleQuotedString` | Quoted identifiers | `"column name"` |
| `TokenTypeBacktickIdentifier` | MySQL identifiers | `` `column` `` |
| `TokenTypeBracketIdentifier` | SQL Server identifiers | `[column]` |

### Special Character Support

```go
// Unicode identifiers (all languages)
`SELECT "名前", "имя", "الاسم" FROM users`

// Emoji in strings
`SELECT * FROM users WHERE status = '🚀'`

// PostgreSQL operators
`SELECT * FROM users WHERE tags @> ARRAY['admin']`

// MySQL backticks
`SELECT `user_id` FROM `users``
```

## Parser API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/parser`

The parser builds an Abstract Syntax Tree (AST) from tokens.

### Functions

#### `NewParser() *Parser`
Creates a new parser instance from the pool.

```go
p := parser.NewParser()
defer p.Release() // ALWAYS defer the release
```

**Returns:** A pointer to a Parser instance  
**Thread-Safe:** Yes

### Type: `Parser`

#### Method: `Parse(tokens []token.Token) (ast.Node, error)`
Parses tokens into an AST.

```go
astNode, err := p.Parse(tokens)
if err != nil {
    // Handle parse error
}
```

**Parameters:**
- `tokens`: Array of tokens to parse

**Returns:**
- `ast.Node`: Root node of the AST
- `error`: Parse error if any

**Supported Statements:**
- SELECT (with JOIN, GROUP BY, ORDER BY, HAVING)
- INSERT (single and multi-row)
- UPDATE (with WHERE)
- DELETE (with WHERE)
- CREATE TABLE
- ALTER TABLE
- DROP TABLE
- CREATE INDEX

#### Method: `Release()`
Returns the parser to the pool.

```go
p.Release()
```

**Important:** Always call this when done

## AST API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/ast`

The AST package provides node types for SQL syntax trees.

### Core Interfaces

#### Interface: `Node`
Base interface for all AST nodes.

```go
type Node interface {
    TokenLiteral() string  // Returns the literal token
    Children() []Node      // Returns child nodes
}
```

#### Interface: `Statement`
Represents SQL statements.

```go
type Statement interface {
    Node
    statementNode()
}
```

#### Interface: `Expression`
Represents SQL expressions.

```go
type Expression interface {
    Node
    expressionNode()
}
```

### Statement Types

#### `SelectStatement`
Represents a SELECT query.

```go
type SelectStatement struct {
    Columns     []Expression      // SELECT columns
    From        []TableReference  // FROM tables
    Joins       []JoinClause      // JOIN clauses
    Where       Expression        // WHERE condition
    GroupBy     []Expression      // GROUP BY columns
    Having      Expression        // HAVING condition
    OrderBy     []OrderByElement  // ORDER BY clauses
    Limit       *int64           // LIMIT value
}
```

**Example Usage:**
```go
if stmt, ok := astNode.(*ast.SelectStatement); ok {
    for _, col := range stmt.Columns {
        fmt.Println("Column:", col.TokenLiteral())
    }
}
```

#### `InsertStatement`
Represents an INSERT statement.

```go
type InsertStatement struct {
    Table   string       // Target table
    Columns []string     // Column names
    Values  [][]Expression // Value rows
}
```

#### `UpdateStatement`
Represents an UPDATE statement.

```go
type UpdateStatement struct {
    Table   string              // Target table
    Set     []UpdateSetClause   // SET clauses
    Where   Expression          // WHERE condition
}
```

#### `DeleteStatement`
Represents a DELETE statement.

```go
type DeleteStatement struct {
    Table string      // Target table
    Where Expression  // WHERE condition
}
```

### Expression Types

#### `Identifier`
Represents a column or table name.

```go
type Identifier struct {
    Name string
}
```

#### `Literal`
Represents a literal value.

```go
type Literal struct {
    Type  LiteralType // STRING, NUMBER, BOOLEAN, NULL
    Value interface{}
}
```

#### `BinaryExpression`
Represents binary operations.

```go
type BinaryExpression struct {
    Left     Expression
    Operator string // =, >, <, AND, OR, etc.
    Right    Expression
}
```

#### `FunctionCall`
Represents function calls.

```go
type FunctionCall struct {
    Name      string
    Arguments []Expression
}
```

### Object Pool Functions

#### `NewAST() *AST`
Gets an AST instance from the pool.

```go
astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)
```

#### `ReleaseAST(ast *AST)`
Returns an AST instance to the pool.

```go
ast.ReleaseAST(astObj)
```

## Models

### Package: `github.com/ajitpratap0/GoSQLX/pkg/models`

Core data structures used throughout the library.

### Type: `Token`
Represents a lexical token.

```go
type Token struct {
    Type  TokenType // Token type enum
    Value string    // Token value
}
```

### Type: `TokenWithSpan`
Token with position information.

```go
type TokenWithSpan struct {
    Token Token
    Start Location // Start position
    End   Location // End position
}
```

### Type: `Location`
Position in source text.

```go
type Location struct {
    Line   int // 1-based line number
    Column int // 1-based column number
    Index  int // 0-based byte offset
}
```

### Type: `TokenType`
Enumeration of token types.

```go
type TokenType int

const (
    TokenTypeEOF             TokenType = 0
    TokenTypeUnknown         TokenType = 1
    TokenTypeIdentifier      TokenType = 14
    TokenTypeNumber          TokenType = 11
    TokenTypeSingleQuotedString TokenType = 31
    TokenTypeDoubleQuotedString TokenType = 32
    // ... many more
)
```

## Error Handling

### Type: `TokenizerError`
Tokenization errors with position information.

```go
type TokenizerError struct {
    Message  string
    Location Location
}
```

**Example:**
```go
tokens, err := tkz.Tokenize(sqlBytes)
if err != nil {
    if tkErr, ok := err.(tokenizer.TokenizerError); ok {
        fmt.Printf("Error at line %d, column %d: %s\n",
            tkErr.Location.Line,
            tkErr.Location.Column,
            tkErr.Message)
    }
}
```

### Type: `ParseError`
Parsing errors with context.

```go
type ParseError struct {
    Message string
    Token   Token
}
```

## Performance Considerations

### Object Pooling Best Practices

1. **Always use defer for cleanup:**
```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // Ensures cleanup even on panic
```

2. **Don't store pooled objects:**
```go
// BAD: Storing pooled object
type MyStruct struct {
    tkz *Tokenizer // DON'T DO THIS
}

// GOOD: Get from pool when needed
func (m *MyStruct) Process(sql []byte) error {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    return tkz.Tokenize(sql)
}
```

3. **Batch operations efficiently:**
```go
func ProcessQueries(queries []string) [][]models.TokenWithSpan {
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    results := make([][]models.TokenWithSpan, len(queries))
    for i, query := range queries {
        tokens, _ := tkz.Tokenize([]byte(query))
        results[i] = tokens
        tkz.Reset() // Reset between uses
    }
    return results
}
```

### Memory Optimization

- **Zero-copy tokenization**: The tokenizer works directly on input bytes
- **Pool reuse**: ~60-80% memory reduction vs creating new instances
- **Minimal allocations**: Most operations are allocation-free

### Concurrency Guidelines

All pool operations are thread-safe:

```go
func ConcurrentTokenization(queries []string) {
    var wg sync.WaitGroup
    for _, query := range queries {
        wg.Add(1)
        go func(sql string) {
            defer wg.Done()
            
            tkz := tokenizer.GetTokenizer()
            defer tokenizer.PutTokenizer(tkz)
            
            tokens, _ := tkz.Tokenize([]byte(sql))
            // Process tokens...
        }(query)
    }
    wg.Wait()
}
```

## Complete Example

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func main() {
    sql := `
        SELECT u.id, u.name, COUNT(o.id) as order_count
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.created_at >= '2024-01-01'
        GROUP BY u.id, u.name
        HAVING COUNT(o.id) > 5
        ORDER BY order_count DESC
        LIMIT 10
    `
    
    // Step 1: Tokenize
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    tokens, err := tkz.Tokenize([]byte(sql))
    if err != nil {
        log.Fatal("Tokenization error:", err)
    }
    
    // Step 2: Convert to parser tokens
    parserTokens := make([]token.Token, 0, len(tokens))
    for _, tok := range tokens {
        if tok.Token.Type == models.TokenTypeEOF {
            break
        }
        parserTokens = append(parserTokens, token.Token{
            Type:    fmt.Sprintf("%d", tok.Token.Type),
            Literal: tok.Token.Value,
        })
    }
    
    // Step 3: Parse
    p := parser.NewParser()
    defer p.Release()
    
    astNode, err := p.Parse(parserTokens)
    if err != nil {
        log.Fatal("Parse error:", err)
    }
    
    // Step 4: Analyze AST
    if stmt, ok := astNode.(*ast.SelectStatement); ok {
        fmt.Printf("Found SELECT with %d columns\n", len(stmt.Columns))
        fmt.Printf("Has WHERE: %v\n", stmt.Where != nil)
        fmt.Printf("Has GROUP BY: %v\n", len(stmt.GroupBy) > 0)
        fmt.Printf("Has ORDER BY: %v\n", len(stmt.OrderBy) > 0)
    }
}
```