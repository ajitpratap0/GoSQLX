# GoSQLX API Reference

## Table of Contents
- [Package Overview](#package-overview)
- [High-Level API (pkg/gosqlx)](#high-level-api)
- [Tokenizer API](#tokenizer-api)
- [Parser API](#parser-api)
- [AST API](#ast-api)
- [Keywords Package](#keywords-package)
- [Models](#models)
- [Error Handling](#error-handling)
- [Metrics Package](#metrics-package)
- [Performance Considerations](#performance-considerations)

## Package Overview

GoSQLX is organized into the following packages:

```
github.com/ajitpratap0/GoSQLX/
├── pkg/
│   ├── gosqlx/          # High-level convenience API
│   ├── models/          # Core data structures
│   ├── sql/
│   │   ├── tokenizer/   # SQL lexical analysis
│   │   ├── parser/      # SQL syntax parsing
│   │   ├── ast/         # Abstract syntax tree
│   │   ├── keywords/    # SQL keyword definitions
│   │   └── token/       # Token types and utilities
│   ├── errors/          # Structured error handling
│   ├── metrics/         # Performance monitoring
│   └── linter/          # SQL linting rules engine
```

## High-Level API

### Package: `github.com/ajitpratap0/GoSQLX/pkg/gosqlx`

The high-level API provides convenient functions for common SQL parsing operations with automatic object pool management. This is the recommended API for most use cases.

### Parsing Functions

#### `Parse(sql string) (*ast.AST, error)`

Parse SQL in a single convenient call.

```go
sql := "SELECT * FROM users WHERE active = true"
astNode, err := gosqlx.Parse(sql)
if err != nil {
    log.Fatal(err)
}
```

**Returns:**
- `*ast.AST`: Parsed abstract syntax tree
- `error`: Parse error if any

**Use Case:** Simple parsing without timeout requirements

---

#### `ParseWithContext(ctx context.Context, sql string) (*ast.AST, error)`

Parse SQL with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := gosqlx.ParseWithContext(ctx, sql)
if err == context.DeadlineExceeded {
    log.Println("Parsing timed out")
}
```

**Parameters:**
- `ctx`: Context for cancellation/timeout
- `sql`: SQL string to parse

**Returns:**
- `*ast.AST`: Parsed AST
- `error`: `context.Canceled`, `context.DeadlineExceeded`, or parse error

**Use Case:** Long-running parsing operations that need cancellation

---

#### `ParseWithTimeout(sql string, timeout time.Duration) (*ast.AST, error)`

Convenience wrapper for parsing with automatic timeout.

```go
astNode, err := gosqlx.ParseWithTimeout(sql, 10*time.Second)
if err == context.DeadlineExceeded {
    log.Println("Timeout after 10 seconds")
}
```

**Use Case:** Quick timeout-based parsing without manual context management

---

#### `ParseBytes(sql []byte) (*ast.AST, error)`

Parse SQL from byte slice (zero-copy when already in bytes).

```go
sqlBytes, _ := os.ReadFile("query.sql")
astNode, err := gosqlx.ParseBytes(sqlBytes)
```

**Use Case:** Parsing SQL from file I/O or byte sources

---

#### `MustParse(sql string) *ast.AST`

Parse SQL, panicking on error (for tests and initialization).

```go
// In test or init()
ast := gosqlx.MustParse("SELECT 1")
```

**Use Case:** Parsing SQL literals where errors indicate bugs

---

#### `ParseMultiple(queries []string) ([]*ast.AST, error)`

Parse multiple SQL statements efficiently.

```go
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
    "SELECT * FROM products",
}
asts, err := gosqlx.ParseMultiple(queries)
```

**Benefits:**
- Reuses tokenizer and parser objects
- 40-60% faster than individual Parse() calls
- Lower memory allocation

**Use Case:** Batch processing SQL queries

---

### Validation Functions

#### `Validate(sql string) error`

Check if SQL is syntactically valid.

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Printf("Invalid SQL: %v\n", err)
}
```

**Returns:** `nil` if valid, error describing the problem

**Use Case:** Syntax validation without building full AST

---

### Metadata Extraction

#### `ExtractTables(astNode *ast.AST) []string`

Extract all table names from parsed SQL.

```go
sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
astNode, _ := gosqlx.Parse(sql)
tables := gosqlx.ExtractTables(astNode)
// Returns: ["users", "orders"]
```

**Extracts from:**
- FROM clauses
- JOIN clauses
- Subqueries and CTEs
- INSERT/UPDATE/DELETE statements

**Returns:** Deduplicated slice of table names

---

#### `ExtractTablesQualified(astNode *ast.AST) []QualifiedName`

Extract table names with schema/alias information.

```go
sql := "SELECT * FROM public.users u"
astNode, _ := gosqlx.Parse(sql)
tables := gosqlx.ExtractTablesQualified(astNode)
// Returns: [QualifiedName{Schema: "public", Name: "users"}]
```

**Use Case:** When schema information is needed

---

#### `ExtractColumns(astNode *ast.AST) []string`

Extract all column references from SQL.

```go
sql := "SELECT id, name, email FROM users WHERE active = true"
astNode, _ := gosqlx.Parse(sql)
columns := gosqlx.ExtractColumns(astNode)
// Returns: ["id", "name", "email", "active"]
```

**Extracts from:**
- SELECT columns
- WHERE conditions
- JOIN conditions
- GROUP BY, HAVING, ORDER BY clauses

**Returns:** Deduplicated slice of column names

---

#### `ExtractColumnsQualified(astNode *ast.AST) []QualifiedName`

Extract column references with table qualifiers.

```go
sql := "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id"
astNode, _ := gosqlx.Parse(sql)
columns := gosqlx.ExtractColumnsQualified(astNode)
// Returns qualified names like "u.id", "u.name", "o.total", etc.
```

**Use Case:** Understanding column-to-table relationships

---

#### `ExtractFunctions(astNode *ast.AST) []string`

Extract all function calls from SQL.

```go
sql := "SELECT COUNT(*), MAX(price), AVG(quantity) FROM products"
astNode, _ := gosqlx.Parse(sql)
functions := gosqlx.ExtractFunctions(astNode)
// Returns: ["COUNT", "MAX", "AVG"]
```

**Includes:**
- Aggregate functions (COUNT, SUM, AVG, MIN, MAX)
- Scalar functions (UPPER, LOWER, SUBSTRING, etc.)
- Window functions (ROW_NUMBER, RANK, etc.)

---

### Types

#### `QualifiedName`

Represents a schema.table.column qualified name.

```go
type QualifiedName struct {
    Schema string // Optional schema name
    Table  string // Table name
    Name   string // Column or table name
}
```

**Methods:**

- `String() string` - Returns "schema.table.name" format
- `FullName() string` - Returns meaningful name without schema

**Examples:**

```go
// Column reference
col := QualifiedName{Table: "users", Name: "id"}
col.String()    // "users.id"
col.FullName()  // "users.id"

// Table reference with schema
tbl := QualifiedName{Schema: "public", Name: "users"}
tbl.String()    // "public.users"
tbl.FullName()  // "users"

// 3-part name
full := QualifiedName{Schema: "db", Table: "public", Name: "users"}
full.String()    // "db.public.users"
full.FullName()  // "public.users"
```

---

### Known Limitations

The high-level API extraction functions have the following parser limitations:

1. **CASE Expressions**: Column references within CASE may not extract correctly
2. **CAST Expressions**: Type conversion expressions not fully supported
3. **IN Expressions**: Complex IN clauses may not parse completely
4. **BETWEEN Expressions**: Range comparisons partially supported
5. **Schema-Qualified Names**: `schema.table` format not fully supported
6. **Complex Recursive CTEs**: Advanced recursive queries may fail

For queries using these features, consider manual extraction or contributing parser enhancements.

---

### Performance Comparison

| Operation | Tokenizer+Parser API | High-Level API | Overhead |
|-----------|---------------------|----------------|----------|
| Single parse | 100% (baseline) | ~110% | +10% |
| Batch parse (10 queries) | 100% (with reuse) | ~105% | +5% |

**Recommendation:**
- Use high-level API for simple cases (< 100 queries/sec)
- Use tokenizer+parser API for performance-critical batch processing

---

### Complete Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
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

    // Parse SQL
    astNode, err := gosqlx.Parse(sql)
    if err != nil {
        log.Fatal("Parse error:", err)
    }

    // Extract metadata
    tables := gosqlx.ExtractTables(astNode)
    columns := gosqlx.ExtractColumns(astNode)
    functions := gosqlx.ExtractFunctions(astNode)

    fmt.Printf("Tables: %v\n", tables)       // ["users", "orders"]
    fmt.Printf("Columns: %v\n", columns)     // ["id", "name", "created_at", "user_id"]
    fmt.Printf("Functions: %v\n", functions) // ["COUNT"]
}
```

---

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

## Keywords Package

### Package: `github.com/ajitpratap0/GoSQLX/pkg/sql/keywords`

The Keywords package provides SQL keyword recognition, categorization, and multi-dialect support for PostgreSQL, MySQL, SQL Server, Oracle, and SQLite.

### Overview

**Key Features:**
- **Multi-Dialect Support**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Keyword Categorization**: Reserved, DML, DDL, functions, operators, data types
- **Compound Keywords**: GROUP BY, ORDER BY, LEFT JOIN, NULLS FIRST, etc.
- **Case-Insensitive**: Recognizes keywords in any case (SELECT, select, Select)
- **Thread-Safe**: All operations safe for concurrent use
- **Extensible**: Support for adding custom keywords

### Core Types

#### Type: `Keywords`

Main keyword registry for a specific SQL dialect.

```go
type Keywords struct {
    dialect SQLDialect
    // Internal keyword maps
}
```

**Usage:**
```go
kw := keywords.New(keywords.PostgreSQL)
if kw.IsKeyword("SELECT") {
    fmt.Println("SELECT is a keyword")
}
```

#### Type: `SQLDialect`

Supported SQL dialects.

```go
type SQLDialect int

const (
    PostgreSQL SQLDialect = iota  // PostgreSQL dialect
    MySQL                         // MySQL dialect
    SQLServer                     // SQL Server dialect
    Oracle                        // Oracle dialect
    SQLite                        // SQLite dialect
    Generic                       // SQL-99 standard keywords
)
```

**Example:**
```go
// Create keyword registry for specific dialect
pgKw := keywords.New(keywords.PostgreSQL)
myKw := keywords.New(keywords.MySQL)
genericKw := keywords.New(keywords.Generic)
```

#### Type: `KeywordCategory`

Keyword classification.

```go
type KeywordCategory int

const (
    CategoryReserved   KeywordCategory = iota  // Reserved keywords (SELECT, FROM, WHERE)
    CategoryDML                                // Data manipulation (INSERT, UPDATE, DELETE)
    CategoryDDL                                // Data definition (CREATE, ALTER, DROP)
    CategoryFunction                           // Function names (COUNT, SUM, AVG)
    CategoryOperator                           // Operators (AND, OR, NOT, LIKE)
    CategoryDataType                           // Data types (INTEGER, VARCHAR, TIMESTAMP)
)
```

### Core Functions

#### Function: `New`

Creates a keyword registry for a specific SQL dialect.

```go
func New(dialect SQLDialect) *Keywords
```

**Parameters:**
- `dialect`: SQL dialect to use (PostgreSQL, MySQL, SQLite, etc.)

**Returns:**
- `*Keywords`: Keyword registry instance

**Example:**
```go
kw := keywords.New(keywords.PostgreSQL)
```

#### Method: `IsKeyword`

Checks if a word is a SQL keyword (case-insensitive).

```go
func (k *Keywords) IsKeyword(word string) bool
```

**Parameters:**
- `word`: Word to check

**Returns:**
- `bool`: true if word is a keyword

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.IsKeyword("SELECT")  // true
kw.IsKeyword("select")  // true
kw.IsKeyword("SeLeCt")  // true
kw.IsKeyword("foo")     // false
```

#### Method: `IsReserved`

Checks if a keyword is reserved (cannot be used as identifier without quoting).

```go
func (k *Keywords) IsReserved(word string) bool
```

**Parameters:**
- `word`: Word to check

**Returns:**
- `bool`: true if word is a reserved keyword

**Example:**
```go
kw := keywords.New(keywords.PostgreSQL)

if kw.IsReserved("TABLE") {
    fmt.Println("TABLE is reserved - must quote if used as identifier")
}
```

#### Method: `GetKeyword`

Gets detailed keyword information.

```go
func (k *Keywords) GetKeyword(word string) *Keyword
```

**Parameters:**
- `word`: Keyword to look up

**Returns:**
- `*Keyword`: Keyword details (TokenType, Category), or nil if not found

**Example:**
```go
kw := keywords.New(keywords.Generic)
keyword := kw.GetKeyword("SELECT")
if keyword != nil {
    fmt.Printf("Type: %s, Category: %d\n", keyword.TokenType, keyword.Category)
}
```

#### Method: `GetTokenType`

Gets the token type for a keyword.

```go
func (k *Keywords) GetTokenType(word string) string
```

**Parameters:**
- `word`: Keyword to look up

**Returns:**
- `string`: Token type (e.g., "SELECT", "INSERT", "JOIN"), or empty string if not found

**Example:**
```go
kw := keywords.New(keywords.Generic)
tokenType := kw.GetTokenType("select")  // Returns "SELECT"
```

#### Method: `IsCompoundKeyword`

Checks if two words form a compound keyword (e.g., GROUP BY, LEFT JOIN).

```go
func (k *Keywords) IsCompoundKeyword(word1, word2 string) bool
```

**Parameters:**
- `word1`: First word
- `word2`: Second word

**Returns:**
- `bool`: true if words form a compound keyword

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.IsCompoundKeyword("GROUP", "BY")     // true
kw.IsCompoundKeyword("ORDER", "BY")     // true
kw.IsCompoundKeyword("LEFT", "JOIN")    // true
kw.IsCompoundKeyword("NULLS", "FIRST")  // true
kw.IsCompoundKeyword("SELECT", "FROM")  // false (not compound)
```

#### Method: `GetCompoundKeywordType`

Gets the token type for a compound keyword.

```go
func (k *Keywords) GetCompoundKeywordType(word1, word2 string) string
```

**Parameters:**
- `word1`: First word
- `word2`: Second word

**Returns:**
- `string`: Compound keyword token type, or empty string if not compound

**Example:**
```go
kw := keywords.New(keywords.Generic)

kw.GetCompoundKeywordType("GROUP", "BY")     // "GROUP BY"
kw.GetCompoundKeywordType("ORDER", "BY")     // "ORDER BY"
kw.GetCompoundKeywordType("LEFT", "JOIN")    // "LEFT JOIN"
kw.GetCompoundKeywordType("NULLS", "FIRST")  // "NULLS FIRST"
```

#### Method: `AddKeyword`

Adds a custom keyword (for extensions).

```go
func (k *Keywords) AddKeyword(word string, tokenType string, category KeywordCategory)
```

**Parameters:**
- `word`: Keyword to add
- `tokenType`: Token type for the keyword
- `category`: Keyword category

**Example:**
```go
kw := keywords.New(keywords.Generic)
kw.AddKeyword("CUSTOM", "CUSTOM", keywords.CategoryReserved)
```

### Keyword Categories

#### Reserved Keywords

Core SQL statement keywords that cannot be used as identifiers without quoting:

```
SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP,
JOIN, INNER, LEFT, RIGHT, OUTER, FULL, CROSS, NATURAL,
GROUP, ORDER, HAVING, UNION, EXCEPT, INTERSECT,
WITH, RECURSIVE, AS, ON, USING,
WINDOW, PARTITION, OVER, ROWS, RANGE
```

#### DML Keywords

Data manipulation modifiers:

```
DISTINCT, ALL, FETCH, FIRST, NEXT, LAST, ONLY,
WITH TIES, NULLS, LIMIT, OFFSET
```

#### Compound Keywords

Multi-word keywords recognized as single tokens:

```
GROUP BY, ORDER BY,
LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, NATURAL JOIN,
INNER JOIN, LEFT OUTER JOIN, RIGHT OUTER JOIN, FULL OUTER JOIN,
UNION ALL, WITH TIES, NULLS FIRST, NULLS LAST
```

#### Window Function Keywords

Window function names and frame specifications:

```
ROW_NUMBER, RANK, DENSE_RANK, NTILE, PERCENT_RANK, CUME_DIST,
LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTH_VALUE,
ROWS BETWEEN, RANGE BETWEEN, UNBOUNDED PRECEDING, CURRENT ROW
```

### Dialect-Specific Keywords

#### PostgreSQL-Specific

```go
pgKw := keywords.New(keywords.PostgreSQL)

// PostgreSQL-specific keywords
pgKw.IsKeyword("ILIKE")        // Case-insensitive LIKE
pgKw.IsKeyword("SIMILAR")      // SIMILAR TO operator
pgKw.IsKeyword("MATERIALIZED") // Materialized views
pgKw.IsKeyword("CONCURRENTLY") // Concurrent operations
pgKw.IsKeyword("RETURNING")    // RETURNING clause
```

**PostgreSQL Keywords:**
```
MATERIALIZED, ILIKE, SIMILAR, FREEZE, ANALYSE, ANALYZE,
CONCURRENTLY, REINDEX, TOAST, NOWAIT, RETURNING
```

#### MySQL-Specific

```go
myKw := keywords.New(keywords.MySQL)

// MySQL-specific keywords
myKw.IsKeyword("UNSIGNED")     // Unsigned modifier
myKw.IsKeyword("ZEROFILL")     // Zero-fill display
myKw.IsKeyword("FORCE")        // Force index
myKw.IsKeyword("IGNORE")       // Ignore errors
```

**MySQL Keywords:**
```
BINARY, CHAR, VARCHAR, DATETIME, DECIMAL, UNSIGNED, ZEROFILL,
FORCE, IGNORE, INDEX, KEY, KILL, OPTION, PURGE, READ, WRITE,
STATUS, VARIABLES
```

#### SQLite-Specific

```go
sqliteKw := keywords.New(keywords.SQLite)

// SQLite-specific keywords
sqliteKw.IsKeyword("AUTOINCREMENT")  // Auto-increment
sqliteKw.IsKeyword("CONFLICT")       // Conflict resolution
sqliteKw.IsKeyword("REPLACE")        // Replace operation
```

**SQLite Keywords:**
```
ABORT, ACTION, AFTER, ATTACH, AUTOINCREMENT, CONFLICT, DATABASE,
DETACH, EXCLUSIVE, INDEXED, INSTEAD, PLAN, QUERY, RAISE, REPLACE,
TEMP, TEMPORARY, VACUUM, VIRTUAL
```

### Usage Examples

#### Basic Keyword Recognition

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func main() {
    kw := keywords.New(keywords.PostgreSQL)

    // Check if word is a keyword
    if kw.IsKeyword("SELECT") {
        fmt.Println("SELECT is a keyword")
    }

    // Check if reserved
    if kw.IsReserved("TABLE") {
        fmt.Println("TABLE is reserved - quote if used as identifier")
    }

    // Get keyword info
    keyword := kw.GetKeyword("JOIN")
    if keyword != nil {
        fmt.Printf("Type: %s, Category: %d\n", keyword.TokenType, keyword.Category)
    }
}
```

#### Compound Keyword Detection

```go
kw := keywords.New(keywords.Generic)

// Check compound keywords
if kw.IsCompoundKeyword("GROUP", "BY") {
    fmt.Println("GROUP BY is a compound keyword")
}

if kw.IsCompoundKeyword("NULLS", "FIRST") {
    fmt.Println("NULLS FIRST is a compound keyword")
}

// Get compound keyword type
tokenType := kw.GetCompoundKeywordType("LEFT", "JOIN")
fmt.Printf("Token type: %s\n", tokenType)  // "LEFT JOIN"
```

#### Identifier Validation

```go
func ValidateIdentifier(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("'%s' is a reserved keyword - must be quoted", name)
    }

    return nil
}

// Usage
err := ValidateIdentifier("table")  // Error: 'table' is reserved
err := ValidateIdentifier("users")  // OK
```

#### SQL Formatter

```go
func FormatKeyword(word string, style string) string {
    kw := keywords.New(keywords.Generic)

    if !kw.IsKeyword(word) {
        return word  // Not a keyword, return as-is
    }

    switch style {
    case "upper":
        return strings.ToUpper(word)
    case "lower":
        return strings.ToLower(word)
    case "title":
        return strings.Title(strings.ToLower(word))
    default:
        return word
    }
}

// Usage
formatted := FormatKeyword("select", "upper")  // "SELECT"
```

#### Dialect Switching

```go
func AnalyzeKeywords(sql string, dialect keywords.SQLDialect) {
    kw := keywords.New(dialect)
    words := strings.Fields(sql)

    for _, word := range words {
        if kw.IsKeyword(word) {
            category := kw.GetKeyword(word).Category
            fmt.Printf("%s: category=%d\n", word, category)
        }
    }
}

// Usage for different dialects
AnalyzeKeywords("SELECT * FROM users", keywords.PostgreSQL)
AnalyzeKeywords("SELECT * FROM users", keywords.MySQL)
```

### Integration with Tokenizer

The keywords package is used by the tokenizer to identify SQL keywords:

```go
// In tokenizer
kw := keywords.New(keywords.PostgreSQL)

// Check if identifier is actually a keyword
if kw.IsKeyword(identifierText) {
    tokenType = kw.GetTokenType(identifierText)
} else {
    tokenType = "IDENTIFIER"
}

// Check for compound keywords
if kw.IsCompoundKeyword(currentWord, nextWord) {
    tokenType = kw.GetCompoundKeywordType(currentWord, nextWord)
    // Consume both words
}
```

### Integration with Parser

The parser uses keyword information for syntax validation:

```go
// Check if next token is a specific keyword
if p.currentToken.Type == "GROUP" {
    // Expecting "BY" for GROUP BY
    if p.peekToken.Type == "BY" {
        // Parse GROUP BY clause
    }
}

// Compound keyword handling
if p.currentToken.Type == "NULLS" {
    if p.peekToken.Type == "FIRST" || p.peekToken.Type == "LAST" {
        // Parse NULLS FIRST/LAST clause
    }
}
```

### Case Sensitivity

All keyword matching is **case-insensitive**:

```go
kw := keywords.New(keywords.Generic)

kw.IsKeyword("SELECT")  // true
kw.IsKeyword("select")  // true
kw.IsKeyword("Select")  // true
kw.IsKeyword("SeLeCt")  // true
```

### Performance Characteristics

- **Lookup Time**: O(1) hash map lookups
- **Memory**: Pre-allocated keyword maps (~10KB per dialect)
- **Thread-Safe**: No synchronization overhead for reads
- **Cache-Friendly**: Keywords stored in contiguous memory

### Best Practices

#### 1. Create Once, Reuse

```go
// GOOD: Create once at package level
var globalKeywords = keywords.New(keywords.PostgreSQL)

func IsKeyword(word string) bool {
    return globalKeywords.IsKeyword(word)
}

// BAD: Creating repeatedly (wasteful)
func IsKeyword(word string) bool {
    kw := keywords.New(keywords.PostgreSQL)  // Creates new instance every call
    return kw.IsKeyword(word)
}
```

#### 2. Use Appropriate Dialect

```go
// Match your database
pgKeywords := keywords.New(keywords.PostgreSQL)   // For PostgreSQL
myKeywords := keywords.New(keywords.MySQL)        // For MySQL
genericKeywords := keywords.New(keywords.Generic) // For SQL-99 standard
```

#### 3. Check Reserved Keywords for Identifiers

```go
func ValidateTableName(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("'%s' is reserved - must be quoted", name)
    }

    return nil
}
```

### Common Patterns

#### Pattern 1: Syntax Highlighting

```go
func HighlightSQL(sql string) string {
    kw := keywords.New(keywords.Generic)
    words := strings.Fields(sql)

    for i, word := range words {
        if kw.IsKeyword(word) {
            words[i] = fmt.Sprintf("<keyword>%s</keyword>", word)
        }
    }

    return strings.Join(words, " ")
}
```

#### Pattern 2: Keyword Case Normalization

```go
func NormalizeKeywords(sql string) string {
    kw := keywords.New(keywords.Generic)
    words := strings.Fields(sql)

    for i, word := range words {
        if kw.IsKeyword(word) {
            words[i] = strings.ToUpper(word)  // Normalize to uppercase
        }
    }

    return strings.Join(words, " ")
}
```

#### Pattern 3: Identifier Quoting

```go
func QuoteIfNeeded(identifier string, dialect keywords.SQLDialect) string {
    kw := keywords.New(dialect)

    if kw.IsReserved(identifier) {
        return fmt.Sprintf("\"%s\"", identifier)  // Quote reserved keywords
    }

    return identifier
}
```