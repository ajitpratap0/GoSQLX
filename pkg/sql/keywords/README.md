# Keywords Package

## Overview

The `keywords` package provides SQL keyword recognition, categorization, and multi-dialect support. It enables the tokenizer and parser to correctly identify and classify SQL keywords across PostgreSQL, MySQL, SQL Server, Oracle, and SQLite dialects.

## Key Features

- **Multi-Dialect Support**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Keyword Categorization**: Reserved, DML, compound, window functions
- **Compound Keywords**: GROUP BY, ORDER BY, LEFT JOIN, etc.
- **Case-Insensitive**: Recognizes keywords in any case
- **Extensible**: Support for adding custom keywords
- **Thread-Safe**: All operations are safe for concurrent use

## Core Types

### Keywords

Main keyword registry:

```go
type Keywords struct {
    dialect SQLDialect
    // Internal keyword maps
}
```

### SQLDialect

Supported SQL dialects:

```go
type SQLDialect int

const (
    PostgreSQL SQLDialect = iota
    MySQL
    SQLServer
    Oracle
    SQLite
    Generic  // SQL-99 standard keywords
)
```

### KeywordCategory

Keyword classification:

```go
type KeywordCategory int

const (
    CategoryReserved KeywordCategory = iota
    CategoryDML
    CategoryDDL
    CategoryFunction
    CategoryOperator
    CategoryDataType
)
```

## Usage

### Basic Keyword Recognition

```go
package main

import (
    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func main() {
    // Create keyword registry for PostgreSQL
    kw := keywords.New(keywords.PostgreSQL)

    // Check if word is a keyword
    if kw.IsKeyword("SELECT") {
        fmt.Println("SELECT is a keyword")
    }

    // Check if reserved
    if kw.IsReserved("TABLE") {
        fmt.Println("TABLE is reserved")
    }

    // Get keyword info
    keyword := kw.GetKeyword("JOIN")
    fmt.Printf("Type: %s, Category: %d\n", keyword.TokenType, keyword.Category)
}
```

### Compound Keyword Detection

```go
kw := keywords.New(keywords.Generic)

// Check compound keywords
if kw.IsCompoundKeyword("GROUP", "BY") {
    fmt.Println("GROUP BY is a compound keyword")
}

// Get compound keyword type
tokenType := kw.GetCompoundKeywordType("ORDER", "BY")
fmt.Printf("ORDER BY token type: %s\n", tokenType)
```

### Dialect-Specific Keywords

```go
// PostgreSQL-specific
pgKw := keywords.New(keywords.PostgreSQL)
if pgKw.IsKeyword("ILIKE") {
    fmt.Println("ILIKE is PostgreSQL-specific")
}

// MySQL-specific
myKw := keywords.New(keywords.MySQL)
if myKw.IsKeyword("UNSIGNED") {
    fmt.Println("UNSIGNED is MySQL-specific")
}

// SQLite-specific
sqliteKw := keywords.New(keywords.SQLite)
if sqliteKw.IsKeyword("AUTOINCREMENT") {
    fmt.Println("AUTOINCREMENT is SQLite-specific")
}
```

## Keyword Categories

### Reserved Keywords

Core SQL statement keywords:

```
SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP,
JOIN, INNER, LEFT, RIGHT, OUTER, FULL, CROSS, NATURAL,
GROUP, ORDER, HAVING, UNION, EXCEPT, INTERSECT,
WITH, RECURSIVE, AS, ON, USING,
WINDOW, PARTITION, OVER, ROWS, RANGE, etc.
```

### DML Keywords

Data manipulation modifiers:

```
DISTINCT, ALL, FETCH, FIRST, NEXT, LAST, ONLY,
WITH TIES, NULLS, LIMIT, OFFSET, etc.
```

### Compound Keywords

Multi-word keywords recognized as single tokens:

```
GROUP BY, ORDER BY,
LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, NATURAL JOIN,
INNER JOIN, LEFT OUTER JOIN, RIGHT OUTER JOIN, FULL OUTER JOIN,
UNION ALL, WITH TIES, NULLS FIRST, NULLS LAST, etc.
```

### Window Function Keywords

Window function names and modifiers:

```
ROW_NUMBER, RANK, DENSE_RANK, NTILE, PERCENT_RANK, CUME_DIST,
LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTH_VALUE,
ROWS BETWEEN, RANGE BETWEEN, UNBOUNDED PRECEDING, CURRENT ROW, etc.
```

## Dialect-Specific Keywords

### PostgreSQL

```go
pgKeywords := []string{
    "MATERIALIZED",      // Materialized views
    "ILIKE",             // Case-insensitive LIKE
    "SIMILAR",           // SIMILAR TO operator
    "FREEZE",            // VACUUM FREEZE
    "ANALYSE", "ANALYZE", // Statistics gathering
    "CONCURRENTLY",      // Concurrent operations
    "REINDEX",           // Index rebuilding
    "TOAST",             // TOAST storage
    "NOWAIT",            // Lock timeout
    "RECURSIVE",         // Recursive CTEs
    "RETURNING",         // RETURNING clause
}
```

### MySQL

```go
mysqlKeywords := []string{
    "BINARY",            // Binary collation
    "CHAR", "VARCHAR",   // Character types
    "DATETIME",          // DateTime type
    "DECIMAL",           // Decimal type
    "UNSIGNED",          // Unsigned modifier
    "ZEROFILL",          // Zero-fill display
    "FORCE",             // Force index
    "IGNORE",            // Ignore errors
    "INDEX", "KEY",      // Index keywords
    "KILL",              // Kill query
    "OPTION",            // Query options
    "PURGE",             // Purge logs
    "READ", "WRITE",     // Lock types
    "STATUS",            // Show status
    "VARIABLES",         // Show variables
}
```

### SQLite

```go
sqliteKeywords := []string{
    "ABORT",             // Transaction abort
    "ACTION",            // Foreign key action
    "AFTER",             // Trigger timing
    "ATTACH",            // Attach database
    "AUTOINCREMENT",     // Auto-increment
    "CONFLICT",          // Conflict resolution
    "DATABASE",          // Database keyword
    "DETACH",            // Detach database
    "EXCLUSIVE",         // Exclusive lock
    "INDEXED",           // Index hints
    "INSTEAD",           // INSTEAD OF trigger
    "PLAN",              // Query plan
    "QUERY",             // Query keyword
    "RAISE",             // Raise error
    "REPLACE",           // Replace operation
    "TEMP", "TEMPORARY", // Temporary objects
    "VACUUM",            // Database vacuum
    "VIRTUAL",           // Virtual tables
}
```

## Functions

### New

Create a keyword registry for a specific dialect:

```go
func New(dialect SQLDialect) *Keywords
```

### IsKeyword

Check if a word is a SQL keyword:

```go
func (k *Keywords) IsKeyword(word string) bool
```

### IsReserved

Check if a keyword is reserved:

```go
func (k *Keywords) IsReserved(word string) bool
```

### GetKeyword

Get detailed keyword information:

```go
func (k *Keywords) GetKeyword(word string) *Keyword
```

### GetTokenType

Get the token type for a keyword:

```go
func (k *Keywords) GetTokenType(word string) string
```

### IsCompoundKeyword

Check if two words form a compound keyword:

```go
func (k *Keywords) IsCompoundKeyword(word1, word2 string) bool
```

### GetCompoundKeywordType

Get the token type for a compound keyword:

```go
func (k *Keywords) GetCompoundKeywordType(word1, word2 string) string
```

### AddKeyword

Add a custom keyword (for extensions):

```go
func (k *Keywords) AddKeyword(word string, tokenType string, category KeywordCategory)
```

## Integration with Tokenizer

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
```

## Integration with Parser

The parser uses keyword information for syntax validation:

```go
// Check if next token is a specific keyword
if p.currentToken.Type == "GROUP" {
    // Expecting "BY" for GROUP BY
    if p.peekToken.Type == "BY" {
        // Parse GROUP BY clause
    }
}
```

## Case Sensitivity

All keyword matching is **case-insensitive**:

```go
kw := keywords.New(keywords.Generic)

kw.IsKeyword("SELECT")  // true
kw.IsKeyword("select")  // true
kw.IsKeyword("Select")  // true
kw.IsKeyword("SeLeCt")  // true
```

## Performance

- **Lookup Time**: O(1) hash map lookups
- **Memory**: Pre-allocated keyword maps
- **Thread-Safe**: No synchronization overhead for reads
- **Cache-Friendly**: Keywords stored in contiguous memory

## Common Usage Patterns

### 1. Keyword Validation

```go
func ValidateIdentifier(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("%s is a reserved keyword", name)
    }

    return nil
}
```

### 2. SQL Formatter

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
```

### 3. Syntax Highlighting

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

## Testing

Run keyword tests:

```bash
# All tests
go test -v ./pkg/sql/keywords/

# With race detection
go test -race ./pkg/sql/keywords/

# Specific dialects
go test -v -run TestPostgreSQLKeywords ./pkg/sql/keywords/
go test -v -run TestMySQLKeywords ./pkg/sql/keywords/
go test -v -run TestCompoundKeywords ./pkg/sql/keywords/
```

## Best Practices

### 1. Create Once, Reuse

```go
// GOOD: Create once at package level
var globalKeywords = keywords.New(keywords.PostgreSQL)

func IsKeyword(word string) bool {
    return globalKeywords.IsKeyword(word)
}

// BAD: Creating repeatedly
func IsKeyword(word string) bool {
    kw := keywords.New(keywords.PostgreSQL)  // Wasteful
    return kw.IsKeyword(word)
}
```

### 2. Use Appropriate Dialect

```go
// Match your database
pgKeywords := keywords.New(keywords.PostgreSQL)   // For PostgreSQL
myKeywords := keywords.New(keywords.MySQL)        // For MySQL
genericKeywords := keywords.New(keywords.Generic) // For SQL-99 standard
```

### 3. Check Reserved Keywords for Identifiers

```go
func ValidateTableName(name string) error {
    kw := keywords.New(keywords.PostgreSQL)

    if kw.IsReserved(name) {
        return fmt.Errorf("'%s' is a reserved keyword and cannot be used as a table name", name)
    }

    return nil
}
```

## Related Packages

- **tokenizer**: Uses keywords for token classification
- **parser**: Uses keywords for syntax validation
- **models**: Token type definitions

## Documentation

- [Main API Reference](../../../docs/API_REFERENCE.md)
- [Tokenizer Package](../tokenizer/README.md)
- [Parser Package](../parser/README.md)
- [SQL Compatibility](../../../docs/SQL_COMPATIBILITY.md)

## Version History

- **v1.5.0**: Added NULLS FIRST/LAST keywords
- **v1.4.0**: Expanded PostgreSQL operator support
- **v1.3.0**: Window function keywords
- **v1.2.0**: CTE and set operation keywords
- **v1.0.0**: Core keyword system with multi-dialect support
