# lsp package

The Language Server Protocol implementation behind editor integrations.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/lsp` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/lsp))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The LSP package provides a complete Language Server Protocol implementation for SQL, enabling IDE integration.

## Server Configuration

### Constants
```go
const (
    MaxContentLength  = 10 * 1024 * 1024 // 10MB max message size
    MaxDocumentSize   = 5 * 1024 * 1024  // 5MB max document size
    RateLimitRequests = 100              // 100 requests per second
    RateLimitWindow   = time.Second
    RequestTimeout    = 30 * time.Second
)
```

## Types

### `Server`
```go
type Server struct {
    // Internal fields
}
```

### `Handler`
```go
type Handler struct {
    // Internal fields
}
```

## Functions

### `NewServer(reader io.Reader, writer io.Writer, logger *log.Logger) *Server`
Create a new LSP server.

```go
server := lsp.NewServer(os.Stdin, os.Stdout, logger)
```

### `NewStdioServer(logger *log.Logger) *Server`
Create a new LSP server using stdin/stdout.

```go
logger := log.New(os.Stderr, "LSP: ", log.LstdFlags)
server := lsp.NewStdioServer(logger)
```

### `(s *Server) Run() error`
Start the server's main loop.

```go
if err := server.Run(); err != nil {
    log.Fatal(err)
}
```

## LSP Capabilities (v1.6.0)

The GoSQLX LSP server implements the following LSP features:

### **1. Text Document Synchronization**
- `textDocument/didOpen` - Document opened notification
- `textDocument/didChange` - Document changed notification (incremental sync)
- `textDocument/didClose` - Document closed notification
- `textDocument/didSave` - Document saved notification

**Example (VSCode):**
```typescript
// When you open a .sql file in VSCode, the LSP server receives:
{
  "method": "textDocument/didOpen",
  "params": {
    "textDocument": {
      "uri": "file:///path/to/query.sql",
      "languageId": "sql",
      "version": 1,
      "text": "SELECT * FROM users"
    }
  }
}
```

### **2. Diagnostics (Real-time Validation)**
- `textDocument/publishDiagnostics` - Syntax error reporting with position info

**Features:**
- Real-time SQL syntax validation
- Error position extraction from parser messages
- Error code integration (E1001-E3004)
- Contextual error messages

**Example:**
```go
// Invalid SQL triggers diagnostic
sql := "SELECT * FORM users" // Typo: FORM instead of FROM

// LSP sends diagnostic:
{
  "uri": "file:///query.sql",
  "diagnostics": [
    {
      "range": {
        "start": {"line": 0, "character": 9},
        "end": {"line": 0, "character": 13}
      },
      "severity": 1,  // Error
      "code": "E2002",
      "source": "gosqlx",
      "message": "unexpected token: expected FROM, got FORM"
    }
  ]
}
```

### **3. Hover Documentation**
- `textDocument/hover` - Keyword/function documentation

**Supported Keywords (60+):**
SELECT, FROM, WHERE, JOIN, LEFT, RIGHT, INNER, OUTER, GROUP, ORDER, HAVING, LIMIT, OFFSET, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, TRUNCATE, WITH, UNION, EXCEPT, INTERSECT, CASE, WHEN, THEN, ELSE, END, AND, OR, NOT, IN, BETWEEN, LIKE, IS, NULL, AS, DISTINCT, COUNT, SUM, AVG, MIN, MAX, OVER, PARTITION, ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, MERGE, ROLLUP, CUBE, GROUPING, FETCH, ROWS, RANGE

**Example:**
````go
// Hovering over "SELECT" shows:
**SELECT** - Retrieves data from one or more tables.

```sql
SELECT column1, column2 FROM table_name;
```
````

### **4. Code Completion**
- `textDocument/completion` - SQL keywords and snippets

**Features:**
- 100+ keyword completions (SELECT, FROM, WHERE, JOIN, etc.)
- 22 code snippets for common patterns
- Function signatures with parameters
- Prefix-based filtering

**Snippet Examples:**
```go
// Typing "sel" suggests:
"SELECT ${1:columns}\nFROM ${2:table}\nWHERE ${3:condition}"

// Typing "cte" suggests:
"WITH ${1:cte_name} AS (\n\tSELECT ${2:columns}\n\tFROM ${3:table}\n\tWHERE ${4:condition}\n)\nSELECT *\nFROM ${1:cte_name}"

// Typing "window" suggests:
"${1:ROW_NUMBER}() OVER (\n\tPARTITION BY ${2:partition_column}\n\tORDER BY ${3:order_column}\n)"
```

### **5. Document Formatting**
- `textDocument/formatting` - SQL code formatting

**Features:**
- Automatic keyword case normalization
- Smart indentation based on SQL clauses
- Whitespace normalization
- Configurable via FormattingOptions

**Example:**
```go
// Input:
"select  *  from   users   where  id=1"

// Formatted output:
"SELECT * FROM users\nWHERE id = 1"
```

### **6. Document Symbols**
- `textDocument/documentSymbol` - SQL statement outline

**Features:**
- Statement-level navigation (SELECT #1, INSERT #2, etc.)
- Statement type classification (DML, DDL)
- Symbol kinds for different statement types

**Example:**
```go
// Multi-statement file:
WITH active_users AS (SELECT * FROM users WHERE active = true)
SELECT * FROM active_users;
INSERT INTO logs (message) VALUES ('Query executed');

// Returns symbols:
[
  {"name": "SELECT #1", "kind": "Method", "detail": "SELECT statement"},
  {"name": "INSERT #2", "kind": "Method", "detail": "INSERT statement"}
]
```

### **7. Signature Help**
- `textDocument/signatureHelp` - Function parameter hints

**Supported Functions (20+):**
COUNT, SUM, AVG, MIN, MAX, COALESCE, NULLIF, CAST, SUBSTRING, TRIM, UPPER, LOWER, LENGTH, CONCAT, ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTILE

**Example:**
```go
// Typing "COALESCE(" shows:
COALESCE(value1, value2, ...)
Returns the first non-null value in the list.

Parameters:
  - value1: First value to check.
  - value2, ...: Additional values to check.
```

### **8. Code Actions (Quick Fixes)**
- `textDocument/codeAction` - Automated fixes for common errors

**Available Quick Fixes:**
- Add missing semicolon
- Convert keyword to uppercase
- Additional context-aware fixes

**Example:**
```go
// Diagnostic: "Expected semicolon"
// Quick fix: Add semicolon at end of statement

// Diagnostic: "Keyword should be uppercase"
// Quick fix: Convert 'select' to 'SELECT'
```

## LSP Usage

### **Starting the LSP Server**
```bash
# Start LSP server on stdio
./gosqlx lsp

# Start with debug logging
./gosqlx lsp --log /tmp/lsp.log
```

### **VSCode Integration**
```json
// settings.json
{
  "gosqlx.enable": true,
  "gosqlx.executablePath": "/path/to/gosqlx",
  "gosqlx.format.indentSize": 2,
  "gosqlx.format.uppercaseKeywords": true,
  "gosqlx.dialect": "postgresql"
}
```

### **Programmatic Usage**
```go
import (
    "log"
    "os"
    "github.com/ajitpratap0/GoSQLX/pkg/lsp"
)

func main() {
    logger := log.New(os.Stderr, "LSP: ", log.LstdFlags)
    server := lsp.NewStdioServer(logger)

    if err := server.Run(); err != nil {
        log.Fatal(err)
    }
}
```

## LSP Performance (v1.6.0)

- **Rate Limiting**: 100 requests/second with window-based throttling
- **Size Limits**: 10MB max message size, 5MB max document size
- **Request Timeout**: 30 seconds per request
- **Incremental Sync**: Supports incremental document updates for performance
- **Concurrent Safety**: Thread-safe document management with defensive copying
