# GoSQLX Language Server Protocol (LSP) Guide


## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Starting the LSP Server](#starting-the-lsp-server)
4. [Supported Features](#supported-features)
5. [IDE Integration](#ide-integration)
6. [Error Codes](#error-codes)
7. [Configuration](#configuration)
8. [Performance](#performance)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The GoSQLX Language Server Protocol (LSP) implementation provides real-time SQL validation, formatting, code completion, hover documentation, and code intelligence features for IDEs and text editors.

### Key Features

- **Real-time Diagnostics**: Syntax error detection with precise error positions
- **Code Completion**: 100+ SQL keywords, functions, and 23 snippet templates
- **Hover Documentation**: Inline help for 70+ SQL keywords
- **Document Formatting**: Intelligent SQL formatting with configurable options
- **Document Symbols**: Navigation through SQL statements
- **Signature Help**: Function parameter documentation for 15+ SQL functions
- **Code Actions**: Quick fixes for common SQL issues
- **Semantic Tokens**: Dialect-aware syntax highlighting powered by `pkg/highlight`
- **Rate Limiting**: Protection against DoS (100 requests/sec)

---

## Quick Start

### Command Line

```bash
# Start LSP server on stdio
gosqlx lsp

# Start with debug logging
gosqlx lsp --log /tmp/gosqlx-lsp.log

# Verify installation
gosqlx lsp --help
```

### Within Go Code

```go
import "github.com/ajitpratap0/GoSQLX/pkg/lsp"

// Create stdio server
server := lsp.NewStdioServer(logger)
err := server.Run()
```

---

## Starting the LSP Server

### Standard Input/Output

The server communicates via LSP protocol on stdin/stdout:

```bash
# Start server
gosqlx lsp

# With logging for debugging
gosqlx lsp --log /tmp/gosqlx-lsp.log
```

### Process Lifecycle

```
1. Client connects via stdin/stdout
2. Client sends 'initialize' request
3. Server responds with capabilities
4. Client sends 'initialized' notification
5. Client sends document notifications (didOpen, didChange, etc.)
6. Server sends diagnostics and responses
7. Client sends 'shutdown' request
8. Client sends 'exit' notification
9. Server exits gracefully
```

---

## Supported Features

### 1. Text Document Synchronization

**Sync Mode**: Incremental (full and partial updates)

```json
{
  "method": "textDocument/didOpen",
  "params": {
    "textDocument": {
      "uri": "file:///path/to/query.sql",
      "languageId": "sql",
      "version": 1,
      "text": "SELECT * FROM users WHERE id = 1"
    }
  }
}
```

### 2. Diagnostics

**Severity Levels**:
- `1` = Error
- `2` = Warning
- `3` = Information
- `4` = Hint

**Document Limits**:
- Maximum 5MB per document
- Maximum 10MB per message

### 3. Code Completion

**Trigger Characters**: ` ` (space), `.` (dot), `(` (paren)

**Completion Types**:
- **Keywords**: SELECT, FROM, WHERE, JOIN, etc. (90+ keywords)
- **Functions**: Aggregate and window functions
- **Snippets**: 23 SQL pattern templates

**Available Snippets**:
| Snippet | Description |
|---------|-------------|
| `sel` | SELECT statement |
| `selall` | SELECT * FROM table |
| `seljoin` | SELECT with JOIN |
| `selleft` | SELECT with LEFT JOIN |
| `selgroup` | SELECT with GROUP BY |
| `ins` | INSERT statement |
| `upd` | UPDATE statement |
| `del` | DELETE statement |
| `cte` | Common Table Expression |
| `cterec` | Recursive CTE |
| `window` | Window function |
| `merge` | MERGE statement |
| `case` | CASE expression |

### 4. Hover Documentation

Markdown documentation for 70+ SQL keywords including:
- Clauses: SELECT, FROM, WHERE, GROUP BY, ORDER BY, HAVING
- Joins: JOIN, LEFT, RIGHT, INNER, OUTER, CROSS
- Operators: AND, OR, NOT, IN, BETWEEN, LIKE
- DDL: CREATE, DROP, ALTER, TRUNCATE
- Window functions: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD

### 5. Document Formatting

**Options**:
```json
{
  "tabSize": 2,
  "insertSpaces": true,
  "insertFinalNewline": true,
  "trimTrailingWhitespace": true
}
```

### 6. Document Symbols

Lists all SQL statements with categorization:
- Method (DML: SELECT, INSERT, UPDATE, DELETE)
- Struct (DDL: CREATE, DROP, ALTER)

### 7. Signature Help

**Trigger Characters**: `(` and `,`

Function documentation for:
- Aggregates: COUNT, SUM, AVG, MIN, MAX
- String: COALESCE, NULLIF, CAST, SUBSTRING, TRIM
- Window: ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, NTILE

### 8. Code Actions

Quick fixes for common issues:
- Add missing semicolon
- Keyword case conversion

### Semantic Tokens

`textDocument/semanticTokens/full` is powered by `pkg/highlight`, the same
classifier used by `gosqlx highlight`, so every dialect keyword and all line and
block comments are covered. The legend uses standard LSP token types:

| Token Type | Applies To |
|------------|-----------|
| `keyword` | SQL keywords (SELECT, FROM, WHERE, AND, etc.); TRUE/FALSE/NULL carry the `readonly` modifier |
| `function` | Function names in call position (`COUNT(*)`, `now()`) |
| `type` | Data types in type position (`VARCHAR(20)`, `x::int`, `CAST(x AS DATE)`) |
| `variable` | Table names, column names, aliases and quoted identifiers |
| `string` | String literals |
| `number` | Integer and float literals |
| `operator` | Operators (`=`, `<>`, `\|\|`, `->>`, `::`, etc.) |
| `comment` | SQL line and block comments |
| `parameter` | Placeholders and bind variables (`$1`, `?`, `:name`, `@var`) |

Positions are UTF-16 code units, as LSP requires, and multi-line tokens (block
comments, multi-line strings) are split into one token per line. Editors that
support semantic tokens (VS Code, Neovim with nvim-lspconfig) use these types to
apply richer highlighting than TextMate grammars provide. See
[HIGHLIGHTING.md](HIGHLIGHTING.md) for the full category list.

Earlier builds used a non-standard `identifier` token type and reported quoted
identifiers as `string`. Custom highlight rules keyed on `identifier` (for
example Neovim's `@lsp.type.identifier`) must use `variable` instead.

#### Dialect for Semantic Tokens

Semantic tokens use the SQL dialect from the client's `initializationOptions`:

```json
{ "dialect": "mysql" }
```

- `dialect` is a string and accepts `generic`, `postgresql`, `mysql`,
  `mariadb`, `sqlserver`, `oracle`, `sqlite`, `snowflake`, `bigquery`,
  `redshift` and `clickhouse`.
- A missing, non-string, empty or unrecognised value uses `generic`.
- The setting is read once, at `initialize`, and affects semantic tokens only.
  Changing it requires restarting the language server. The VS Code extension
  restarts the server when `gosqlx.dialect` changes. Other clients must restart
  the server themselves (in nvim-lspconfig, `:LspRestart`).

Neovim with nvim-lspconfig, using the `gosqlx` config from
[Neovim](#neovim):

```lua
require('lspconfig').gosqlx.setup{
  init_options = { dialect = 'mysql' },
}
```

Any client sends the setting in the `initialize` request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "processId": null,
    "rootUri": "file:///path/to/project",
    "capabilities": {},
    "initializationOptions": { "dialect": "postgresql" }
  }
}
```

### Diagnostic Debouncing

Diagnostics are debounced 300ms per document URI. Rapid keystrokes no longer trigger
a full parse on every keystroke — the parser fires 300ms after the last change.
This improves performance in large SQL files and reduces flicker in the editor.

---

## IDE Integration

### Visual Studio Code

Install the official GoSQLX VSCode extension from the marketplace, or configure manually:

```json
{
  "gosqlx.lsp.enable": true,
  "gosqlx.lsp.path": "gosqlx",
  "[sql]": {
    "editor.defaultFormatter": "gosqlx.formatter",
    "editor.formatOnSave": true
  }
}
```

### Neovim

Using nvim-lspconfig:

```lua
require('lspconfig.configs').gosqlx = {
  default_config = {
    cmd = { 'gosqlx', 'lsp' },
    filetypes = { 'sql' },
    root_dir = function() return vim.fn.getcwd() end,
  },
}

require('lspconfig').gosqlx.setup{
  on_attach = function(client, bufnr)
    vim.keymap.set('n', 'K', vim.lsp.buf.hover, { noremap = true })
    vim.keymap.set('n', '<leader>ca', vim.lsp.buf.code_action, { noremap = true })
  end
}
```

### Emacs

Using lsp-mode:

```emacs-lisp
(lsp-register-client
 (make-lsp-client
  :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
  :major-modes '(sql-mode)
  :server-id 'gosqlx))

(add-hook 'sql-mode-hook #'lsp)
```

Using eglot:

```emacs-lisp
(add-to-list 'eglot-server-programs
             '(sql-mode . ("gosqlx" "lsp")))

(add-hook 'sql-mode-hook #'eglot-ensure)
```

### Sublime Text

```json
{
  "lsp_servers": {
    "gosqlx": {
      "command": ["gosqlx", "lsp"],
      "languages": [
        {
          "languageId": "sql",
          "scopes": ["source.sql"],
          "syntaxes": ["Packages/SQL/SQL.sublime-syntax"]
        }
      ]
    }
  }
}
```

---

## Error Codes

### Tokenizer Errors (E1xxx)

| Code | Name | Description |
|------|------|-------------|
| E1001 | Unexpected Character | Invalid character in SQL |
| E1002 | Unterminated String | Unclosed string literal |
| E1003 | Invalid Number | Malformed numeric literal |
| E1004 | Invalid Operator | Incorrect operator sequence |
| E1005 | Invalid Identifier | Bad table/column name |
| E1006 | Input Too Large | Document exceeds 5MB |
| E1007 | Token Limit | Too many tokens |
| E1008 | Tokenizer Panic | Internal tokenizer error |

### Parser Errors (E2xxx)

| Code | Name | Description |
|------|------|-------------|
| E2001 | Unexpected Token | Token not expected here |
| E2002 | Expected Token | Missing required token |
| E2003 | Missing Clause | Required clause missing |
| E2004 | Invalid Syntax | General syntax error |
| E2005 | Incomplete Statement | Statement cuts off |
| E2006 | Invalid Expression | Expression syntax error |
| E2007 | Recursion Depth | Nesting too deep |
| E2008-E2012 | Various | Unsupported features |

### Semantic Errors (E3xxx)

| Code | Name | Description |
|------|------|-------------|
| E3001 | Undefined Table | Table not found |
| E3002 | Undefined Column | Column not found |
| E3003 | Type Mismatch | Incompatible types |
| E3004 | Ambiguous Column | Column reference unclear |

---

## Configuration

### Server Capabilities

```json
{
  "capabilities": {
    "textDocumentSyncOptions": {
      "openClose": true,
      "change": 2,
      "save": {"includeText": true}
    },
    "completionProvider": {
      "triggerCharacters": [" ", ".", "("]
    },
    "hoverProvider": true,
    "documentFormattingProvider": true,
    "documentSymbolProvider": true,
    "signatureHelpProvider": {
      "triggerCharacters": ["(", ","]
    },
    "codeActionProvider": {
      "codeActionKinds": ["quickfix"]
    }
  }
}
```

### Server Limits

| Limit | Value |
|-------|-------|
| Max Message Size | 10 MB |
| Max Document Size | 5 MB |
| Rate Limit | 100 req/sec |
| Request Timeout | 30 seconds |

---

## Performance

### Throughput

- **Message Processing**: 100+ concurrent requests/sec
- **Latency**: <100ms for most operations
- **Token Processing**: 8M+ tokens/sec (underlying parser)

### Memory Usage

- **Per Document**: ~10KB baseline + document size
- **Per Connection**: ~1MB for internal buffers
- **Pool Efficiency**: 95%+ hit rate

---

## Troubleshooting

### Server Won't Start

```bash
# Check installation
which gosqlx

# Reinstall if needed
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

# Test with logging
gosqlx lsp --log /tmp/test.log
cat /tmp/test.log
```

### IDE Can't Connect

```bash
# Verify gosqlx command exists
command -v gosqlx

# Test LSP protocol
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | gosqlx lsp
```

### No Diagnostics

1. Verify document is under 5MB
2. Check for syntax errors preventing parsing
3. Enable logging: `gosqlx lsp --log /tmp/lsp.log`
4. Check log for diagnostic messages

### Debug Mode

```bash
# Enable detailed logging
gosqlx lsp --log /tmp/gosqlx-lsp.log

# Monitor real-time
tail -f /tmp/gosqlx-lsp.log | grep -E "Initialize|Document|Diagnostic"
```

---

## Resources

- **Repository**: https://github.com/ajitpratap0/GoSQLX
- **Issues**: https://github.com/ajitpratap0/GoSQLX/issues
- **Discussions**: https://github.com/ajitpratap0/GoSQLX/discussions
- **LSP Specification**: https://microsoft.github.io/language-server-protocol/
