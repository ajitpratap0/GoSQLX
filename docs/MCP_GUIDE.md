# GoSQLX MCP Server Guide

**Version**: v1.10.0
**Last Updated**: 2026-03-09

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Starting the Server](#starting-the-server)
5. [Configuration](#configuration)
6. [Authentication](#authentication)
7. [Tools Reference](#tools-reference)
   - [validate\_sql](#validate_sql)
   - [format\_sql](#format_sql)
   - [parse\_sql](#parse_sql)
   - [extract\_metadata](#extract_metadata)
   - [security\_scan](#security_scan)
   - [lint\_sql](#lint_sql)
   - [analyze\_sql](#analyze_sql)
8. [AI Assistant Integration](#ai-assistant-integration)
9. [Embedding as a Go Library](#embedding-as-a-go-library)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The GoSQLX MCP server (`gosqlx-mcp`) exposes all GoSQLX SQL capabilities as [Model Context Protocol](https://modelcontextprotocol.io) tools over streamable HTTP. This lets AI assistants like Claude and Cursor call SQL validation, formatting, parsing, linting, and security scanning directly during a conversation.

### Key Features

- **7 SQL Tools**: validate, format, parse, extract metadata, security scan, lint, and composite analyze
- **Streamable HTTP**: Compatible with any MCP client that supports the streamable HTTP transport
- **Optional Bearer Auth**: Protect the server with a token when exposing to a network
- **Multi-Dialect Validation**: postgresql, mysql, sqlite, sqlserver, oracle, snowflake, generic
- **Concurrent Analysis**: `analyze_sql` fans out all 6 tools via `sync.WaitGroup` — one round trip for a full SQL health report
- **Zero Business Logic Duplication**: Every tool delegates to the existing `pkg/gosqlx`, `pkg/linter`, and `pkg/sql/security` packages

---

## Installation

### Install via go install (Recommended)

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
```

The binary is placed in `$GOPATH/bin`. Make sure that directory is in your `PATH`.

### Build from Source

```bash
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX
go build -o gosqlx-mcp ./cmd/gosqlx-mcp
```

### Run without Installing

```bash
go run github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
```

---

## Quick Start

### Start the Server

```bash
gosqlx-mcp
# gosqlx-mcp: listening on 127.0.0.1:8080 (auth=false)
```

### Smoke Test with curl

```bash
# Validate SQL
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}'
```

Expected response:

```json
{"valid": true}
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8080/mcp
```

This opens an interactive browser UI to browse and call all 7 tools.

---

## Starting the Server

### Environment Variable Examples

```bash
# Local development (all defaults)
gosqlx-mcp

# Custom port
GOSQLX_MCP_PORT=9090 gosqlx-mcp

# Expose to network with bearer auth
GOSQLX_MCP_HOST=0.0.0.0 GOSQLX_MCP_PORT=8080 GOSQLX_MCP_AUTH_TOKEN=my-secret gosqlx-mcp
```

### Task Commands

If you have [Task](https://taskfile.dev) installed:

```bash
task mcp           # Run the MCP server
task mcp:build     # Build the gosqlx-mcp binary
task mcp:test      # Run MCP package tests
task mcp:install   # Install gosqlx-mcp to GOPATH/bin
```

### Graceful Shutdown

The server listens for context cancellation. When the process receives `SIGINT` or `SIGTERM`, it calls `http.Server.Shutdown` and drains in-flight requests before exiting.

---

## Configuration

The `gosqlx-mcp` server is configured exclusively via environment variables. No YAML file is read. All variables are optional — safe defaults are applied for local development.

| Variable | Default | Type | Validation |
|----------|---------|------|-----------|
| `GOSQLX_MCP_HOST` | `127.0.0.1` | string | Any valid bind address |
| `GOSQLX_MCP_PORT` | `8080` | integer | 1–65535; non-integer or out-of-range → startup error |
| `GOSQLX_MCP_AUTH_TOKEN` | *(empty)* | string | Empty = auth disabled; value is whitespace-trimmed |

**Notes:**

- `GOSQLX_MCP_PORT` fails fast at startup with a descriptive error if the value is not a valid port number.
- `GOSQLX_MCP_AUTH_TOKEN` enables bearer token auth for all requests when set to a non-empty string.
- MCP server configuration is independent of `.gosqlx.yml` — the YAML config is not read by `gosqlx-mcp`.

---

## Authentication

By default the server accepts all requests without authentication. To enable bearer token auth, set `GOSQLX_MCP_AUTH_TOKEN`:

```bash
GOSQLX_MCP_AUTH_TOKEN=supersecret gosqlx-mcp
# gosqlx-mcp: listening on 127.0.0.1:8080 (auth=true)
```

All requests must then include the `Authorization` header:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer supersecret" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT 1"}}}'
```

Requests missing or carrying an incorrect token receive HTTP `401 Unauthorized`. The `BearerAuthMiddleware` wraps the streamable HTTP handler and is a no-op when auth is disabled.

---

## Tools Reference

All tools accept a required `sql` string parameter. The server returns tool-semantic failures (e.g., invalid SQL) as a valid JSON result with `valid: false` rather than as a protocol error. Protocol errors (missing required parameter, server fault) return an MCP error response.

---

### validate\_sql

**Description**: Validate SQL syntax. Optionally specify a dialect.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sql` | string | yes | — | The SQL string to validate |
| `dialect` | string | no | *(generic)* | One of: `generic`, `mysql`, `postgresql`, `sqlite`, `sqlserver`, `oracle`, `snowflake` |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `valid` | bool | `true` if syntax is valid |
| `error` | string | *(present on failure)* Parse error message |
| `dialect` | string | *(present when dialect was specified)* Echo of the dialect used |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"validate_sql","arguments":{"sql":"SELECT id FROM users","dialect":"postgresql"}}}'
```

```json
{
  "valid": true,
  "dialect": "postgresql"
}
```

Invalid SQL:

```json
{
  "valid": false,
  "error": "unexpected token 'FORM' at position 7"
}
```

---

### format\_sql

**Description**: Format SQL with configurable indentation and keyword casing.

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sql` | string | yes | — | The SQL string to format |
| `indent_size` | integer | no | `2` | Spaces per indent level |
| `uppercase_keywords` | boolean | no | `false` | Uppercase SQL keywords |
| `add_semicolon` | boolean | no | `false` | Append a trailing semicolon |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `formatted_sql` | string | The formatted SQL output |
| `options` | object | Echo of the options used (`indent_size`, `uppercase_keywords`, `add_semicolon`) |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"format_sql","arguments":{"sql":"select id,name from users where active=true","uppercase_keywords":true,"indent_size":4}}}'
```

```json
{
  "formatted_sql": "SELECT\n    id,\n    name\nFROM users\nWHERE active = true",
  "options": {
    "indent_size": 4,
    "uppercase_keywords": true,
    "add_semicolon": false
  }
}
```

---

### parse\_sql

**Description**: Parse SQL and return an AST summary: statement count and types.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | yes | The SQL string to parse |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `statement_count` | integer | Number of statements parsed |
| `statement_types` | array of string | Go type names of each parsed statement (e.g. `*ast.SelectStatement`) |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"parse_sql","arguments":{"sql":"SELECT 1; INSERT INTO t VALUES (1)"}}}'
```

```json
{
  "statement_count": 2,
  "statement_types": [
    "*ast.SelectStatement",
    "*ast.InsertStatement"
  ]
}
```

---

### extract\_metadata

**Description**: Extract tables, columns, and functions referenced in SQL.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | yes | The SQL string to analyze |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `tables` | array of string | Table names referenced in the query |
| `columns` | array of string | Column names referenced in the query |
| `functions` | array of string | Function names called in the query |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"extract_metadata","arguments":{"sql":"SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.id"}}}'
```

```json
{
  "tables": ["users", "orders"],
  "columns": ["id", "id"],
  "functions": ["COUNT"]
}
```

---

### security\_scan

**Description**: Scan SQL for injection patterns: tautologies, UNION attacks, stacked queries, comment bypasses, and more.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | yes | The SQL string to scan |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `is_clean` | bool | `true` if no findings detected |
| `has_critical` | bool | `true` if any CRITICAL severity finding |
| `has_high` | bool | `true` if any HIGH or CRITICAL finding |
| `total_count` | integer | Total number of findings |
| `critical_count` | integer | Number of CRITICAL findings |
| `high_count` | integer | Number of HIGH findings |
| `medium_count` | integer | Number of MEDIUM findings |
| `low_count` | integer | Number of LOW findings |
| `findings` | array of object | Each finding: `severity`, `pattern`, `description`, `risk`, `suggestion` |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"security_scan","arguments":{"sql":"SELECT * FROM users WHERE id = 1 OR 1=1"}}}'
```

```json
{
  "is_clean": false,
  "has_critical": true,
  "has_high": true,
  "total_count": 1,
  "critical_count": 1,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0,
  "findings": [
    {
      "severity": "CRITICAL",
      "pattern": "tautology",
      "description": "Tautology injection detected: always-true condition",
      "risk": "Authentication bypass or full table disclosure",
      "suggestion": "Use parameterized queries; never interpolate user input into SQL"
    }
  ]
}
```

---

### lint\_sql

**Description**: Lint SQL against all 10 GoSQLX style rules (L001–L010).

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | yes | The SQL string to lint |

#### Response

| Field | Type | Description |
|-------|------|-------------|
| `violation_count` | integer | Number of violations found |
| `violations` | array of object | Each violation: `rule`, `rule_name`, `severity`, `message`, `line`, `column`, `suggestion` |

#### Lint Rules

| Rule | Name | Category |
|------|------|----------|
| L001 | TrailingWhitespace | whitespace |
| L002 | MixedIndentation | whitespace |
| L003 | ConsecutiveBlankLines | whitespace |
| L004 | IndentationDepth | whitespace |
| L005 | LongLines | whitespace |
| L006 | ColumnAlignment | style |
| L007 | KeywordCase | keywords |
| L008 | CommaPlacement | style |
| L009 | AliasingConsistency | style |
| L010 | RedundantWhitespace | whitespace |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lint_sql","arguments":{"sql":"select id,name from users"}}}'
```

```json
{
  "violation_count": 1,
  "violations": [
    {
      "rule": "L007",
      "rule_name": "KeywordCase",
      "severity": "warning",
      "message": "Keyword 'select' should be uppercase",
      "line": 1,
      "column": 1,
      "suggestion": "Use 'SELECT' instead of 'select'"
    }
  ]
}
```

---

### analyze\_sql

**Description**: Run all 6 analysis tools concurrently and return a composite report. Results are keyed by tool name (`validate`, `parse`, `metadata`, `security`, `lint`, `format`). Partial failures appear under an `errors` key.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | yes | The SQL string to analyze |

#### Response

| Key | Type | Description |
|-----|------|-------------|
| `validate` | object | Output of `validate_sql` |
| `parse` | object | Output of `parse_sql` |
| `metadata` | object | Output of `extract_metadata` |
| `security` | object | Output of `security_scan` |
| `lint` | object | Output of `lint_sql` |
| `format` | object | Output of `format_sql` (indent_size=2, defaults) |
| `errors` | object | *(present only on partial failure)* Map of tool name → error message |

#### Example

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analyze_sql","arguments":{"sql":"SELECT id FROM users"}}}'
```

```json
{
  "validate": {
    "valid": true
  },
  "parse": {
    "statement_count": 1,
    "statement_types": ["*ast.SelectStatement"]
  },
  "metadata": {
    "tables": ["users"],
    "columns": ["id"],
    "functions": []
  },
  "security": {
    "is_clean": true,
    "has_critical": false,
    "has_high": false,
    "total_count": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "findings": []
  },
  "lint": {
    "violation_count": 0,
    "violations": []
  },
  "format": {
    "formatted_sql": "SELECT id\nFROM users",
    "options": {
      "indent_size": 2,
      "uppercase_keywords": false,
      "add_semicolon": false
    }
  }
}
```

---

## AI Assistant Integration

### Claude Desktop

Add `gosqlx-mcp` to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "gosqlx": {
      "command": "gosqlx-mcp",
      "env": {
        "GOSQLX_MCP_PORT": "8080"
      }
    }
  }
}
```

After restarting Claude Desktop, the 7 GoSQLX tools appear in the tool panel. Claude can now validate, lint, and analyze SQL on your behalf in any conversation.

### Cursor

Add the MCP server to your Cursor configuration (`.cursor/mcp.json` in your project root, or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "gosqlx": {
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

Start `gosqlx-mcp` before opening Cursor (or add it to a startup script). Cursor will connect to the running server and expose the tools in its Agent mode.

### With Authentication

When running with `GOSQLX_MCP_AUTH_TOKEN`:

```json
{
  "mcpServers": {
    "gosqlx": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

---

## Embedding as a Go Library

Import `pkg/mcp` directly to embed the MCP server in your own application:

```go
import "github.com/ajitpratap0/GoSQLX/pkg/mcp"

func main() {
    cfg, err := mcp.LoadConfig()
    if err != nil {
        log.Fatal(err)
    }
    srv := mcp.New(cfg)
    if err := srv.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
}
```

### Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `Config` | struct | Server configuration |
| `LoadConfig` | `() (*Config, error)` | Load from env vars |
| `DefaultConfig` | `() *Config` | Defaults: `127.0.0.1:8080`, auth disabled |
| `New` | `(cfg *Config) *Server` | Create server with all 7 tools registered |
| `(*Server).Start` | `(ctx context.Context) error` | Bind, serve, block until ctx cancelled |
| `BearerAuthMiddleware` | `(cfg *Config, next http.Handler) http.Handler` | Auth wrapper; no-op when auth is disabled |
| `(*Config).Addr` | `() string` | Returns `"host:port"` |
| `(*Config).AuthEnabled` | `() bool` | Reports whether auth token is set |

### Config Struct

```go
type Config struct {
    Host      string // GOSQLX_MCP_HOST (default "127.0.0.1")
    Port      int    // GOSQLX_MCP_PORT (default 8080, range 1–65535)
    AuthToken string // GOSQLX_MCP_AUTH_TOKEN (default "" = auth disabled)
}
```

### Custom Context with Cancellation

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Cancel on SIGINT
go func() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
    cancel()
}()

cfg := mcp.DefaultConfig()
srv := mcp.New(cfg)
log.Fatal(srv.Start(ctx))
```

---

## Troubleshooting

### Server Won't Start — "address already in use"

Another process is using port 8080. Change the port:

```bash
GOSQLX_MCP_PORT=9090 gosqlx-mcp
```

Or find and stop the conflicting process:

```bash
lsof -i :8080
```

### Server Won't Start — "GOSQLX_MCP_PORT: expected integer"

The port value is not a valid integer:

```bash
# Wrong
GOSQLX_MCP_PORT=abc gosqlx-mcp

# Correct
GOSQLX_MCP_PORT=8080 gosqlx-mcp
```

### HTTP 401 on All Requests

Authentication is enabled but the token is missing or wrong. Check `GOSQLX_MCP_AUTH_TOKEN` and include the header:

```bash
curl ... -H "Authorization: Bearer your-token"
```

### "command not found: gosqlx-mcp"

`$GOPATH/bin` is not in your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### MCP Inspector Can't Connect

Verify the server is running and listening on the correct address:

```bash
curl -s http://127.0.0.1:8080/mcp
# Should return an MCP protocol response, not "connection refused"
```

### analyze\_sql Returns Partial Results with "errors" Key

One or more sub-tools failed. The `errors` map identifies which tools failed and why. Successful results are always returned alongside errors.

```json
{
  "validate": {"valid": false, "error": "syntax error"},
  "errors": {
    "parse": "parse failed: unexpected token at position 0",
    "metadata": "parse failed: unexpected token at position 0"
  }
}
```

The format, security scan, and lint tools operate on the raw SQL string independently and may still succeed.

---

## Resources

- **Repository**: https://github.com/ajitpratap0/GoSQLX
- **Issues**: https://github.com/ajitpratap0/GoSQLX/issues
- **MCP Specification**: https://modelcontextprotocol.io/specification
- **mark3labs/mcp-go**: https://github.com/mark3labs/mcp-go

---

**Last Updated**: 2026-03-09
**Version**: v1.10.0
