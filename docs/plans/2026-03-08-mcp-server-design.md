# MCP Server Design: GoSQLX

**Date:** 2026-03-08
**Status:** Implemented

## Overview

GoSQLX MCP server exposes SQL processing capabilities as MCP tools over streamable HTTP transport, enabling AI assistants and MCP-compatible clients to parse, validate, format, lint, and security-scan SQL.

## Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Transport | Streamable HTTP only | Required for non-subprocess clients |
| MCP library | `mark3labs/mcp-go` | Mature HTTP transport; simpler API vs official SDK |
| Auth | Optional bearer token (env var) | Secure by default when configured, zero-config for local use |
| Structure | `pkg/mcp/` + `cmd/gosqlx-mcp/` | Library importable; binary for direct use |

## Tools

| Tool | Wraps | Purpose |
|---|---|---|
| `validate_sql` | `gosqlx.Validate` / `ParseWithDialect` | Syntax validation with dialect support |
| `format_sql` | `gosqlx.Format` | Formatting with configurable options |
| `parse_sql` | `gosqlx.Parse` | AST summary (statement count and types) |
| `extract_metadata` | `gosqlx.ExtractMetadata` | Tables, columns, functions |
| `security_scan` | `security.Scanner.ScanSQL` | SQL injection pattern detection |
| `lint_sql` | `linter.Linter.LintString` | Style rules L001–L010 |
| `analyze_sql` | All 6 above (concurrent) | Composite one-call analysis |

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `GOSQLX_MCP_HOST` | `127.0.0.1` | Bind interface |
| `GOSQLX_MCP_PORT` | `8080` | TCP port (1–65535) |
| `GOSQLX_MCP_AUTH_TOKEN` | `""` | Bearer token; empty disables auth |

## Architecture

```
cmd/gosqlx-mcp/main.go       → LoadConfig → New → Start
pkg/mcp/
  config.go                  → Config, LoadConfig, DefaultConfig
  middleware.go              → BearerAuthMiddleware
  tools.go                   → 7 handlers + internal result functions
  server.go                  → Server, New, Start, registerTools
```

## Key Patterns

- **Internal result functions**: Each tool has a `*Internal()` function returning `map[string]any` called by both the MCP handler and `analyze_sql`'s concurrent fan-out
- **Fan-out**: `analyze_sql` uses `sync.WaitGroup` + buffered channel to run all 6 tools concurrently
- **Thin wrappers**: Zero new business logic — all SQL processing delegates to existing GoSQLX packages
- **Consistent imports**: Rule constructors mirror `cmd/gosqlx/cmd/lint.go:createLinter()` exactly

## Quick Start

```bash
# Run server (default: localhost:8080, no auth)
gosqlx-mcp

# With auth
GOSQLX_MCP_AUTH_TOKEN=secret gosqlx-mcp

# Build binary
task mcp:build

# Run tests
task mcp:test
```
