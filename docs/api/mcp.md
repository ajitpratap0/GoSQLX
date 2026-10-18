# mcp package

The Model Context Protocol server that exposes GoSQLX tools to AI assistants.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/mcp` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/mcp))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

MCP server exposing all GoSQLX capabilities as Model Context Protocol tools over streamable HTTP.

## Types

### `Config`
```go
type Config struct {
    Host      string // GOSQLX_MCP_HOST (default "127.0.0.1")
    Port      int    // GOSQLX_MCP_PORT (default 8080, range 1–65535)
    AuthToken string // GOSQLX_MCP_AUTH_TOKEN (default "" = auth disabled)
}
```

## Functions

### `LoadConfig() (*Config, error)`
Load from env vars. Returns error only if `GOSQLX_MCP_PORT` is non-integer or out of range.

### `DefaultConfig() *Config`
Returns `Config{Host: "127.0.0.1", Port: 8080}` with auth disabled.

### `New(cfg *Config) *Server`
Create server with all 7 tools registered. Registers tools once at construction - no dynamic registration.

### `(s *Server) Start(ctx context.Context) error`
Bind to `cfg.Addr()`, serve streamable HTTP. Blocks until ctx cancelled or fatal error. Graceful shutdown on context cancellation.

### `BearerAuthMiddleware(cfg *Config, next http.Handler) http.Handler`
Returns `next` unchanged when `cfg.AuthEnabled()` is false. When enabled, enforces `Authorization: Bearer <token>` on all requests; returns HTTP 401 on failure.

## Registered Tools

| Tool | Description |
|------|-------------|
| `validate_sql` | SQL syntax validation with optional dialect |
| `format_sql` | SQL formatting (indent, keyword case, semicolon) |
| `parse_sql` | AST summary - statement count and types |
| `extract_metadata` | Tables, columns, functions referenced |
| `security_scan` | Injection pattern detection with severity |
| `lint_sql` | Style rule enforcement (L001–L010) |
| `analyze_sql` | Concurrent composite of all 6 above |

See [MCP Server Guide](/docs/integrations/mcp/) for complete tool schemas and JSON response formats.
