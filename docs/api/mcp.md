# mcp package

The Model Context Protocol server that exposes GoSQLX tools to AI assistants.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/mcp` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/mcp))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

MCP server exposing all GoSQLX capabilities as Model Context Protocol tools over streamable HTTP.

## Types

### `Config`
```go
type Config struct {
    Host                     string // GOSQLX_MCP_HOST (default "127.0.0.1")
    Port                     int    // GOSQLX_MCP_PORT (default 8080, range 1–65535)
    AuthToken                string // GOSQLX_MCP_AUTH_TOKEN (default "" = auth disabled)
    OpenAIAppsChallenge      string // GOSQLX_MCP_OPENAI_APPS_CHALLENGE (served at /.well-known/openai-apps-challenge)
    TrustedProxyHeader       string // GOSQLX_MCP_TRUSTED_PROXY_HEADER, e.g. "CF-Connecting-IP"
    TrustedProxyHops         int    // GOSQLX_MCP_TRUSTED_PROXY_HOPS (X-Forwarded-For hops; 0 = ignored)
    TrustedProxySecretHeader string // GOSQLX_MCP_TRUSTED_PROXY_SECRET_HEADER
    TrustedProxySecret       string // GOSQLX_MCP_TRUSTED_PROXY_SECRET (min 16 bytes)
}
```

Without a trusted-proxy setting, rate limits key on the TCP peer address, so every client behind a reverse proxy shares one bucket. When both secret fields are set, the trusted header and hops apply only to requests that carry the shared secret (constant-time compare). See [MCP_GUIDE.md](../MCP_GUIDE.md) for the proxy setup.

## Functions

### `LoadConfig() (*Config, error)`
Load from env vars. Returns an error if `GOSQLX_MCP_PORT` is non-integer or out of range, or if the trusted-proxy settings are invalid (bad header name, `X-Forwarded-For` as the trusted header, hops outside 0-16, a proxy secret shorter than 16 bytes, a secret header or secret set without the other, a secret header that reuses `Authorization`, `X-Forwarded-For` or the trusted header, or a secret with no trusted header or hops configured). See [MCP_GUIDE.md](../MCP_GUIDE.md).

### `DefaultConfig() *Config`
Returns `Config{Host: "127.0.0.1", Port: 8080}` with auth disabled and no trusted proxy.

### `New(cfg *Config) *Server`
Create server with all 7 tools registered. Registers tools once at construction - no dynamic registration.

### `(s *Server) Handler() http.Handler`
Returns the streamable HTTP handler wrapped in bearer auth. Use it to embed the server in your own `http.Server`.

> **Warning:** `Handler` and `Start` do not apply rate limiting, the GET stream cap, the body read deadline or the 64 KB body cap. Wrap `Handler()` with `NewRateLimitMiddleware(cfg, h)` (as `cmd/gosqlx-mcp` does) before exposing it to untrusted clients.

### `(s *Server) Start(ctx context.Context) error`
Bind to `cfg.Addr()`, serve streamable HTTP with read-header and idle timeouts. Blocks until ctx is cancelled or a fatal error occurs, then shuts down the HTTP server and the session sweeper. Applies bearer auth only (see the warning above).

### `(s *Server) Shutdown(ctx context.Context) error`
Stops the shared transport and its idle-session sweeper. Call it when you serve `Handler()` yourself.

### `NewRateLimitMiddleware(cfg *Config, next http.Handler) http.Handler`
Per-client rate limiting keyed by peer address or the configured trusted proxy. Denials are HTTP 429 with `Retry-After` (a denied `initialize` keeps HTTP 200 for mcp-go clients). Also enforces the 64 KB body cap, the body read deadline and 4 GET (SSE) streams per client.

### `RateLimitMiddleware(next http.Handler) http.Handler`
`NewRateLimitMiddleware(nil, next)`: keys on the TCP peer address only.

### `BearerAuthMiddleware(cfg *Config, next http.Handler) http.Handler`
Returns `next` unchanged when `cfg.AuthEnabled()` is false. When enabled, enforces `Authorization: Bearer <token>` (scheme case-insensitive, token compared in constant time) on all requests; returns HTTP 401 on failure.

### `SessionIdleTTL`
How long an idle MCP session's transport state is kept before the sweeper frees it.

## Registered Tools

| Tool | Description |
|------|-------------|
| `validate_sql` | SQL syntax validation with optional dialect |
| `format_sql` | SQL formatting (indent, keyword case, semicolon) |
| `parse_sql` | AST summary with optional dialect - statement count and types |
| `extract_metadata` | Tables, columns, functions referenced |
| `security_scan` | Injection pattern detection with severity |
| `lint_sql` | Style rule enforcement (L001–L010) |
| `analyze_sql` | Concurrent composite of all 6 above |

`parse_sql` accepts a required `sql` string and an optional `dialect` string (default: `generic`).
Use `"dialect": "sqlserver"` for scripts containing `GO`. The response keys
`statement_count` and `statement_types` exclude `GO` batch separators
(`*ast.BatchSeparator`), including separators with repeat counts.

See [MCP Server Guide](../MCP_GUIDE.md) for complete tool schemas and JSON response formats.
