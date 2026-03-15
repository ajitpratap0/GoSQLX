# Remote MCP Server — Design Spec

## Overview

Deploy the existing GoSQLX MCP server as a public, no-auth remote service on Render. Any MCP client (Claude Code, Claude Desktop, Cursor) can connect instantly with a single URL. Smart three-layer rate limiting prevents abuse while keeping the service open.

**Goal**: Zero-friction access to 7 SQL tools for any MCP client — no installation, no API key, no signup.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Hosting | Render (free tier, no credit card required) | 750 hrs/month free, Docker support, auto-deploy from GitHub |
| Auth | None (public) | Maximum adoption, no friction. SQL parsing is read-only and safe. |
| Rate limiting | Tiered + adaptive + tool-aware | Prevents abuse without punishing normal use |
| URL | `gosqlx.onrender.com/mcp` | Free Render subdomain, custom domain can be added later |
| Container | Distroless static | Minimal attack surface, ~12-15MB final image (Go binary + base) |
| CI/CD | Render auto-deploy from GitHub | Auto-deploy on MCP-related code changes |
| Region | `iad` (US East) | Render free tier, Oregon region |

## Architecture

```
MCP Client (Claude Code / Desktop / Cursor)
    ↓ HTTPS (Streamable HTTP)
Render Edge (DDoS protection, TLS termination)
    ↓ HTTP
Rate Limiter Middleware (3 layers)
    ↓
GoSQLX MCP Server (modified to accept middleware)
    ↓
7 SQL Tools (validate, format, parse, extract, security, lint, analyze)
```

### Integration Point

The existing `pkg/mcp/server.go` `Server.Start()` method creates the HTTP server internally. To insert the rate limiter, `Server` will be modified to expose a `Handler()` method that returns the `http.Handler` chain. `cmd/gosqlx-mcp/main.go` will then wrap this handler with the rate limiter middleware before starting the HTTP server. This is a small refactor — `Start()` continues to work unchanged for local use; the new `Handler()` method is additive.

### Cold Start Behavior

With `min_machines_running = 0`, the Render VM stops when idle. On the first request after idle, Render boots the machine (~1-3 seconds) + Go binary starts (~100ms). Total cold start: **2-4 seconds**. MCP clients handle this gracefully as the HTTP connection stays open during boot. Subsequent requests have no delay.

## Rate Limiting Design

### Layer 1: Render Edge

Render provides built-in L3/L4 DDoS protection and connection limiting at the proxy level. Configuration via `render.yaml`:

- `auto_stop_machines = "stop"` — stops VM when no traffic (saves resources)
- `auto_start_machines = true` — starts VM on incoming request
- `min_machines_running = 0` — allows full shutdown when idle

No code changes required for this layer.

### Layer 2: Per-IP Tiered Rate Limits

In-process middleware using token bucket algorithm per IP address.

**Limits:**
- **Burst**: max 10 requests/second per IP
- **Sustained**: max 120 weighted-requests/minute per IP

**Implementation:**
- Sharded map (`[16]struct{ sync.RWMutex; m map[string]*rateBucket }`) for concurrent write performance, sharded by IP hash. Avoids `sync.Map` which is optimized for read-heavy workloads, not the frequent-write pattern of rate limiting.
- Each bucket tracks: tokens remaining, last refill time, weighted request count per minute
- IP extracted from `X-Forwarded-For` header (set by Render proxy) with fallback to `RemoteAddr`
- Background goroutine cleans up stale entries (no activity for 10 minutes) every 5 minutes

### Layer 3: Tool-Aware Cost Weighting

Each MCP tool has a cost weight. Rate limit budget is consumed by weight, not raw count.

| Tool | Weight | Reason |
|---|---|---|
| `validate_sql` | 1 | Single parse operation |
| `format_sql` | 1 | Parse + format |
| `parse_sql` | 1 | Single parse |
| `extract_metadata` | 2 | Parse + AST traversal |
| `security_scan` | 2 | Parse + pattern matching |
| `lint_sql` | 2 | Parse + 10 rule evaluations |
| `analyze_sql` | 5 | Runs all 6 tools concurrently |

**Body buffering**: The tool name is extracted from the JSON-RPC request body (`method: "tools/call"`, `params.name: "validate_sql"`). The middleware reads the request body, parses just the top-level `method` and `params.name` fields (not the full SQL content), then re-buffers the body with `io.NopCloser(bytes.NewReader(...))` for the downstream handler. This doubles memory usage for the request envelope only (~200-500 bytes), not the SQL payload. The middleware uses `json.NewDecoder` with a `MaxBytesReader` (64KB) to prevent abuse via oversized requests.

Non-tool requests (initialize, list tools) have weight 0 (unlimited).

### Layer 3b: Adaptive Load Scaling

Limits tighten when the server is under load, measured by active concurrent request count.

| Load Level | Active Requests | Sustained Limit (weighted/min) |
|---|---|---|
| Normal | < 50 | 120 |
| Elevated | 50–80 | 60 |
| Critical | > 80 | 30 |

Active requests tracked via `atomic.Int64` incremented on request start, decremented on completion.

### Rate Limit Response

When rate limited, the middleware returns **HTTP 200 with a JSON-RPC error** (not HTTP 429). This is important because MCP clients expect JSON-RPC responses at the application layer. HTTP-level errors may be mishandled by MCP transport libraries.

```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32000,
    "message": "Rate limit exceeded. Try again in 15 seconds."
  }
}
```

Additional HTTP headers for observability:
- `X-RateLimit-Limit: 120`
- `X-RateLimit-Remaining: 0`
- `X-RateLimit-Reset: <unix timestamp>`

## Health Check

A simple `/health` endpoint registered directly in `cmd/gosqlx-mcp/main.go` (not in the MCP server package). Returns server status for monitoring and uptime checks.

`GET https://gosqlx.onrender.com/health` returns:
```json
{
  "status": "ok",
  "version": "1.11.1",
  "tools": 7
}
```

## Deployment

### Dockerfile

Multi-stage build:
```
Stage 1 (builder): golang:1.23-alpine
  - Copy go.mod, go.sum, download deps
  - Copy source, build cmd/gosqlx-mcp with CGO_ENABLED=0 -ldflags="-s -w"

Stage 2 (runtime): gcr.io/distroless/static
  - Copy binary from builder
  - EXPOSE 8080
  - ENTRYPOINT ["/gosqlx-mcp"]
```

Final image: ~12-15MB (Go static binary ~10-12MB + distroless base ~2MB).

### render.yaml

```toml
app = "gosqlx-mcp"
primary_region = "iad"

[build]

[env]
  GOSQLX_MCP_HOST = "0.0.0.0"
  GOSQLX_MCP_PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
```

### CI/CD Workflow

`.github/workflows/deploy-mcp.yml`:
- **Trigger**: Push to `main` when paths match `cmd/gosqlx-mcp/**`, `pkg/mcp/**`, `Dockerfile`, `render.yaml`
- **Steps**: Checkout → Setup render CLI → Deploy with `curl $RENDER_DEPLOY_HOOK_URL`
- **Secret**: `RENDER_DEPLOY_HOOK_URL` (added to GitHub repo secrets)

## Files

| File | Action | Purpose |
|---|---|---|
| `Dockerfile` | Create | Multi-stage Go build for gosqlx-mcp |
| `render.yaml` | Create | Render deployment configuration |
| `pkg/mcp/ratelimit.go` | Create | Smart rate limiter middleware (3 layers) |
| `pkg/mcp/ratelimit_test.go` | Create | Unit tests for rate limiter |
| `pkg/mcp/server.go` | Modify | Add `Handler()` method to expose the HTTP handler chain |
| `cmd/gosqlx-mcp/main.go` | Modify | Wrap handler with rate limiter, add `/health` endpoint |
| `.github/workflows/deploy-mcp.yml` | Create | CI/CD workflow for Render |
| `docs/MCP_GUIDE.md` | Modify | Add "Remote Server" section with connection instructions |
| `README.md` | Modify | Add remote MCP server badge/link |

## User Experience

### Connecting

```bash
# Claude Code
claude mcp add --transport http gosqlx https://gosqlx.onrender.com/mcp

# Claude Desktop (claude_desktop_config.json)
{
  "mcpServers": {
    "gosqlx": {
      "url": "https://gosqlx.onrender.com/mcp"
    }
  }
}

# Cursor
Add remote MCP server URL: https://gosqlx.onrender.com/mcp
```

### Available Tools (after connecting)

All 7 tools available instantly:
- `validate_sql` — check syntax validity
- `format_sql` — format SQL with options
- `parse_sql` — parse into AST statement types
- `extract_metadata` — extract tables, columns, functions
- `security_scan` — detect SQL injection patterns
- `lint_sql` — lint against 10 rules (L001–L010)
- `analyze_sql` — run all 6 tools in one call

## Out of Scope

- Custom domain (add CNAME later when ready)
- Authentication / API keys (public for now)
- Multi-region deployment (single `iad` for now)
- Usage analytics / dashboards
- Persistent storage (server is stateless)
- WebSocket transport (Streamable HTTP only)
