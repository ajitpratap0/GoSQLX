# Remote MCP Server Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the GoSQLX MCP server as a public remote service on Render with smart 3-layer rate limiting.

**Architecture:** Add a `Handler()` method to `pkg/mcp/Server` to expose the HTTP handler chain. Create rate limiter middleware (`pkg/mcp/ratelimit.go`) with tiered IP limits, adaptive load scaling, and tool-aware cost weighting. Wrap the handler in `cmd/gosqlx-mcp/main.go`. Containerize with multi-stage Dockerfile. Deploy via GitHub Actions to Render.

**Tech Stack:** Go 1.23+, mark3labs/mcp-go, Render, Docker (distroless), GitHub Actions

**Spec:** `docs/superpowers/specs/2026-03-15-remote-mcp-server-design.md`

---

## Chunk 1: Rate Limiter + Server Refactor

### Task 1: Add Handler() method to Server

**Files:**
- Modify: `pkg/mcp/server.go`

- [ ] **Step 1: Add Handler() method**

Add a new method to `Server` that returns the HTTP handler chain without starting the server. This lets `main.go` wrap it with middleware.

```go
// Handler returns the HTTP handler chain (MCP server + auth middleware)
// without starting an HTTP server. Use this when you need to wrap
// the handler with additional middleware (e.g., rate limiting).
func (s *Server) Handler() http.Handler {
	streamSrv := mcpserver.NewStreamableHTTPServer(s.mcpSrv)
	return BearerAuthMiddleware(s.cfg, streamSrv)
}
```

- [ ] **Step 2: Verify existing tests pass**

```bash
go test ./pkg/mcp/ -v -short
```

- [ ] **Step 3: Commit**

```bash
git add pkg/mcp/server.go
git commit -m "feat(mcp): add Handler() method to expose HTTP handler chain"
```

---

### Task 2: Create rate limiter middleware

**Files:**
- Create: `pkg/mcp/ratelimit.go`
- Create: `pkg/mcp/ratelimit_test.go`

- [ ] **Step 1: Write rate limiter tests**

Create `pkg/mcp/ratelimit_test.go` with tests for:
- Basic request passes when under limit
- Request blocked after exceeding burst limit (10 req/sec)
- Request blocked after exceeding sustained limit (120 weighted/min)
- Tool weight: `analyze_sql` (weight 5) consumes 5x budget
- Non-tool requests (weight 0) are unlimited
- Adaptive: limits tighten under load
- Stale entries cleaned up
- Rate limit response is valid JSON-RPC error with HTTP 200

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./pkg/mcp/ -run TestRateLimit -v
```
Expected: FAIL (ratelimit.go doesn't exist yet)

- [ ] **Step 3: Implement rate limiter**

Create `pkg/mcp/ratelimit.go`:

```go
package mcp

// RateLimiter is HTTP middleware providing 3-layer rate limiting:
// 1. Per-IP tiered limits (burst: 10/sec, sustained: 120 weighted/min)
// 2. Tool-aware cost weighting (analyze_sql=5, lint_sql=2, validate_sql=1)
// 3. Adaptive load scaling (tighten limits under high concurrency)

// toolWeights maps MCP tool names to their cost weight.
var toolWeights = map[string]int{
    "validate_sql":     1,
    "format_sql":       1,
    "parse_sql":        1,
    "extract_metadata": 2,
    "security_scan":    2,
    "lint_sql":         2,
    "analyze_sql":      5,
}

// RateLimitMiddleware wraps an http.Handler with smart rate limiting.
func RateLimitMiddleware(next http.Handler) http.Handler
```

Implementation details:
- Sharded map: `[16]shard` where each shard has `sync.RWMutex` + `map[string]*bucket`
- `bucket` struct: `tokens float64`, `lastRefill time.Time`, `weightedCount int`, `windowStart time.Time`
- Extract IP from `X-Forwarded-For` header, fallback to `RemoteAddr`
- Extract tool name: read body, parse JSON for `method` + `params.name`, re-buffer with `io.NopCloser`
- `MaxBytesReader` (64KB) on request body
- Active request counter via `atomic.Int64`
- Adaptive thresholds: <50 active → 120/min, 50-80 → 60/min, >80 → 30/min
- Rate limit response: HTTP 200 + JSON-RPC error `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Rate limit exceeded..."}}`
- Background cleanup goroutine (every 5 min, remove entries idle >10 min)

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/mcp/ -run TestRateLimit -v
```
Expected: PASS

- [ ] **Step 5: Run all MCP tests + race detector**

```bash
go test -race ./pkg/mcp/ -v
```
Expected: PASS, no races

- [ ] **Step 6: Commit**

```bash
git add pkg/mcp/ratelimit.go pkg/mcp/ratelimit_test.go
git commit -m "feat(mcp): smart rate limiter with tiered, adaptive, tool-aware limiting"
```

---

### Task 3: Wire rate limiter + health endpoint in main.go

**Files:**
- Modify: `cmd/gosqlx-mcp/main.go`

- [ ] **Step 1: Update main.go**

Modify `run()` to:
1. Create the server with `gosqlxmcp.New(cfg)`
2. Get the handler with `srv.Handler()`
3. Wrap with `gosqlxmcp.RateLimitMiddleware(handler)`
4. Add `/health` endpoint via `http.NewServeMux`
5. Start the HTTP server manually (instead of calling `srv.Start()`)

```go
func run() error {
    cfg, err := gosqlxmcp.LoadConfig()
    if err != nil {
        return fmt.Errorf("configuration error: %w", err)
    }

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    srv := gosqlxmcp.New(cfg)

    // Build handler chain: MCP handler → auth → rate limiter
    handler := gosqlxmcp.RateLimitMiddleware(srv.Handler())

    // Mux for /mcp and /health
    mux := http.NewServeMux()
    mux.Handle("/mcp", handler)
    mux.Handle("/mcp/", handler)
    mux.HandleFunc("/health", healthHandler)

    httpSrv := &http.Server{
        Addr:    cfg.Addr(),
        Handler: mux,
    }

    go func() {
        <-ctx.Done()
        _ = httpSrv.Shutdown(context.Background())
    }()

    log.Printf("gosqlx-mcp: listening on %s\n", cfg.Addr())
    if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        return fmt.Errorf("server error: %w", err)
    }
    return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"status":"ok","version":"1.11.1","tools":7}`)
}
```

- [ ] **Step 2: Test locally**

```bash
go run ./cmd/gosqlx-mcp &
curl http://127.0.0.1:8080/health
# Expected: {"status":"ok","version":"1.11.1","tools":7}
kill %1
```

- [ ] **Step 3: Commit**

```bash
git add cmd/gosqlx-mcp/main.go
git commit -m "feat(mcp): wire rate limiter and health endpoint in main"
```

---

## Chunk 2: Containerization + Deployment

### Task 4: Create Dockerfile

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Create multi-stage Dockerfile**

```dockerfile
# Stage 1: Build
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gosqlx-mcp ./cmd/gosqlx-mcp

# Stage 2: Runtime
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /gosqlx-mcp /gosqlx-mcp
EXPOSE 8080
ENTRYPOINT ["/gosqlx-mcp"]
```

- [ ] **Step 2: Test Docker build locally**

```bash
docker build -t gosqlx-mcp .
docker run -p 8080:8080 -e GOSQLX_MCP_HOST=0.0.0.0 gosqlx-mcp &
curl http://127.0.0.1:8080/health
# Expected: {"status":"ok","version":"1.11.1","tools":7}
docker stop $(docker ps -q --filter ancestor=gosqlx-mcp)
```

- [ ] **Step 3: Add .dockerignore**

Create `.dockerignore`:
```
website/
.git/
*.wasm
wasm/playground/
.superpowers/
.playwright-mcp/
dist/
node_modules/
```

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add Dockerfile for gosqlx-mcp server"
```

---

### Task 5: Create render.yaml

**Files:**
- Create: `render.yaml`

- [ ] **Step 1: Create render.yaml**

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

- [ ] **Step 2: Commit**

```bash
git add render.yaml
git commit -m "feat: add render.yaml for Render deployment"
```

---

### Task 6: Create GitHub Actions deployment workflow

**Files:**
- Create: `.github/workflows/deploy-mcp.yml`

- [ ] **Step 1: Create workflow**

```yaml
name: Deploy MCP Server
on:
  push:
    branches: [main]
    paths:
      - 'cmd/gosqlx-mcp/**'
      - 'pkg/mcp/**'
      - 'Dockerfile'
      - 'render.yaml'
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: superfly/render CLI-actions/setup-render CLI@master

      - run: render CLI deploy --remote-only
        env:
          RENDER_DEPLOY_HOOK_URL: ${{ secrets.RENDER_DEPLOY_HOOK_URL }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/deploy-mcp.yml
git commit -m "ci: add GitHub Actions workflow for MCP server deployment to Render"
```

---

## Chunk 3: Documentation + PR

### Task 7: Update docs and README

**Files:**
- Modify: `docs/MCP_GUIDE.md`
- Modify: `README.md`

- [ ] **Step 1: Add Remote Server section to MCP_GUIDE.md**

Add a new section "## Remote Server (Public)" near the top of `docs/MCP_GUIDE.md`:

```markdown
## Remote Server (Public)

A public GoSQLX MCP server is available — no installation needed:

### Claude Code
\`\`\`bash
claude mcp add --transport http gosqlx https://gosqlx.onrender.com/mcp
\`\`\`

### Claude Desktop
Add to `claude_desktop_config.json`:
\`\`\`json
{
  "mcpServers": {
    "gosqlx": {
      "url": "https://gosqlx.onrender.com/mcp"
    }
  }
}
\`\`\`

### Cursor
Add remote MCP server URL: `https://gosqlx.onrender.com/mcp`

### Rate Limits
The public server has smart rate limiting:
- 10 requests/second burst, 120 weighted-requests/minute sustained per IP
- Heavier tools (analyze_sql) consume more budget than simple ones (validate_sql)
- Limits tighten automatically under high server load

### Self-Hosting
To run your own instance, see the [Self-Hosting Guide](#self-hosting-with-docker) below.
```

- [ ] **Step 2: Add remote MCP badge to README.md**

Add a badge in the badges section:
```markdown
[![MCP Server](https://img.shields.io/badge/MCP-Remote%20Server-blue?style=for-the-badge&logo=cloud)](https://gosqlx.onrender.com/health)
```

- [ ] **Step 3: Commit**

```bash
git add docs/MCP_GUIDE.md README.md
git commit -m "docs: add remote MCP server connection instructions"
```

---

### Task 8: Create PR

- [ ] **Step 1: Push branch and create PR**

```bash
git push origin feat/remote-mcp-server
gh pr create --title "feat: remote MCP server on Render with smart rate limiting" --body "..."
```

- [ ] **Step 2: Wait for CI checks to pass**

```bash
gh pr checks <PR_NUMBER>
```

- [ ] **Step 3: Read review comments**

```bash
gh api repos/ajitpratap0/GoSQLX/issues/<PR_NUMBER>/comments --jq '.[].body'
```

- [ ] **Step 4: Address any review issues**

- [ ] **Step 5: Merge after CI + review pass**

---

## Task Dependencies & Parallelization

```
Task 1 (Handler method) — must go first
Task 2 (Rate limiter) — depends on Task 1
Task 3 (Wire in main.go) — depends on Tasks 1+2
Task 4 (Dockerfile) — independent of Tasks 1-3, can parallel
Task 5 (render.yaml) — independent, can parallel with Task 4
Task 6 (CI workflow) — independent, can parallel with Tasks 4+5
Task 7 (Docs) — independent, can parallel
Task 8 (PR) — after all tasks
```

**Parallel opportunities:**
- Tasks 4 + 5 + 6 + 7 (Dockerfile, render.yaml, CI, docs) — all independent, can run in parallel after Tasks 1-3
