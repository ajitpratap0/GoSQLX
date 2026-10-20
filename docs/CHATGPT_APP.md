# GoSQLX as a ChatGPT App (Apps SDK / MCP Apps)

`gosqlx-mcp` is one MCP server that works in three kinds of host:

- **Plain MCP clients** (Claude Code, Cursor, MCP Inspector, …). They see seven
  tools that return JSON text, exactly as before.
- **MCP Apps hosts** (extension `io.modelcontextprotocol/ui`, spec 2026-01-26, such as
  Claude). They also render the interactive `analyze_sql` report.
- **ChatGPT** (OpenAI Apps SDK). It reads the MCP Apps keys and the legacy `openai/*`
  aliases, and renders the same report.

Hosts ignore `_meta` keys they do not understand. That is why one tool list works
in all three without negotiating capabilities per host.

User-facing setup is in [integrations/chatgpt/README.md](../integrations/chatgpt/README.md).
General server documentation is in [MCP_GUIDE.md](MCP_GUIDE.md).

## Source layout

| File | Role |
|---|---|
| `pkg/mcp/server.go` | Server construction: version (`gosqlx.Version`), `WithInstructions`, resource capability, tool registration with shared annotations |
| `pkg/mcp/apps.go` | Widget URI and MIME type, `go:embed` of the widget, tool and resource `_meta` builders, resource registration |
| `pkg/mcp/widget/analysis.html` | Self-contained report widget (inline CSS/JS, no network) |
| `pkg/mcp/tools.go` | Tool handlers; `toolResult` returns text plus `structuredContent` |
| `cmd/gosqlx-mcp/main.go` | HTTP routes: `/mcp`, `/health`, optional `/.well-known/openai-apps-challenge` |

## Initialize

- `serverInfo.version` is `gosqlx.Version`. It is no longer hard-coded.
- `capabilities` advertises `tools` and `resources`.
- `instructions` describes when to use each tool. It does not steer the model toward
  GoSQLX for unrelated requests, which would break the OpenAI submission guidelines.

## Tools

All seven tools (`validate_sql`, `format_sql`, `parse_sql`, `extract_metadata`,
`security_scan`, `lint_sql`, `analyze_sql`) share these annotations:

```json
{"title": "...", "readOnlyHint": true, "destructiveHint": false,
 "idempotentHint": true, "openWorldHint": false}
```

ChatGPT requires `readOnlyHint`, `destructiveHint` and `openWorldHint` to be set
explicitly. When they are missing, it assumes the worst case and asks the user to
confirm every call.

Every tool's `_meta` contains:

| Key | Value | Consumer |
|---|---|---|
| `openai/toolInvocation/invoking` | for example `"Validating SQL…"` | ChatGPT status line (≤ 64 chars) |
| `openai/toolInvocation/invoked` | for example `"Validated SQL"` | ChatGPT status line |
| `securitySchemes` | `[{"type":"noauth"}]`, only when `GOSQLX_MCP_AUTH_TOKEN` is unset | ChatGPT auth (back-compat `_meta` mirror) |

`analyze_sql` also carries the widget binding:

```json
"_meta": {
  "ui": {"resourceUri": "ui://gosqlx/analysis-v1.html", "visibility": ["model", "app"]},
  "openai/outputTemplate": "ui://gosqlx/analysis-v1.html",
  "openai/widgetAccessible": true
}
```

- `ui.resourceUri` is the MCP Apps source of truth. The deprecated flat key
  `ui/resourceUri` is not emitted.
- `openai/outputTemplate` is set to the same URI because some ChatGPT builds only
  render with the legacy key.
- `ui.visibility: ["model","app"]` and `openai/widgetAccessible: true` let the widget
  call the tool again if a later version adds interactivity. The current widget only
  displays results.

Only `analyze_sql` gets the widget. The widget renders the composite report shape
(`validate`, `parse`, `metadata`, `security`, `lint`, `format`, `errors`). The other
tools return different shapes and stay text and JSON only.

The `validate_sql` `dialect` enum is `generic, postgresql, mysql, mariadb, sqlserver,
oracle, sqlite, snowflake, clickhouse`. All nine are accepted by
`gosqlx.ParseWithDialect`, and a test checks each one.

`lint_sql` applies the 10 rules that `newFullLinter` registers. They are the same set
`gosqlx lint` uses: L001–L010, with a line-length limit of 100.

## UI resource

`resources/list`:

```json
{"uri": "ui://gosqlx/analysis-v1.html", "name": "gosqlx_analysis_report",
 "mimeType": "text/html;profile=mcp-app", "description": "...", "_meta": { ... }}
```

`resources/read` returns exactly one `TextResourceContents` whose `text` is the
embedded HTML. It carries the following `_meta`, which is also copied onto the
`resources/list` entry:

```json
{
  "ui": {
    "csp": {"connectDomains": [], "resourceDomains": []},
    "prefersBorder": true,
    "permissions": {"clipboardWrite": {}}
  },
  "openai/widgetCSP": {"connect_domains": [], "resource_domains": []},
  "openai/widgetPrefersBorder": true,
  "openai/widgetDescription": "Interactive GoSQLX analysis report: ..."
}
```

- **MIME type:** `text/html;profile=mcp-app` (ext-apps `RESOURCE_MIME_TYPE`). ChatGPT
  accepts it in place of the legacy `text/html+skybridge`.
- **CSP:** empty on purpose. The widget loads no remote scripts, styles, fonts or
  images and makes no `fetch`/XHR calls, so the MCP Apps default CSP is enough.
  Submission still requires a CSP to be declared.
- **`clipboardWrite`:** requested for the Copy button. When the host does not grant
  it, the widget falls back to `document.execCommand("copy")`. OpenAI documents that
  ChatGPT widgets cannot use `navigator.clipboard`, and the sandbox may also block
  `execCommand`, in which case the button shows "Copy failed" and the user copies
  from the code block.
- **Versioned URI:** ChatGPT caches templates by URI. Bump `-v1` in
  `AnalysisWidgetURI` whenever the widget changes in a way that is incompatible with
  older results.
- `openai/widgetDomain` is not set. The widget does not need its own origin.

## Tool results

`toolResult` returns:

```json
{
  "content": [{"type": "text", "text": "<compact JSON>"}],
  "structuredContent": { ...same object... }
}
```

- The `text` content is byte-for-byte what earlier versions returned, so existing
  clients and tests keep working. A test checks this.
- `structuredContent` is the same map. The model sees it, and the widget receives it
  as `params.structuredContent` in `ui/notifications/tool-result`, or as
  `window.openai.toolOutput` in ChatGPT.
- No result-level `_meta` is set. Results contain no request IDs, timestamps or user
  data (response minimisation).
- Protocol-level errors (missing `sql`, parse failure in `parse_sql`, …) behave as
  before.

## Widget runtime

`pkg/mcp/widget/analysis.html` implements a minimal MCP Apps view by hand, without a
build step or SDK:

1. Posts JSON-RPC `ui/initialize` (with `appInfo`/`clientInfo`, `appCapabilities`,
   `protocolVersion: "2026-01-26"`) to `window.parent`. It applies
   `hostContext.theme` and the font variables, then sends
   `ui/notifications/initialized`.
2. Handles `ui/notifications/tool-input`, `tool-result`, `tool-cancelled` and
   `host-context-changed`, and answers `ping` and `ui/resource-teardown`.
3. Sends `ui/notifications/size-changed` from a `ResizeObserver` on the content
   root (so the reported height can shrink as well as grow). In ChatGPT it also
   calls `window.openai.notifyIntrinsicHeight`.
4. ChatGPT fallback: reads `window.openai.toolOutput`, `toolInput` and `theme`, and
   listens for `openai:set_globals`.
5. Theme: follows the host theme (`data-theme`) and otherwise `prefers-color-scheme`.
6. Failed calls: a tool result with `isError: true`, or one without analysis data,
   shows "Analysis failed" with the error text instead of waiting forever.
7. Large results: repeated statement types collapse into counts (`SELECT ×5000`), and
   every chip and finding list shows its first 50 items with a "+K more" toggle; an
   expanded list scrolls inside a fixed height. The reported iframe height stays
   bounded however large the input is.
8. Copy uses the async Clipboard API only when the frame's permissions policy allows
   `clipboard-write`, and `execCommand("copy")` otherwise, so hosts that omit
   `allow="clipboard-write"` see no console error.

It renders all data with `textContent`, so SQL text and error messages are never parsed
as HTML. The test `TestApps_ResourcesRead_ReturnsSelfContainedWidget` fails if the
HTML gains remote `src`/`href` URLs, `@import`, `fetch(`, `XMLHttpRequest` or
`innerHTML`.

## HTTP endpoints (`cmd/gosqlx-mcp`)

| Path | Purpose |
|---|---|
| `/mcp` | MCP streamable HTTP: rate limit → optional bearer auth → MCP |
| `/health` | `{"status":"ok","version":<gosqlx.Version>,"tools":<registered tool count>}` |
| `/.well-known/openai-apps-challenge` | Plain-text domain-verification token. Served only when `GOSQLX_MCP_OPENAI_APPS_CHALLENGE` is set; returns 404 otherwise |

### Sessions

The streamable HTTP transport runs in mcp-go's default stateless mode. Session IDs
are random, the server does not record which ones it issued, and any well-formed
ID is accepted. Per-session transport state (request-ID counters, per-session
tool/resource registrations, last-activity time) is removed by a sweeper that runs
every `SessionIdleTTL/2`, so state goes 30 to 45 minutes after a session's last
request (`SessionIdleTTL` is 30 minutes). Neither the sweep nor `DELETE /mcp`
invalidates an ID: a later request with the same ID simply starts new state.
mcp-go's informational transport logs, which include session IDs, are discarded;
only transport errors are logged, so nothing identifies a session in the logs.

The HTTP server sets `ReadHeaderTimeout`. `Server.Start` (library use) also sets
`IdleTimeout` but applies only bearer auth, not the rate limiter or the 64 KB body
cap; `cmd/gosqlx-mcp` wraps the handler in `RateLimitMiddleware`. Call
`Server.Shutdown` when you discard a `Server` whose `Handler` you used, to stop the
session sweeper goroutine.

The server sends no CORS headers. ChatGPT and Claude connect to MCP servers server to
server, and nothing in the Apps SDK or MCP Apps requirements asks for CORS on the MCP
endpoint. Browser-based tools such as MCP Inspector go through their own proxy.

## Not implemented (optional)

- `search`/`fetch` tools for ChatGPT company knowledge and deep research. They only
  make sense over documentation, not over SQL analysis.
- OAuth. The public server is anonymous and read-only.
- `openai/widgetDomain` and fullscreen display modes.

## Verifying locally

```bash
GOSQLX_MCP_PORT=8765 go run ./cmd/gosqlx-mcp &
H='-H Content-Type:application/json -H Accept:application/json,text/event-stream'
curl -si $H localhost:8765/mcp -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# copy the Mcp-Session-Id response header into SID, then:
curl -s $H -H "Mcp-Session-Id: $SID" localhost:8765/mcp -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
curl -s $H -H "Mcp-Session-Id: $SID" localhost:8765/mcp -d '{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"ui://gosqlx/analysis-v1.html"}}'
curl -s $H -H "Mcp-Session-Id: $SID" localhost:8765/mcp -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_sql","arguments":{"sql":"SELECT id FROM users WHERE id = 1 OR 1=1"}}}'
```
