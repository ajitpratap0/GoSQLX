# GoSQLX for ChatGPT

GoSQLX runs in ChatGPT as an app built on the MCP server in
[`cmd/gosqlx-mcp`](../../cmd/gosqlx-mcp). This is the same server that Claude,
Cursor and other MCP clients use. ChatGPT gets the same seven read-only SQL tools
plus an interactive report for `analyze_sql`.

- **Endpoint:** `https://mcp.gosqlx.dev/mcp` (MCP streamable HTTP)
- **Authentication:** none
- **What it does:** parses, validates, formats, lints and security-scans SQL text.
  It never connects to a database and never executes SQL.

Technical details (metadata keys, resource URI, result shapes) are in
[docs/CHATGPT_APP.md](../../docs/CHATGPT_APP.md).

## Connect in ChatGPT (developer mode)

1. In ChatGPT, open **Settings → Apps & Connectors → Advanced settings** and turn on
   **Developer mode**. On Business, Enterprise and Edu workspaces an admin has to
   allow it first.
2. Back in **Settings → Apps & Connectors**, choose **Create**.
3. Fill in the form:
   - **Name:** `GoSQLX`
   - **Description:** `Parse, validate, format, lint and security-scan SQL across 8 dialects. Read-only; never runs queries.`
   - **MCP server URL:** `https://mcp.gosqlx.dev/mcp`
   - **Authentication:** `No authentication`
4. Tick the trust checkbox and click **Create**. The seven tools are listed.
5. In a chat, click **+ → More**, pick **GoSQLX**, and ask a question about SQL.

If you change the server (new tools, new descriptions or a new widget), go to
**Settings → Apps & Connectors → GoSQLX → Refresh** so ChatGPT re-reads the tool list.

Menu labels in ChatGPT change from time to time. If a step above does not match
what you see, look for "Developer mode" and "Create connector" under Apps or Connectors.

### Other ways to test

- **MCP Inspector:** `npx @modelcontextprotocol/inspector@latest`, choose
  transport "Streamable HTTP" and URL `https://mcp.gosqlx.dev/mcp`.
- **OpenAI API Playground:** Tools → Add → MCP Server → the same URL, no auth.

## Example prompts

| Prompt | Tool ChatGPT should pick |
|---|---|
| "Review this query: `SELECT * FROM orders o JOIN users u ON o.user_id = u.id WHERE u.email = 'a' OR 1=1`" | `analyze_sql` (renders the report) |
| "Is `SELECT TOP 10 * FROM t` valid SQL Server syntax?" | `validate_sql` with `dialect: sqlserver` |
| "Format this SQL with 4-space indentation and uppercase keywords: …" | `format_sql` |
| "Which tables and columns does this query touch?" | `extract_metadata` |
| "Does this WHERE clause look like SQL injection? `id = '' OR '1'='1' --`" | `security_scan` |
| "Lint this SQL for style problems." | `lint_sql` |
| "How many statements are in this script, and what kinds?" | `parse_sql` |

Prompts where GoSQLX should *not* be used, because it neither runs SQL nor knows your
schema:

- "How many rows are in my `users` table?"
- "Write me a migration that adds a column." (GoSQLX can validate the result, but it does not write SQL.)
- "Connect to my Postgres database."

## What the widget shows

When ChatGPT, or any other host that supports MCP Apps, calls `analyze_sql`, it renders
an inline report next to the answer:

- a **Valid / Invalid** badge and the parser error, if there is one
- counts of statements, tables, security findings and lint violations
- **Statements:** the type of each statement (SELECT, INSERT, …)
- **Tables, columns & functions** the query references
- **Security:** injection findings sorted by severity (critical, high, medium, low),
  each with its risk and a suggested fix
- **Lint:** violations of rules L001–L010, with line:column and a suggestion
- **Formatted SQL**, with a **Copy** button
- **Skipped checks:** sub-checks that could not run (for example, formatting invalid SQL)

The widget is one self-contained HTML file with inline CSS and JS. It makes no network
requests, follows ChatGPT's light or dark theme, and renders all data as text.

## Self-hosting

The server is one static Go binary.

```bash
# Docker (repository root)
docker build -t gosqlx-mcp .
docker run -p 8080:8080 -e GOSQLX_MCP_HOST=0.0.0.0 gosqlx-mcp

# or from source
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
GOSQLX_MCP_HOST=0.0.0.0 gosqlx-mcp
```

To deploy on Render, use the [`render.yaml`](../../render.yaml) blueprint at the
repository root. The health check is `GET /health`.

ChatGPT has to reach the server over **public HTTPS**. For local development you can
use a tunnel such as `ngrok http 8080` or `cloudflared tunnel --url http://localhost:8080`
and give ChatGPT `https://<tunnel-host>/mcp`. Tunnels are fine in developer mode but
are not accepted for directory submission.

| Variable | Purpose |
|---|---|
| `GOSQLX_MCP_HOST` / `GOSQLX_MCP_PORT` | Bind address (default `127.0.0.1:8080`). |
| `GOSQLX_MCP_AUTH_TOKEN` | Optional bearer token. Leave it empty for ChatGPT "No authentication". Once a token is set, tools no longer advertise `securitySchemes: noauth`, and ChatGPT cannot send a static bearer token. |
| `GOSQLX_MCP_OPENAI_APPS_CHALLENGE` | Domain-verification token from the OpenAI Platform, served as plain text at `/.well-known/openai-apps-challenge`. |

## Privacy

- All tools run locally inside the server process on the SQL text you send. GoSQLX
  never connects to a database and never executes SQL.
- The hosted server at `mcp.gosqlx.dev` does not log, store or forward the SQL it
  processes. Its only state is in memory: MCP session state (swept after 30 minutes of inactivity)
  and per-IP rate-limit counters (dropped after 10 minutes of inactivity). Render and
  Cloudflare, which host and front it, see connection metadata such as IP addresses.
  See <https://gosqlx.dev/privacy/>.
- Tool results contain only analysis of the SQL you sent: no user identifiers, request
  IDs or timestamps. ChatGPT request metadata such as locale or user agent is not used.
- Do not paste secrets or personal data into SQL you send to *any* hosted service. For
  sensitive SQL, self-host the server.

## Directory submission checklist

Submit through the OpenAI Platform dashboard (`platform.openai.com/apps-manage`). The
organization must be verified, and you need the Owner role. Submission is not
available to projects with EU data residency.

- [ ] Public, stable HTTPS endpoint: `https://mcp.gosqlx.dev/mcp` (not a tunnel).
- [ ] Domain verification: set `GOSQLX_MCP_OPENAI_APPS_CHALLENGE` in the Render
      dashboard (`render.yaml` declares it with `sync: false`), redeploy, and confirm `curl https://mcp.gosqlx.dev/.well-known/openai-apps-challenge`
      returns the token.
- [ ] CSP declared: the widget resource declares empty `ui.csp` and `openai/widgetCSP`
      (no remote domains are needed).
- [ ] Tool annotations and their justifications. Every tool is
      `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`
      (`idempotentHint: true`), because each one is a pure function of its input
      SQL: no writes, no deletes, no network or database access.
- [ ] Authentication: "No authentication" (`securitySchemes: [{type: "noauth"}]`).
      No test account is needed.
- [ ] Privacy policy URL: <https://gosqlx.dev/privacy/>. It must cover the data
      categories, purposes, recipients and user controls.
- [ ] Terms of service URL: <https://gosqlx.dev/terms/>.
- [ ] Support contact: <https://github.com/ajitpratap0/GoSQLX/issues> (if the form
      insists on an email address, use a maintainer-controlled inbox).
- [ ] Logo (light and dark), at least 3 screenshots of the `analyze_sql` widget, and a
      short demo video.
- [ ] Test cases: use the positive and negative example prompts above
      (reportedly 5 positive and 3 negative).
- [ ] Review the guidelines: no tool descriptions that push the model to prefer
      GoSQLX, minimal data collection, no restricted data.
- [ ] Once the app is published, tool names, signatures and descriptions are locked,
      and any change needs resubmission. The widget URI carries a version
      (`ui://gosqlx/analysis-v1.html`); bump it whenever the widget changes in a
      breaking way.
