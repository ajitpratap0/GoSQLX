# GoSQLX plugin for Claude Code

The official [GoSQLX](https://gosqlx.dev) plugin for Claude Code. It gives Claude SQL validation, formatting, linting, SQL injection scanning and analysis, backed by the GoSQLX parser.

## Install

In Claude Code:

```text
/plugin marketplace add ajitpratap0/GoSQLX
/plugin install gosqlx@gosqlx
```

From a shell:

```sh
claude plugin marketplace add ajitpratap0/GoSQLX
claude plugin install gosqlx@gosqlx
```

The marketplace lives at the root of the GoSQLX repository. To avoid checking out the whole repository, add it with a sparse checkout: `claude plugin marketplace add ajitpratap0/GoSQLX --sparse .claude-plugin plugins`.

Run `/reload-plugins` (or restart Claude Code) and check `/mcp`. The server appears as `plugin:gosqlx:gosqlx`.

## What's included

| Component | Name | What it does |
|---|---|---|
| MCP server | `gosqlx` | Remote GoSQLX MCP server at `https://mcp.gosqlx.dev/mcp`. No install, no API key |
| Skill | `sql-analysis` | Full review via `analyze_sql`, explained in plain language |
| Skill | `sql-formatting` | Formatting via `format_sql` |
| Skill | `sql-security-review` | Injection scan via `security_scan`, plus review of code that builds SQL strings |
| Skill | `sql-linting` | Lint via `lint_sql`; explains rules L001-L030 |
| Skill | `sql-dialects` | Dialect validation via `validate_sql` |
| Command | `/gosqlx:analyze` | Analyze a SQL string or `.sql` file |
| Command | `/gosqlx:format` | Format a SQL string or `.sql` file |
| Command | `/gosqlx:lint` | Lint a SQL string or `.sql` file |
| Command | `/gosqlx:security` | Injection review of SQL or a source file |
| Agent | `sql-reviewer` | Read-only reviewer for SQL files, migrations and SQL-building code |
| Hook | `PostToolUse` | After Claude writes or edits a `.sql` file, validates it with the local `gosqlx` CLI if it is installed |

MCP tools (all read-only): `validate_sql`, `format_sql`, `parse_sql`, `extract_metadata`, `security_scan`, `lint_sql`, `analyze_sql`. In Claude Code they are named `mcp__plugin_gosqlx_gosqlx__<tool>`.

## Usage

```text
/gosqlx:analyze SELECT * FROM users WHERE id = 1 OR 1=1
/gosqlx:format db/queries/report.sql
/gosqlx:lint "select a,b from t  where x=1"
/gosqlx:security internal/store/users.go
@agent-gosqlx:sql-reviewer review the migrations in this branch
```

The skills also trigger from plain requests, for example "is this query valid on Snowflake?", "format this SQL", "explain lint rule L019" or "check this handler for SQL injection".

### Things to know

- `lint_sql` and `gosqlx lint` apply the style rules **L001-L010**. Rules L011-L030 (safety, performance, naming) run only through the Go library (`gosqlx.Lint`). See [LINTING_RULES.md](https://github.com/ajitpratap0/GoSQLX/blob/main/docs/LINTING_RULES.md).
- `validate_sql` accepts these dialects: `generic`, `mysql`, `postgresql`, `sqlite`, `sqlserver`, `oracle`, `snowflake`. Newer server builds also accept `mariadb` and `clickhouse`; if the connected server's tool schema does not list them, use the CLI: `gosqlx validate --dialect clickhouse file.sql`.
- The public server is rate limited: a burst of 10 requests per second and 120 weighted requests per minute per IP. `analyze_sql` costs more than the other tools.

## The validation hook

The hook runs `hooks/validate-sql.sh` after `Write`, `Edit` and `MultiEdit`. It is best-effort and never blocks:

- It does nothing unless the edited file ends in `.sql` and the `gosqlx` CLI is on `PATH`.
- If `gosqlx validate` reports a syntax error, the error is passed back to Claude so it can fix the file.
- It reads the hook input with `jq` when available, with a `sed` fallback otherwise.
- To turn it off, set `GOSQLX_HOOK_DISABLE=1` in your environment.

Install the CLI to enable it:

```sh
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
```

The CLI validates with its default dialect. Dialect-specific files can produce false positives.

## Privacy and data flow

What the plugin runs, sends and fetches:

- **MCP server (remote).** The plugin's only network connection is the hosted server `https://mcp.gosqlx.dev/mcp`. **Any SQL that Claude passes to a GoSQLX tool is sent to that server.** It needs no account or API key and the plugin sends no credentials. The server keeps no SQL, results or request data on disk. Don't send SQL that contains secrets, credentials or personal data. For proprietary schemas or queries, use local mode.
- **Validation hook (local).** The hook runs only the `gosqlx` CLI already installed on your machine, reads only the `.sql` file Claude just wrote, and sends nothing over the network. It downloads and installs nothing.
- **Skills, commands and the agent** are Markdown instructions. They call the MCP tools above or, when the server isn't available, the local `gosqlx` CLI.

The tools only parse and analyze text. They never connect to or execute anything against a database.

Privacy policy: <https://gosqlx.dev/privacy/>.

## Local / private mode

Install the MCP server binary:

```sh
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
```

**Run the server over stdio** and add it as a separate MCP server:

```sh
claude mcp add gosqlx-local -- gosqlx-mcp --stdio
```

Or add it to a project `.mcp.json`:

```json
{
  "mcpServers": {
    "gosqlx-local": {
      "command": "gosqlx-mcp",
      "args": ["--stdio"]
    }
  }
}
```

The local tools are named `mcp__gosqlx-local__<tool>`. The skills refer to tools by their short names (`analyze_sql` and so on), so Claude still finds them, but you may be asked for permission the first time each one runs. To keep everything local, also disable the plugin's remote server (`plugin:gosqlx:gosqlx`) in `/mcp`.

`gosqlx-mcp` without `--stdio` serves HTTP on `127.0.0.1:8080` (`GOSQLX_MCP_HOST` / `GOSQLX_MCP_PORT`); add it with `claude mcp add --transport http gosqlx-local http://127.0.0.1:8080/mcp`.

**CLI only:** with no MCP server at all, every skill, command and the agent fall back to the local `gosqlx` CLI (`validate`, `format`, `lint`, `analyze`).

## Claude.ai and Claude Desktop (custom connector)

Hooks and slash commands run only in Claude Code. In Claude.ai, Claude Desktop and Cowork you can use the same GoSQLX tools as a remote MCP custom connector.

**Pro / Max:**

1. Open **Customize > Connectors**. In some versions this is under **Settings > Connectors**.
2. Click **+ Add**, then **Add custom connector**.
3. Name: `GoSQLX`. Remote MCP server URL: `https://mcp.gosqlx.dev/mcp`.
4. Authentication: **No sign in**. The server needs no auth.
5. Click **Add**.

**Team / Enterprise:** an Owner adds the connector under **Organization settings > Connectors > Add > Custom > Web** with the same name and URL. Members then connect it from **Customize > Connectors**.

**In a chat:** click **+** in the lower-left corner of the composer, open **Connectors**, and turn on **GoSQLX**.

On the Free plan you can add one custom connector. The same privacy note applies: SQL you send through the connector goes to `mcp.gosqlx.dev`.

Claude Desktop can also run the server locally over stdio through `claude_desktop_config.json` (`"command": "gosqlx-mcp", "args": ["--stdio"]`). See the [MCP guide](https://github.com/ajitpratap0/GoSQLX/blob/main/docs/MCP_GUIDE.md).

## Development

```sh
claude plugin validate .                 # from the repository root (marketplace)
claude plugin validate plugins/gosqlx    # the plugin itself
claude --plugin-dir ./plugins/gosqlx     # try it without installing
```

## License

Apache-2.0. See [LICENSE](https://github.com/ajitpratap0/GoSQLX/blob/main/LICENSE).
