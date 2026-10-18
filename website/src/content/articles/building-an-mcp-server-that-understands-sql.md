---
title: "Building an MCP server that understands SQL"
description: "How GoSQLX exposes a real SQL parser to AI assistants over the Model Context Protocol in Go: tool design, error shapes, annotations and hosting."
date: 2026-10-18
tags: [mcp, ai, go, sql]
---

AI assistants write a lot of SQL, and most of it looks right. The problem is that "looks right" is all a language model can offer on its own. It cannot run a parser in its head, so a missing comma, a dialect-specific function or a `GROUP BY` that does not match the select list comes back to you as a runtime error, or worse, as a query that runs and returns the wrong thing.

The [Model Context Protocol](https://modelcontextprotocol.io) (MCP) lets an assistant call tools that you provide. If one of those tools is a real SQL parser, the assistant can check its own work before showing it to you. This post describes how the GoSQLX MCP server is built, and the design decisions that make a tool useful to a model rather than just callable by one.

## What an MCP tool is

An MCP tool has three parts: a name, a JSON Schema describing its arguments, and a handler. The client, such as Claude or Cursor, lists the tools when it connects, shows their descriptions to the model, and forwards the model's calls to your handler.

In Go, the `mark3labs/mcp-go` package handles the protocol. A complete server with one SQL tool fits on a screen:

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	s := server.NewMCPServer("sql-tools", "0.1.0", server.WithToolCapabilities(false))

	s.AddTool(
		mcp.NewTool("validate_sql",
			mcp.WithDescription("Check whether a SQL statement is syntactically valid. Returns {valid, error?, line?, column?}."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithString("sql", mcp.Required(), mcp.Description("The SQL to check")),
		),
		validateSQL,
	)

	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}

func validateSQL(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sql, err := req.RequireString("sql")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	result := map[string]any{"valid": true}
	if err := gosqlx.Validate(sql); err != nil {
		result = map[string]any{"valid": false, "error": err.Error()}
		if loc := gosqlx.ErrorLocation(err); loc != nil {
			result["line"], result["column"] = loc.Line, loc.Column
		}
	}

	b, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}
```

Sent `SELECT id FROM WHERE x = 1`, it answers:

```json
{
  "valid": false,
  "line": 1,
  "column": 16,
  "error": "gosqlx: syntax error: Error E2002 at line 1, column 16: expected identifier, got WHERE ..."
}
```

That is enough for a model to see what it got wrong, fix it and call the tool again.

## Design decision 1: invalid SQL is an answer, not an error

MCP distinguishes between a tool that fails (a protocol error, or a result flagged as an error) and a tool that succeeds with bad news. For a validator, "this SQL is invalid" is the successful outcome of the tool. Returning it as data, `{"valid": false, ...}` with a position, gives the model something to act on. Returning it as a failure tends to make clients report that the tool broke, and the model learns nothing about its query.

The GoSQLX server applies the same rule throughout: a missing `sql` argument is an error, because the call itself was wrong; SQL that fails to parse is a normal result.

## Design decision 2: thin tools over a real library

The production server, `gosqlx-mcp`, exposes seven tools:

| Tool | What it returns |
|---|---|
| `validate_sql` | Valid or not, with the parse error; optional dialect |
| `format_sql` | The formatted SQL, with indentation and keyword-case options |
| `parse_sql` | Statement count and statement types |
| `extract_metadata` | Tables, columns and functions referenced |
| `security_scan` | SQL injection findings with severities |
| `lint_sql` | Style rule violations |
| `analyze_sql` | All six of the above in one call |

None of them contains SQL logic. Each handler reads its arguments, calls the same `pkg/gosqlx`, `pkg/linter` or `pkg/sql/security` function a Go program would call, and marshals the result. That keeps the server small, and it means a fix in the parser reaches the assistant without touching the MCP layer.

## Design decision 3: tell the client the tools are safe

MCP tool annotations describe how a tool behaves. Every GoSQLX tool is declared read-only, non-destructive, idempotent and closed-world: it only looks at the string it was given, never touches a database and always gives the same answer for the same input. Clients can use those hints to call such tools without asking the user each time, which matters when a model wants to validate every query it writes.

## Design decision 4: one round trip for the full picture

Models are charged, in time and tokens, for every tool call. When an assistant wants a full review of a query, six separate calls is a poor experience. `analyze_sql` runs validation, parsing, metadata extraction, the security scan, linting and formatting concurrently, one goroutine each, and merges the results into a single response. A failure in one analysis is reported under an `errors` key without hiding the others.

This is safe because the underlying library is: GoSQLX parses concurrently from many goroutines, with its pools tested under the race detector (see [sync.Pool for AST nodes without races](/blog/sync-pool-ast-nodes-without-races/)).

## Design decision 5: a transport for each setting

The same tools work locally and remotely:

- **stdio**, as in the example above, for a server the client starts as a subprocess on your machine.
- **Streamable HTTP**, which `gosqlx-mcp` serves by default, for a server shared by a team or hosted publicly. Optional bearer-token authentication protects a server exposed beyond localhost.

A public instance runs at `https://mcp.gosqlx.dev/mcp`, with per-IP rate limiting in which heavier tools such as `analyze_sql` cost more than simple ones. The tools only analyse the SQL text they are sent and never connect to a database, so a hosted instance has no data of yours to expose.

## Try it

Connect Claude Code to the public server:

```bash
claude mcp add --transport http gosqlx https://mcp.gosqlx.dev/mcp
```

Or run your own:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
gosqlx-mcp
# gosqlx-mcp: listening on 127.0.0.1:8080 (auth=false)
```

Then ask the assistant to write a query and validate it before answering. The difference is not that the model writes better SQL; it is that it now finds out when it did not.

Further reading:

- [MCP server guide](/docs/integrations/mcp/): configuration, authentication and every tool's arguments
- [mcp package reference](/docs/reference/api/mcp/): embed the server in your own Go program
- [Blocking SQL injection with AST analysis](/blog/blocking-sql-injection-with-ast-analysis/): gate the SQL an assistant wants to run
