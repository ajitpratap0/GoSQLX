---
name: sql-analysis
description: Full GoSQLX review of a SQL query or .sql file - syntax validity, statement types, referenced tables/columns/functions, injection patterns, style lint and a formatted version - followed by a plain-language explanation of what the SQL does and what to fix. Use when the user asks to analyze, review, check, explain or sanity-check SQL.
argument-hint: "[SQL string or path to .sql file]"
allowed-tools: mcp__plugin_gosqlx_gosqlx__analyze_sql mcp__plugin_gosqlx_gosqlx__validate_sql mcp__plugin_gosqlx_gosqlx__extract_metadata Read Bash(gosqlx analyze:*) Bash(gosqlx validate:*)
---

# SQL analysis with GoSQLX

Input: `$ARGUMENTS` - a SQL string, or a path to a `.sql` file (read the file first). If nothing was given, use the SQL in the current conversation or ask for it.

## Steps

1. Call `analyze_sql` (MCP server `gosqlx`, tool `mcp__plugin_gosqlx_gosqlx__analyze_sql`) with `{"sql": "<the SQL>"}`. It runs validate, parse, metadata, security, lint and format concurrently and returns one report with those six sections.
2. If the user names a dialect, also call `validate_sql` with `dialect` set (see the `sql-dialects` skill for valid values), because `analyze_sql` validates with the generic parser.
3. For a large multi-statement file, it is fine to analyze statement by statement.

## Report back

- **Verdict**: valid or not. For a parse error, quote the error and point at the line/column.
- **What it does**: statement types and the tables, columns and functions it touches (from the parse and metadata sections).
- **Security**: each finding with severity (CRITICAL/HIGH/MEDIUM/LOW) and pattern. A clean scan means no known injection pattern was found, not that the calling code is safe - see `sql-security-review`.
- **Style**: lint violations (rules L001-L010) grouped by rule, with the suggested fix.
- **Formatted SQL**: show the formatted version only when it differs meaningfully.
- **Recommendations**: a short prioritized list. Add your own judgment (missing indexes, `NOT IN` with NULLs, unbounded `DELETE`/`UPDATE`, `SELECT *`) and label it as your judgment, not GoSQLX output.

## Fallback when the MCP tools are unavailable

If the `gosqlx` MCP server is not connected, use the local CLI via Bash (install: `go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest`):

```sh
gosqlx validate path/to/query.sql          # or: echo "SELECT ..." | gosqlx validate
gosqlx analyze --all path/to/query.sql     # security, performance and complexity report
gosqlx analyze "SELECT * FROM users"       # inline SQL
```

Never execute the SQL against a database as part of the analysis.
