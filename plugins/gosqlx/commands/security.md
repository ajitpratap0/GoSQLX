---
description: Scan a SQL string, .sql file, or SQL-building source file for injection risks with GoSQLX
argument-hint: "<SQL string | path/to/file>"
allowed-tools: mcp__plugin_gosqlx_gosqlx__security_scan Read Grep Glob Bash(gosqlx analyze:*) Bash(gosqlx lint:*)
---

Run a SQL injection review with GoSQLX on: $ARGUMENTS

- If the argument is a `.sql` file or SQL text, call the `security_scan` MCP tool on the SQL and report findings by severity with pattern, risk and suggested fix.
- If it is a source file (Go, Python, JS/TS, Java, PHP, ...), find every place that builds SQL from variables, explain which ones are injectable, scan reconstructed SQL with `security_scan` where useful, and recommend parameterized queries or allowlists.
- If it is empty, review the SQL-related code changed in this session.

Follow the `sql-security-review` skill. If the MCP server is unavailable, use `gosqlx analyze --security` via Bash. Do not modify any file.
