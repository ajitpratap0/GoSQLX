---
description: Full GoSQLX analysis of a SQL string or .sql file (validity, metadata, security, lint, formatting)
argument-hint: "<SQL string | path/to/file.sql>"
allowed-tools: mcp__plugin_gosqlx_gosqlx__analyze_sql mcp__plugin_gosqlx_gosqlx__validate_sql Read Bash(gosqlx analyze:*) Bash(gosqlx validate:*)
---

Analyze this SQL with GoSQLX: $ARGUMENTS

If the argument is a path to an existing file, read it and use its contents as the SQL; otherwise treat the argument as SQL text. If it is empty, ask for the SQL.

Call the `analyze_sql` MCP tool with the SQL, then follow the `sql-analysis` skill to report: validity (with line/column for errors), what the statement does, security findings by severity, lint violations by rule, and a short prioritized fix list. If the MCP server is unavailable, fall back to `gosqlx validate` and `gosqlx analyze --all` via Bash. Do not modify any file.
