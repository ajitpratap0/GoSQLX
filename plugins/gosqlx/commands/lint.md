---
description: Lint a SQL string or .sql file with GoSQLX style rules (L001-L010)
argument-hint: "<SQL string | path/to/file.sql>"
allowed-tools: mcp__plugin_gosqlx_gosqlx__lint_sql Read Bash(gosqlx lint:*)
---

Lint this SQL with GoSQLX: $ARGUMENTS

If the argument is a path to an existing file, read it and use its contents; otherwise treat the argument as SQL text. If it is empty, ask for the SQL.

Call the `lint_sql` MCP tool. Group the violations by rule ID, show each offending line with its line/column, and give the fix; note which rules `gosqlx lint --auto-fix` can fix (L001, L002, L003, L007, L010). Use the `sql-linting` skill for rule explanations. If the MCP server is unavailable, run `gosqlx lint` via Bash. Do not modify any file unless asked.
