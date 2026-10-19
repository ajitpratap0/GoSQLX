---
description: Format a SQL string or .sql file with GoSQLX
argument-hint: "<SQL string | path/to/file.sql>"
allowed-tools: mcp__plugin_gosqlx_gosqlx__format_sql mcp__plugin_gosqlx_gosqlx__validate_sql Read Bash(gosqlx format:*)
---

Format this SQL with GoSQLX: $ARGUMENTS

If the argument is a path to an existing file, read it and use its contents; otherwise treat the argument as SQL text. If it is empty, ask for the SQL.

Call the `format_sql` MCP tool (2-space indent; set `uppercase_keywords` to true unless the input clearly uses lowercase keywords). Show the result in a `sql` code block. For a file, ask before overwriting it. If formatting fails, run `validate_sql` and report the syntax error. If the MCP server is unavailable, use `gosqlx format` via Bash (it prints to stdout; do not pass `-i` unless the user asked to edit the file).
