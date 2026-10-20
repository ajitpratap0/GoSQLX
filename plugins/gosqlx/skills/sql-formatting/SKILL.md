---
name: sql-formatting
description: Format or pretty-print SQL with GoSQLX - consistent indentation, keyword casing and optional trailing semicolon. Use when the user asks to format, beautify, pretty-print, reindent or clean up SQL, or to make a .sql file consistent.
argument-hint: "[SQL string or path to .sql file]"
allowed-tools: mcp__plugin_gosqlx_gosqlx__format_sql mcp__plugin_gosqlx_gosqlx__validate_sql Read Bash(gosqlx format:*)
---

# SQL formatting with GoSQLX

Input: `$ARGUMENTS` - a SQL string or a path to a `.sql` file.

## Steps

1. Get the SQL (read the file if a path was given).
2. Call `format_sql` (`mcp__plugin_gosqlx_gosqlx__format_sql`) with:
   - `sql` (required)
   - `indent_size` - default 2. `0` puts each statement on one line. Clauses always start at column 0; larger values only indent nested blocks such as CREATE TABLE column lists
   - `uppercase_keywords` - `true` upper-cases all keywords (`AND`, `IN`, `CASE`, ...) but not data type names such as `int`. The default `false` still upper-cases clause keywords (`SELECT`, `FROM`, `WHERE`, ...) and leaves others such as `and`/`or` as written; the MCP tool cannot lowercase keywords
   - `add_semicolon` - default `false`
3. If formatting fails, the SQL probably does not parse: call `validate_sql` and report the error instead of guessing a fix.
4. Show the formatted SQL in a fenced `sql` block. When the input was a file, write the result back only if the user asked you to change the file; otherwise show it.

Formatting is whitespace and keyword-case only - it must not change meaning. If the output appears to drop or alter anything (comments, hints, dialect syntax), say so and keep the original.

## Fallback when the MCP tools are unavailable

```sh
gosqlx format query.sql                 # print formatted SQL (keywords uppercased by default)
gosqlx format --indent 4 query.sql
gosqlx format --uppercase=false query.sql  # lowercase clause keywords (do not use --no-uppercase: it currently uppercases)
gosqlx format --check query.sql         # exit non-zero if the file needs formatting
gosqlx format -i query.sql              # rewrite in place - only when asked
echo "select a from b" | gosqlx format
```

Both upper-case clause keywords by default. For lowercase keywords use the CLI with `--uppercase=false`.
