---
name: sql-dialects
description: Check whether SQL parses under a specific database dialect with GoSQLX (PostgreSQL, MySQL, SQL Server, Oracle, SQLite, Snowflake, generic; MariaDB and ClickHouse via the CLI) and explain dialect-specific syntax problems. Use when the user asks if SQL is valid for a particular database, is porting SQL between databases, or gets a syntax error that may be dialect-related.
argument-hint: "[dialect] [SQL string or .sql file]"
allowed-tools: mcp__plugin_gosqlx_gosqlx__validate_sql Read Bash(gosqlx validate:*) Bash(gosqlx transpile:*)
---

# Dialect validation with GoSQLX

Input: `$ARGUMENTS` - usually a dialect name and SQL (string or `.sql` path). If no dialect is given, infer it from the project (driver imports, connection strings, migration tooling) or ask.

## MCP tool

Call `validate_sql` (`mcp__plugin_gosqlx_gosqlx__validate_sql`) with `sql` and `dialect`. Use only values listed in the tool's `dialect` enum. Every server version accepts:

`generic`, `mysql`, `postgresql`, `sqlite`, `sqlserver`, `oracle`, `snowflake`

Map user wording onto them: Postgres/PG -> `postgresql`; MSSQL/T-SQL/Azure SQL -> `sqlserver`; PL/SQL -> `oracle`. The result is `{valid, error?, dialect?}`.

## CLI-only dialects

Newer server builds also list `mariadb` and `clickhouse`. If the connected server's enum does not include them, use the local CLI:

```sh
gosqlx validate --dialect mariadb query.sql
gosqlx validate --dialect clickhouse query.sql
gosqlx validate --list-dialects        # prints every name the CLI accepts
```

## Steps

1. Validate with the requested dialect. If it fails, also validate with `generic` (or a neighbouring dialect) to tell a real syntax error apart from a dialect-specific construct.
2. Explain the error at its line/column and name the construct involved (for example backtick vs double-quote identifiers, `LIMIT` vs `TOP`/`FETCH FIRST`, `ILIKE`, `::` casts, `QUALIFY`, `ON DUPLICATE KEY UPDATE` vs `ON CONFLICT`).
3. Suggest an equivalent for the target dialect. Separate GoSQLX's verdict from your own knowledge of the database.
4. A pass means GoSQLX parses it; it does not prove the target database accepts every function or type. Say so when it matters.

For conversion, the CLI has `gosqlx transpile --from <d> --to <d>`; it currently supports mysql -> postgres, postgres -> mysql and postgres -> sqlite.
