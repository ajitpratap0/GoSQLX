---
name: sql-security-review
description: SQL injection review with GoSQLX - scan SQL text for injection patterns (tautologies, UNION attacks, stacked queries, comment bypasses, time-based and out-of-band probes, dangerous functions) and review application code that builds SQL strings (concatenation, f-strings, fmt.Sprintf, template literals), recommending parameterized queries. Use when the user asks whether SQL or database code is safe, about SQL injection, or to security-review queries or data-access code.
argument-hint: "[SQL string, .sql file, or source file that builds SQL]"
allowed-tools: mcp__plugin_gosqlx_gosqlx__security_scan mcp__plugin_gosqlx_gosqlx__validate_sql Read Grep Glob Bash(gosqlx analyze:*) Bash(gosqlx lint:*)
---

# SQL security review with GoSQLX

Input: `$ARGUMENTS` - a SQL string, a `.sql` file, or source code that constructs SQL.

## 1. Scan SQL text

Call `security_scan` (`mcp__plugin_gosqlx_gosqlx__security_scan`) with `{"sql": "..."}`. It returns `is_clean`, per-severity counts (`critical_count`, `high_count`, `medium_count`, `low_count`) and `findings[]`, each with `severity`, `pattern`, `description`, `risk` and `suggestion`. Pattern types: `TAUTOLOGY`, `COMMENT_BYPASS`, `STACKED_QUERY`, `UNION_BASED`, `UNION_INJECTION`, `UNION_GENERIC`, `TIME_BASED`, `BOOLEAN_BASED`, `OUT_OF_BAND`, `DANGEROUS_FUNCTION`.

The scanner inspects a finished SQL string. It catches injected payloads, not the vulnerable code path that lets them in.

## 2. Review code that builds SQL

Use Grep/Read to find where queries are assembled. Flag any user-influenced value that reaches the SQL text through:

- string concatenation or interpolation: `"... WHERE id = " + id`, Python f-strings / `%` / `.format()`, JS template literals, Go `fmt.Sprintf`, Java `String.format`, PHP `"$var"` in query strings;
- ORM raw-query escape hatches (`raw()`, `extra()`, `Sequelize.literal`, `knex.raw`, `db.Exec(fmt.Sprintf(...))`) fed with user input;
- dynamic identifiers (table, column, `ORDER BY` direction) taken from input.

For each finding give: file:line, the tainted source, why it is injectable, and a fix:

- **Values** -> placeholders/bind parameters (`?`, `$1`, `:name`, `@p1`) with the driver's parameter API.
- **Identifiers / sort direction** -> map input onto a hard-coded allowlist; never quote-escape by hand.
- **LIKE patterns** -> bind the pattern and escape `%`/`_` in user text.

To exercise the scanner on code findings, reconstruct the SQL with a hostile value (for example `' OR 1=1 --`) and run `security_scan` on it.

## 3. Report

Lead with CRITICAL/HIGH issues. Separate GoSQLX scanner findings from your own code-review findings. Do not claim code is safe just because `is_clean` is true for a sample query.

## Fallback when the MCP tools are unavailable

```sh
gosqlx analyze --security query.sql
gosqlx lint --security query.sql      # adds LIKE-injection, tautology and UNION checks to lint
echo "SELECT * FROM users WHERE id = 1 OR 1=1" | gosqlx analyze --security
```

Never run suspected injection payloads against a real database.
