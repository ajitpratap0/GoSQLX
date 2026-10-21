---
name: sql-linting
description: Lint SQL with GoSQLX and explain its rules L001-L030 (whitespace, keyword case, comma placement, aliasing, plus safety, performance and naming rules), including which rules each entry point applies and which can be auto-fixed. Use when the user asks to lint SQL, enforce SQL style, explains a GoSQLX rule ID like L007 or L019, or sets up SQL linting in CI.
argument-hint: "[SQL string, .sql file, or rule ID like L016]"
allowed-tools: mcp__plugin_gosqlx_gosqlx__lint_sql Read Bash(gosqlx lint:*)
---

# SQL linting with GoSQLX

Input: `$ARGUMENTS` - SQL, a `.sql` file, or a rule ID to explain.

## Which rules run where

| Entry point | Rules applied |
|---|---|
| MCP `lint_sql` (`mcp__plugin_gosqlx_gosqlx__lint_sql`) | L001-L010 (style). Keyword case expected UPPER, trailing commas, max line 100 |
| `gosqlx lint` CLI | L001-L010; `--auto-fix` fixes L001, L002, L003, L007, L010 |
| `gosqlx.Lint()` Go library | All 30 rules, L001-L030 |

L011-L030 are not returned by `lint_sql` or the CLI. When you spot one of those patterns yourself, cite the rule ID as guidance and say it comes from the Go library's rule set.

## Rules

| ID | Rule | Severity | Auto-fix |
|---|---|---|---|
| L001 | Trailing whitespace | Warning | Yes |
| L002 | Mixed indentation (tabs and spaces) | Error | Yes |
| L003 | Consecutive blank lines | Warning | Yes |
| L004 | Indentation depth (excessive nesting) | Warning | No |
| L005 | Long lines | Info | No |
| L006 | Column alignment in SELECT lists | Info | No |
| L007 | Keyword case consistency | Warning | Yes |
| L008 | Comma placement (trailing vs leading) | Info | No |
| L009 | Aliasing consistency | Warning | No |
| L010 | Redundant whitespace | Info | Yes |
| L011 | DELETE without WHERE | Error | No |
| L012 | UPDATE without WHERE | Error | No |
| L013 | DROP without IF EXISTS | Warning | No |
| L014 | TRUNCATE TABLE | Warning | No |
| L015 | SELECT ... INTO OUTFILE / DUMPFILE | Error | No |
| L016 | SELECT * | Warning | No |
| L017 | Missing WHERE on full scan (no WHERE or LIMIT) | Warning | No |
| L018 | Leading wildcard LIKE (`'%x'`) | Warning | No |
| L019 | NOT IN with NULL risk (prefer NOT EXISTS) | Warning | No |
| L020 | Correlated subquery in SELECT list (N+1) | Warning | No |
| L021 | OR chain instead of IN | Warning | No |
| L022 | Function on indexed column in WHERE | Warning | No |
| L023 | Implicit cross join (comma joins) | Warning | No |
| L024 | Table alias required | Warning | No |
| L025 | Reserved keyword used as identifier | Warning | No |
| L026 | INSERT without explicit column list | Warning | No |
| L027 | UNION instead of UNION ALL | Warning | No |
| L028 | LIMIT without ORDER BY | Warning | No |
| L029 | Subquery that can be a JOIN | Warning | No |
| L030 | DISTINCT on many columns | Warning | No |

Full reference with examples: https://github.com/ajitpratap0/GoSQLX/blob/main/docs/LINTING_RULES.md

## Steps

1. Call `lint_sql` with `{"sql": "..."}`. Each violation has `rule`, `rule_name`, `severity`, `message`, `line`, `column` and `suggestion`.
2. Group violations by rule, show the offending line, and give the fix. For auto-fixable rules, mention `gosqlx lint --auto-fix`.
3. For a rule-ID question, explain the rule from the table above and show a before/after example.

## Fallback when the MCP tools are unavailable

```sh
gosqlx lint query.sql
gosqlx lint -r ./queries/            # recurse into a directory
gosqlx lint --auto-fix query.sql     # rewrites the file - only when asked
gosqlx lint --fail-on-warn query.sql # non-zero exit on warnings (CI)
gosqlx lint --max-length 120 query.sql
```
