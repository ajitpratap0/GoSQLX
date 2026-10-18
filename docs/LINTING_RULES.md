# SQL Linting Rules Reference

This document is the complete reference for the 30 built-in GoSQLX SQL linting rules (L001-L030). The rule IDs, names, descriptions, severities and auto-fix flags below come from the rule definitions in `pkg/linter/rules/`.

## Overview

GoSQLX ships 30 linting rules in six categories: whitespace, style, keywords, safety, performance and naming.

| Category | Rules | Count |
|----------|-------|-------|
| Whitespace | L001, L002, L003, L004, L005, L010 | 6 rules |
| Style | L006, L008, L009 | 3 rules |
| Keywords | L007 | 1 rule |
| Safety | L011, L012, L013, L014, L015 | 5 rules |
| Performance | L016, L017, L018, L019, L020, L021, L022, L023 | 8 rules |
| Naming | L024, L025, L026, L027, L028, L029, L030 | 7 rules |

5 of the 30 rules (L001, L002, L003, L007 and L010) support automatic fixes. The other 25 report violations and a suggestion only.

### Which rules run where

| Entry point | Rules that run |
|-------------|----------------|
| `gosqlx.Lint()` (Go library) | All 30 rules (L001-L030), enabled by default |
| `pkg/linter` | The rules you pass to `linter.New(...)`. All 30 rule constructors are exported from `pkg/linter/rules/*` |
| `gosqlx lint` (CLI), `gosqlx action` and the MCP `lint_sql` tool | The style rules L001-L010 |

The safety, performance and naming rules (L011-L030) are applied through the Go library. To enforce them in CI, call `gosqlx.Lint` from a Go test, as shown in [Lint SQL in CI](guides/lint-sql-in-ci.md).

---

## Rules Summary

| Rule | Name | Severity | Auto-Fix | Default (`gosqlx.Lint`) |
|------|------|----------|----------|-------------------------|
| [L001](#l001-trailing-whitespace) | Trailing Whitespace | Warning | Yes | Enabled |
| [L002](#l002-mixed-indentation) | Mixed Indentation | Error | Yes | Enabled |
| [L003](#l003-consecutive-blank-lines) | Consecutive Blank Lines | Warning | Yes | Enabled |
| [L004](#l004-indentation-depth) | Indentation Depth | Warning | No | Enabled |
| [L005](#l005-long-lines) | Long Lines | Info | No | Enabled |
| [L006](#l006-column-alignment) | Column Alignment | Info | No | Enabled |
| [L007](#l007-keyword-case-consistency) | Keyword Case Consistency | Warning | Yes | Enabled |
| [L008](#l008-comma-placement) | Comma Placement | Info | No | Enabled |
| [L009](#l009-aliasing-consistency) | Aliasing Consistency | Warning | No | Enabled |
| [L010](#l010-redundant-whitespace) | Redundant Whitespace | Info | Yes | Enabled |
| [L011](#l011-delete-without-where) | Delete Without WHERE | Error | No | Enabled |
| [L012](#l012-update-without-where) | Update Without WHERE | Error | No | Enabled |
| [L013](#l013-drop-without-if-exists) | Drop Without IF EXISTS | Warning | No | Enabled |
| [L014](#l014-truncate-table) | Truncate Table | Warning | No | Enabled |
| [L015](#l015-select-into-outfile) | Select Into Outfile | Error | No | Enabled |
| [L016](#l016-select-star) | Select Star | Warning | No | Enabled |
| [L017](#l017-missing-where-on-full-scan) | Missing WHERE on Full Scan | Warning | No | Enabled |
| [L018](#l018-leading-wildcard-like) | Leading Wildcard LIKE | Warning | No | Enabled |
| [L019](#l019-not-in-with-null-risk) | NOT IN With NULL Risk | Warning | No | Enabled |
| [L020](#l020-correlated-subquery-in-select) | Correlated Subquery in SELECT | Warning | No | Enabled |
| [L021](#l021-or-instead-of-in) | OR Instead of IN | Warning | No | Enabled |
| [L022](#l022-function-on-indexed-column) | Function on Indexed Column | Warning | No | Enabled |
| [L023](#l023-implicit-cross-join) | Implicit Cross Join | Warning | No | Enabled |
| [L024](#l024-table-alias-required) | Table Alias Required | Warning | No | Enabled |
| [L025](#l025-reserved-keyword-identifier) | Reserved Keyword Identifier | Warning | No | Enabled |
| [L026](#l026-implicit-column-list-in-insert) | Implicit Column List in INSERT | Warning | No | Enabled |
| [L027](#l027-union-instead-of-union-all) | UNION Instead of UNION ALL | Warning | No | Enabled |
| [L028](#l028-missing-order-by-with-limit) | Missing ORDER BY with LIMIT | Warning | No | Enabled |
| [L029](#l029-subquery-can-be-join) | Subquery Can Be JOIN | Warning | No | Enabled |
| [L030](#l030-distinct-on-many-columns) | Distinct on Many Columns | Warning | No | Enabled |

Severity and auto-fix values are the defaults declared by each rule. A [`.gosqlx.yml` configuration](#configuration) can override the severity or disable individual rules.

---

## Whitespace Rules

### L001: Trailing Whitespace

Detects and removes unnecessary whitespace at the end of lines.

**Severity**: Warning
**Auto-Fix**: Yes

#### Example

```sql
-- VIOLATION: Line has trailing spaces
SELECT * FROM users WHERE active = true
                                       ^-- Trailing whitespace

-- FIXED
SELECT * FROM users WHERE active = true
```

#### CLI Usage

```bash
gosqlx lint query.sql
gosqlx lint --auto-fix query.sql
```

---

### L002: Mixed Indentation

Detects inconsistent use of tabs and spaces for indentation.

**Severity**: Error
**Auto-Fix**: Yes (converts tabs to 4 spaces)

#### Example

```sql
-- VIOLATION: Mixed tabs and spaces
SELECT *
    FROM users  -- 4 spaces
	WHERE id = 1  -- Tab character (mixed!)

-- FIXED: All spaces
SELECT *
    FROM users
    WHERE id = 1
```

---

### L003: Consecutive Blank Lines

Prevents excessive consecutive blank lines.

**Severity**: Warning
**Auto-Fix**: Yes
**Default Max**: 1 consecutive blank line

#### Example

```sql
-- VIOLATION: Too many blank lines
SELECT * FROM users;


WHERE id = 1;  -- Two blank lines above

-- FIXED
SELECT * FROM users;

WHERE id = 1;
```

---

### L004: Indentation Depth

Detects excessively nested indentation.

**Severity**: Warning
**Auto-Fix**: No
**Default Max**: 4 levels

#### Example

```sql
-- VIOLATION: Depth exceeds maximum (max=4)
SELECT
    CASE
        WHEN condition1 THEN
            CASE
                WHEN nested THEN
                    CASE  -- Depth 5 - VIOLATION
```

**Suggestion**: Simplify the query or break into smaller parts.

---

### L005: Long Lines

Warns when SQL lines exceed maximum length.

**Severity**: Info
**Auto-Fix**: No
**Default Max**: 100 characters in the `gosqlx lint` CLI (120 in `gosqlx.Lint`)

#### Example

```sql
-- VIOLATION: Line exceeds the maximum length
SELECT user_id, first_name, last_name, email_address, phone_number, registration_date FROM users WHERE active = true;

-- RECOMMENDED: Split into multiple lines
SELECT
    user_id,
    first_name,
    last_name,
    email_address
FROM users
WHERE active = true;
```

---

### L010: Redundant Whitespace

Detects multiple consecutive spaces outside of indentation.

**Severity**: Info
**Auto-Fix**: Yes

#### Example

```sql
-- VIOLATION: Multiple spaces
SELECT  *  FROM  users  WHERE  id = 1
       ^     ^     ^     ^-- Double spaces

-- FIXED
SELECT * FROM users WHERE id = 1
```

---

## Style Rules

### L006: Column Alignment

Ensures columns in SELECT statements are consistently aligned.

**Severity**: Info
**Auto-Fix**: No

#### Example

```sql
-- VIOLATION: Misaligned columns
SELECT
    col1,
      col2,  -- Misaligned
    col3

-- CORRECT
SELECT
    col1,
    col2,
    col3
```

---

### L008: Comma Placement

Enforces consistent comma placement (trailing or leading style).

**Severity**: Info
**Auto-Fix**: No
**Default**: Trailing commas

#### Trailing Style (Default)

```sql
SELECT
    col1,
    col2,
    col3
FROM users;
```

#### Leading Style

```sql
SELECT
    col1
    , col2
    , col3
FROM users;
```

---

### L009: Aliasing Consistency

Ensures consistent use of table and column aliases.

**Severity**: Warning
**Auto-Fix**: No

#### Example

```sql
-- VIOLATION: Mixed aliasing
SELECT
    u.user_id,
    orders.order_id  -- No alias, but u has one
FROM users u
JOIN orders ON u.id = orders.user_id;

-- CORRECT: Consistent aliases
SELECT
    u.user_id,
    o.order_id
FROM users u
JOIN orders o ON u.id = o.user_id;
```

---

## Keyword Rules

### L007: Keyword Case Consistency

Enforces consistent case for SQL keywords.

**Severity**: Warning
**Auto-Fix**: Yes
**Default**: UPPERCASE

#### Example

```sql
-- VIOLATION: Mixed case
Select name From users Where id = 1;

-- FIXED (uppercase)
SELECT name FROM users WHERE id = 1;

-- FIXED (lowercase, if configured)
select name from users where id = 1;
```

#### Supported Keywords

SELECT, FROM, WHERE, AND, OR, NOT, IN, IS, NULL, LIKE, BETWEEN, EXISTS, CASE, WHEN, THEN, ELSE, END, AS, ON, JOIN, INNER, LEFT, RIGHT, FULL, OUTER, CROSS, NATURAL, GROUP, BY, HAVING, ORDER, ASC, DESC, LIMIT, OFFSET, UNION, ALL, EXCEPT, INTERSECT, INSERT, INTO, VALUES, UPDATE, SET, DELETE, CREATE, TABLE, INDEX, VIEW, DROP, ALTER, WITH, RECURSIVE, DISTINCT, OVER, PARTITION, MERGE, ROLLUP, CUBE, and more.

---

## Safety Rules

### L011: Delete Without WHERE

A `DELETE` statement has no `WHERE` clause and will remove every row in the table.

**Severity**: Error
**Auto-Fix**: No

```sql
-- VIOLATION
DELETE FROM orders;

-- FIXED
DELETE FROM orders WHERE status = 'cancelled';
```

---

### L012: Update Without WHERE

An `UPDATE` statement has no `WHERE` clause and will modify every row in the table.

**Severity**: Error
**Auto-Fix**: No

```sql
-- VIOLATION
UPDATE users SET active = false;

-- FIXED
UPDATE users SET active = false WHERE last_login < '2025-01-01';
```

---

### L013: Drop Without IF EXISTS

A `DROP` statement is missing `IF EXISTS`, so it fails when the object does not exist.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
DROP TABLE temp_results;

-- FIXED
DROP TABLE IF EXISTS temp_results;
```

---

### L014: Truncate Table

`TRUNCATE TABLE` is irreversible and bypasses row-level triggers.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
TRUNCATE TABLE audit_log;

-- Consider a scoped, reviewable alternative
DELETE FROM audit_log WHERE created_at < '2025-01-01';
```

---

### L015: Select Into Outfile

`SELECT ... INTO OUTFILE` and `INTO DUMPFILE` write query results to the database server's filesystem, which is a data exfiltration risk. The check is a case-insensitive text match, because this MySQL extension does not always produce a full AST node.

**Severity**: Error
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT * FROM users INTO OUTFILE '/tmp/users.csv';
```

---

## Performance Rules

### L016: Select Star

`SELECT *` fetches every column and prevents index-only scans.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT * FROM users WHERE id = 1;

-- FIXED
SELECT id, name, email FROM users WHERE id = 1;
```

---

### L017: Missing WHERE on Full Scan

A `SELECT` on a table without a `WHERE` or `LIMIT` clause may cause a full table scan. The rule applies at any nesting level, including subqueries and CTE bodies.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id, name FROM events;

-- FIXED
SELECT id, name FROM events WHERE created_at > '2026-01-01';
```

---

### L018: Leading Wildcard LIKE

A `LIKE` pattern that starts with a wildcard cannot use a B-tree index and forces a full table scan.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM products WHERE name LIKE '%widget';

-- FIXED (a prefix match can use an index)
SELECT id FROM products WHERE name LIKE 'widget%';
```

---

### L019: NOT IN With NULL Risk

`NOT IN (subquery)` returns no rows if the subquery produces any `NULL`.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM users WHERE id NOT IN (SELECT user_id FROM bans);

-- FIXED
SELECT id FROM users u
WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = u.id);
```

---

### L020: Correlated Subquery in SELECT

A subquery in the `SELECT` column list runs once per row (the N+1 problem).

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT u.id, (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) AS order_count
FROM users u;

-- FIXED
SELECT u.id, COUNT(o.id) AS order_count
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
GROUP BY u.id;
```

---

### L021: OR Instead of IN

Several equality conditions on the same column joined with `OR` should use `IN`.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM orders WHERE status = 'new' OR status = 'paid' OR status = 'shipped';

-- FIXED
SELECT id FROM orders WHERE status IN ('new', 'paid', 'shipped');
```

---

### L022: Function on Indexed Column

Applying a function to a column in `WHERE` prevents the database from using an index on that column.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM users WHERE LOWER(email) = 'a@example.com';

-- FIXED (compare the raw column, or add a functional index)
SELECT id FROM users WHERE email = 'a@example.com';
```

---

### L023: Implicit Cross Join

Comma-separated tables in `FROM` create an implicit cross join. Use an explicit `JOIN ... ON`.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT u.id, o.id FROM users u, orders o WHERE u.id = o.user_id;

-- FIXED
SELECT u.id, o.id FROM users u JOIN orders o ON u.id = o.user_id;
```

---

## Naming Rules

### L024: Table Alias Required

Tables in multi-table queries should have aliases so column references are unambiguous. The rule applies at any nesting level.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT users.id, orders.total FROM users JOIN orders ON users.id = orders.user_id;

-- FIXED
SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id;
```

---

### L025: Reserved Keyword Identifier

Using a reserved SQL keyword as a table name or alias in a `FROM` clause requires quoting and is confusing. The rule checks table names and aliases.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT "order".id FROM "order";

-- FIXED
SELECT o.id FROM orders o;
```

---

### L026: Implicit Column List in INSERT

An `INSERT` without an explicit column list is fragile and breaks when the table schema changes.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
INSERT INTO users VALUES (1, 'Ada', 'ada@example.com');

-- FIXED
INSERT INTO users (id, name, email) VALUES (1, 'Ada', 'ada@example.com');
```

---

### L027: UNION Instead of UNION ALL

`UNION` removes duplicates with an expensive sort. Prefer `UNION ALL` when duplicates are acceptable.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM archived_orders UNION SELECT id FROM orders;

-- FIXED (if duplicates are acceptable)
SELECT id FROM archived_orders UNION ALL SELECT id FROM orders;
```

---

### L028: Missing ORDER BY with LIMIT

`LIMIT` or `OFFSET` without `ORDER BY` returns non-deterministic rows, which makes pagination unreliable. The rule applies at any nesting level.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id, name FROM users LIMIT 10;

-- FIXED
SELECT id, name FROM users ORDER BY id LIMIT 10;
```

---

### L029: Subquery Can Be JOIN

An `EXISTS` or `IN` subquery in `WHERE` may be rewritable as a `JOIN` for better performance and readability.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);

-- Consider
SELECT DISTINCT u.id FROM users u JOIN orders o ON o.user_id = u.id;
```

---

### L030: Distinct on Many Columns

`DISTINCT` over many columns (5 or more) suggests a missing `GROUP BY` or a data quality issue, and forces a sort over every projected column. The rule applies at any nesting level.

**Severity**: Warning
**Auto-Fix**: No

```sql
-- VIOLATION
SELECT DISTINCT a, b, c, d, e FROM wide_table;
```

---

## CLI Usage

The `gosqlx lint` command runs the style rules L001-L010. See [Which rules run where](#which-rules-run-where).

### Basic Commands

```bash
# Lint a single file
gosqlx lint query.sql

# Lint multiple files
gosqlx lint query1.sql query2.sql

# Lint directory recursively
gosqlx lint -r ./queries/
```

### Auto-Fix

```bash
# Apply all available auto-fixes
gosqlx lint --auto-fix query.sql

# Auto-fix directory
gosqlx lint --auto-fix -r ./queries/
```

### Options

```bash
# Set max line length (L005)
gosqlx lint --max-length 120 query.sql

# Fail on warnings
gosqlx lint --fail-on-warn query.sql
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No violations (or info only) |
| 1 | Violations found (errors/warnings) |

---

## Configuration

The `pkg/linter/config` package loads a `.gosqlx.yml` file that controls which rules run, per-rule severity overrides, and ignore patterns. Rules that do not appear in the file keep their defaults.

```yaml
rules:
  L001:
    enabled: true
    severity: error
  L016:
    enabled: false    # allow SELECT *
ignore:
  - "migrations/*.sql"
  - "vendor/**"
default_severity: warning
```

Unknown rule IDs are reported as warnings and do not fail loading, so a config can reference rules from newer releases. See the [Configuration reference](CONFIGURATION.md) for the full file format.

---

## Programmatic API

```go
import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

// Lint with all 30 built-in rules
result, err := gosqlx.Lint("SELECT * FROM users")
if err != nil {
    log.Fatal(err)
}
for _, v := range result.Violations {
    fmt.Printf("[%s] %s: %s\n", v.Rule, v.RuleName, v.Message)
}
```

To choose the rules yourself, build a linter from the rule constructors in `pkg/linter/rules/*`:

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/linter"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

l := linter.New(
    whitespace.NewTrailingWhitespaceRule(),
    safety.NewDeleteWithoutWhereRule(),
    safety.NewUpdateWithoutWhereRule(),
)
result := l.LintString(sql, "query.sql")
fmt.Println(linter.FormatResult(result))
```

See the [linter package reference](api/linter.md) for the `Rule` interface and auto-fix.

---

## Integration Examples

### Pre-Commit Hook

```bash
#!/usr/bin/env bash
gosqlx lint --fail-on-warn *.sql
if [ $? -ne 0 ]; then
    echo "SQL linting failed. Fix violations and try again."
    exit 1
fi
```

### GitHub Actions

```yaml
name: SQL Linting
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
      - run: gosqlx lint --fail-on-warn *.sql
```

---

## Related Documentation

- [CLI Guide](CLI_GUIDE.md) - Complete CLI reference
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [API Reference](API_REFERENCE.md) - Full API documentation

