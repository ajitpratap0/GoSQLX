# SQL Linting Rules Reference

**Version**: v1.6.0
**Last Updated**: December 2025

This document provides a complete reference for all GoSQLX SQL linting rules (L001-L010).

## Overview

GoSQLX includes 10 linting rules covering whitespace, style, and keyword consistency.

| Category | Rules | Count |
|----------|-------|-------|
| Whitespace | L001, L002, L003, L004, L005, L010 | 6 rules |
| Style | L006, L008, L009 | 3 rules |
| Keywords | L007 | 1 rule |

---

## Rules Summary

| Rule | Name | Severity | Auto-Fix | Default |
|------|------|----------|----------|---------|
| [L001](#l001-trailing-whitespace) | Trailing Whitespace | Warning | Yes | Enabled |
| [L002](#l002-mixed-indentation) | Mixed Indentation | Error | Yes | Enabled |
| [L003](#l003-consecutive-blank-lines) | Consecutive Blank Lines | Warning | Yes | Enabled |
| [L004](#l004-indentation-depth) | Indentation Depth | Warning | No | Enabled |
| [L005](#l005-long-lines) | Long Lines | Info | No | Enabled |
| [L006](#l006-select-column-alignment) | SELECT Column Alignment | Info | No | Enabled |
| [L007](#l007-keyword-case-consistency) | Keyword Case Consistency | Warning | Yes | Enabled |
| [L008](#l008-comma-placement) | Comma Placement | Info | No | Enabled |
| [L009](#l009-aliasing-consistency) | Aliasing Consistency | Warning | No | Enabled |
| [L010](#l010-redundant-whitespace) | Redundant Whitespace | Info | Yes | Enabled |

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
**Default Max**: 100 characters

#### Example

```sql
-- VIOLATION: Line exceeds 100 characters
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

### L006: SELECT Column Alignment

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

## CLI Usage

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

### .gosqlx.yml

```yaml
linter:
  rules:
    L001:
      enabled: true
    L002:
      enabled: true
    L003:
      enabled: true
      max-consecutive: 1
    L004:
      enabled: true
      max-depth: 4
    L005:
      enabled: true
      max-length: 100
    L006:
      enabled: true
    L007:
      enabled: true
      case: uppercase  # or "lowercase"
    L008:
      enabled: true
      style: trailing  # or "leading"
    L009:
      enabled: true
    L010:
      enabled: true
```

### Example Configurations

**Strict (all rules)**:
```yaml
linter:
  rules:
    L001: enabled
    L002: enabled
    L003: enabled
    L004: enabled
    L005: enabled
    L006: enabled
    L007: enabled
    L008: enabled
    L009: enabled
    L010: enabled
```

**Lenient (critical only)**:
```yaml
linter:
  rules:
    L002: enabled  # Mixed indentation (error)
    L007: enabled  # Keyword case (warning)
```

---

## Programmatic API

```go
import "github.com/ajitpratap0/GoSQLX/pkg/linter"

// Create linter with default rules
l := linter.New()

// Lint SQL string
result := l.LintString(sql, "query.sql")

// Display results
fmt.Println(linter.FormatResult(result))

// Apply auto-fixes
for _, rule := range l.Rules() {
    if rule.CanAutoFix() {
        fixed, err := rule.Fix(content, result.Violations)
    }
}
```

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
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - run: go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
      - run: gosqlx lint --fail-on-warn *.sql
```

---

## Related Documentation

- [CLI Guide](CLI_GUIDE.md) - Complete CLI reference
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [API Reference](API_REFERENCE.md) - Full API documentation

---

**Last Updated**: December 2025
**Version**: v1.6.0
