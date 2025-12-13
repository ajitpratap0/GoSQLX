# GoSQLX Error Codes Reference

**Version**: v1.6.0
**Last Updated**: December 2025

Comprehensive reference for all error codes in GoSQLX with examples and solutions.

## Table of Contents

- [Quick Reference](#quick-reference)
- [E1xxx - Tokenizer Errors](#e1xxx---tokenizer-errors)
  - [E1001 - Unexpected Character](#e1001---unexpected-character)
  - [E1002 - Unterminated String](#e1002---unterminated-string)
  - [E1003 - Invalid Number](#e1003---invalid-number)
  - [E1004 - Invalid Operator Sequence](#e1004---invalid-operator-sequence)
  - [E1005 - Invalid Identifier Format](#e1005---invalid-identifier-format)
  - [E1006 - Input Too Large](#e1006---input-too-large)
  - [E1007 - Token Limit Exceeded](#e1007---token-limit-exceeded)
  - [E1008 - Tokenizer Panic Recovered](#e1008---tokenizer-panic-recovered)
- [E2xxx - Parser Errors](#e2xxx---parser-errors)
  - [E2001 - Unexpected Token](#e2001---unexpected-token)
  - [E2002 - Expected Token](#e2002---expected-token)
  - [E2003 - Missing Clause](#e2003---missing-clause)
  - [E2004 - Invalid Syntax](#e2004---invalid-syntax)
  - [E2005 - Incomplete Statement](#e2005---incomplete-statement)
  - [E2006 - Invalid Expression](#e2006---invalid-expression)
  - [E2007 - Recursion Depth Limit Exceeded](#e2007---recursion-depth-limit-exceeded)
  - [E2008 - Unsupported Data Type](#e2008---unsupported-data-type)
  - [E2009 - Unsupported Constraint](#e2009---unsupported-constraint)
  - [E2010 - Unsupported JOIN Type](#e2010---unsupported-join-type)
  - [E2011 - Invalid CTE Syntax](#e2011---invalid-cte-syntax)
  - [E2012 - Invalid Set Operation](#e2012---invalid-set-operation)
- [E3xxx - Semantic Errors](#e3xxx---semantic-errors)
  - [E3001 - Undefined Table](#e3001---undefined-table)
  - [E3002 - Undefined Column](#e3002---undefined-column)
  - [E3003 - Type Mismatch](#e3003---type-mismatch)
  - [E3004 - Ambiguous Column](#e3004---ambiguous-column)
- [E4xxx - Unsupported Features](#e4xxx---unsupported-features)
  - [E4001 - Unsupported Feature](#e4001---unsupported-feature)
  - [E4002 - Unsupported Dialect](#e4002---unsupported-dialect)
- [Common SQL Patterns](#common-sql-patterns)
- [Linter Rules (L001-L010)](#linter-rules-l001-l010)
- [Security Scanner Findings](#security-scanner-findings)
- [Error Handling in Code](#error-handling-in-code)
- [Advanced Error Diagnostics (v1.6.0)](#advanced-error-diagnostics-v160)
- [LSP Integration for Real-Time Error Detection (v1.6.0)](#lsp-integration-for-real-time-error-detection-v160)
- [Performance Tips](#performance-tips)
- [Getting Help](#getting-help)
- [Changelog](#changelog)

---

## Quick Reference

| Code | Category | Description |
|------|----------|-------------|
| **E1xxx** | **Tokenizer Errors** | **Lexical analysis failures** |
| E1001 | Tokenizer | Unexpected character |
| E1002 | Tokenizer | Unterminated string literal |
| E1003 | Tokenizer | Invalid numeric literal |
| E1004 | Tokenizer | Invalid operator sequence |
| E1005 | Tokenizer | Invalid identifier format |
| E1006 | DoS Protection | Input exceeds maximum size limit (10MB) |
| E1007 | DoS Protection | Token count exceeds limit (1,000,000) |
| E1008 | DoS Protection | Tokenizer panic recovered |
| **E2xxx** | **Parser Errors** | **SQL syntax and parsing failures** |
| E2001 | Parser | Unexpected token |
| E2002 | Parser | Expected token not found |
| E2003 | Parser | Missing required clause |
| E2004 | Parser | General syntax error |
| E2005 | Parser | Incomplete statement |
| E2006 | Parser | Invalid expression |
| E2007 | DoS Protection | Expression nesting exceeds maximum depth (100) |
| E2008 | Parser | Unsupported data type |
| E2009 | Parser | Unsupported constraint type |
| E2010 | Parser | Unsupported JOIN type |
| E2011 | Parser | Invalid CTE (WITH clause) syntax |
| E2012 | Parser | Invalid set operation (UNION/EXCEPT/INTERSECT) |
| **E3xxx** | **Semantic Errors** | **Logical and type errors (requires semantic analysis)** |
| E3001 | Semantic | Undefined table |
| E3002 | Semantic | Undefined column |
| E3003 | Semantic | Type mismatch |
| E3004 | Semantic | Ambiguous column |
| **E4xxx** | **Unsupported Features** | **Features not yet implemented** |
| E4001 | Unsupported | Feature not supported |
| E4002 | Unsupported | Dialect not supported |

---

## E1xxx - Tokenizer Errors

### E1001 - Unexpected Character

Invalid or unsupported character in SQL input.

```sql
-- Wrong: Using bitwise operator
SELECT * FROM users WHERE name = 'John' & age > 18

-- Right: Use logical AND
SELECT * FROM users WHERE name = 'John' AND age > 18
```

**Common fixes:**
- Use `AND` instead of `&`, `OR` instead of `|`
- Quote identifiers with special characters: `"user-id"`

---

### E1002 - Unterminated String

String literal not properly closed.

```sql
-- Wrong: Missing closing quote
SELECT * FROM users WHERE name = 'John

-- Right: Add closing quote
SELECT * FROM users WHERE name = 'John'

-- Escape quotes within strings
SELECT * FROM users WHERE name = 'O''Brien'
```

---

### E1003 - Invalid Number

Numeric literal has invalid format.

```sql
-- Wrong: Multiple decimal points
SELECT * FROM products WHERE price > 19.99.5

-- Right: Valid decimal
SELECT * FROM products WHERE price > 19.99

-- Valid scientific notation
SELECT * FROM data WHERE value = 1.5e10
```

---

### E1004 - Invalid Operator Sequence

Invalid operator combination encountered.

```sql
-- Wrong: Double equals
SELECT * FROM users WHERE age >= = 18

-- Right: Single comparison
SELECT * FROM users WHERE age >= 18

-- Use correct operator
SELECT * FROM users WHERE name != 'John' OR name <> 'John'
```

---

### E1005 - Invalid Identifier Format

Identifier (table/column name) has invalid format.

```sql
-- Wrong: Identifier starts with number
SELECT * FROM 123users

-- Right: Quote the identifier
SELECT * FROM "123users"

-- Quote reserved keywords
SELECT "select" FROM "table"
```

---

### E1006 - Input Too Large

Input SQL exceeds maximum size (10MB).

```go
// Wrong: Parse entire large file at once
largeSQL, _ := os.ReadFile("huge_dump.sql")
ast, err := gosqlx.ParseBytes(largeSQL) // May fail with E1006

// Right: Split into smaller batches
batches := splitSQLIntoBatches(largeSQL, 5*1024*1024) // 5MB batches
for _, batch := range batches {
    ast, err := gosqlx.ParseBytes(batch)
    // Process each batch
}
```

---

### E1007 - Token Limit Exceeded

Token count exceeds maximum (1,000,000 tokens).

```go
// Wrong: Single massive INSERT
INSERT INTO logs VALUES (1, 'a'), (2, 'b'), ... // 100,000 rows

// Right: Batch into reasonable chunks
batchSize := 1000
for i := 0; i < len(data); i += batchSize {
    batch := data[i:min(i+batchSize, len(data))]
    // Generate and parse INSERT for this batch
}
```

---

### E1008 - Tokenizer Panic Recovered

Tokenizer encountered internal error.

```go
// Validate input encoding before parsing
if !utf8.Valid(sqlBytes) {
    return errors.New("invalid UTF-8 encoding")
}

// Sanitize input to remove control characters
sqlBytes = removeControlCharacters(sqlBytes)
ast, err := gosqlx.ParseBytes(sqlBytes)
```

---

## E2xxx - Parser Errors

### E2001 - Unexpected Token

Token doesn't fit SQL grammar at this position.

```sql
-- Wrong: Typo in FROM
SELECT * FORM users

-- Right: Correct spelling
SELECT * FROM users

-- Wrong: Missing comma
SELECT id name FROM users

-- Right: Add comma
SELECT id, name FROM users
```

---

### E2002 - Expected Token

Parser expected specific token but found something else.

```sql
-- Wrong: Missing FROM clause
SELECT * WHERE age > 18

-- Right: Add FROM clause
SELECT * FROM users WHERE age > 18

-- Ensure correct clause order
SELECT * FROM users WHERE age > 18
```

---

### E2003 - Missing Clause

Required SQL clause is missing.

```sql
-- Wrong: Missing INTO
INSERT users VALUES ('John', 25)

-- Right: Add INTO
INSERT INTO users VALUES ('John', 25)

-- Wrong: Missing SET in UPDATE
UPDATE users name = 'John'

-- Right: Add SET
UPDATE users SET name = 'John'
```

---

### E2004 - Invalid Syntax

General SQL syntax error.

```sql
-- Wrong: Duplicate WHERE
SELECT * FROM users WHERE WHERE age > 18

-- Right: Single WHERE clause
SELECT * FROM users WHERE age > 18
```

---

### E2005 - Incomplete Statement

SQL statement started but not completed.

```sql
-- Wrong: Incomplete WHERE
SELECT * FROM users WHERE

-- Right: Complete the condition
SELECT * FROM users WHERE age > 18

-- Wrong: Incomplete INSERT
INSERT INTO users (name, age) VALUES

-- Right: Provide values
INSERT INTO users (name, age) VALUES ('John', 25)
```

---

### E2006 - Invalid Expression

Expression has invalid syntax.

```sql
-- Wrong: Double comparison operator
SELECT * FROM users WHERE age > > 18

-- Right: Single operator
SELECT * FROM users WHERE age > 18

-- Wrong: Invalid function syntax
SELECT COUNT FROM users

-- Right: Proper function call
SELECT COUNT(*) FROM users
```

---

### E2007 - Recursion Depth Limit Exceeded

Expression nesting exceeds maximum depth (100 levels).

```sql
-- Wrong: Excessive nesting
SELECT * FROM users WHERE (((((((status = 'active'))))))))) -- 100+ levels

-- Right: Flatten the structure
SELECT * FROM users WHERE status = 'active'

-- Use CTEs instead of deep nesting
WITH level1 AS (
    SELECT * FROM base_table
),
level2 AS (
    SELECT * FROM level1 WHERE condition
)
SELECT * FROM level2
```

---

### E2008 - Unsupported Data Type

Data type not yet supported.

```sql
-- Wrong: Unsupported XML type
CREATE TABLE users (id INT, data XML)

-- Right: Use TEXT or VARCHAR
CREATE TABLE users (id INT, data TEXT)
```

---

### E2009 - Unsupported Constraint

Constraint type not supported.

```sql
-- May not be supported: Complex CHECK with function
CREATE TABLE users (
    id INT,
    CONSTRAINT chk_custom CHECK (custom_function(id) > 0)
)

-- Supported: Simple CHECK constraint
CREATE TABLE users (
    id INT,
    CONSTRAINT chk_id CHECK (id > 0)
)
```

---

### E2010 - Unsupported JOIN Type

JOIN type not supported by the parser.

**Note**: As of v1.6.0, LATERAL JOIN is fully supported.

```sql
-- SUPPORTED in v1.6.0: LATERAL JOIN
SELECT * FROM users,
LATERAL (SELECT * FROM orders WHERE user_id = users.id LIMIT 3) o;

SELECT * FROM users
LEFT JOIN LATERAL (SELECT * FROM orders WHERE user_id = users.id) o ON true;

-- Supported JOIN types (v1.6.0):
-- INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL JOIN
-- CROSS JOIN, NATURAL JOIN, LATERAL JOIN
-- LEFT JOIN LATERAL, INNER JOIN LATERAL, CROSS JOIN LATERAL

-- Unsupported: Proprietary JOIN extensions
-- Oracle (+) syntax, SQL Server APPLY, etc.
```

**Common fixes:**
- Use standard SQL JOIN syntax
- Replace proprietary syntax with ANSI SQL JOINs
- Use LATERAL JOIN for correlated subqueries (v1.6.0+)

---

### E2011 - Invalid CTE Syntax

CTE (WITH clause) syntax is invalid.

```sql
-- Wrong: Missing parentheses
WITH user_counts AS
    SELECT dept, COUNT(*) FROM employees GROUP BY dept
SELECT * FROM user_counts

-- Right: Add parentheses
WITH user_counts AS (
    SELECT dept, COUNT(*) FROM employees GROUP BY dept
)
SELECT * FROM user_counts

-- Proper recursive CTE with UNION
WITH RECURSIVE hierarchy AS (
    SELECT id, parent_id, 1 as level FROM nodes WHERE parent_id IS NULL
    UNION ALL
    SELECT n.id, n.parent_id, h.level + 1
    FROM nodes n
    JOIN hierarchy h ON n.parent_id = h.id
)
SELECT * FROM hierarchy
```

---

### E2012 - Invalid Set Operation

Set operation (UNION, INTERSECT, EXCEPT) has invalid syntax.

```sql
-- Wrong: Different column counts
SELECT id FROM users
UNION
SELECT id, name FROM orders

-- Right: Same column count
SELECT id, name FROM users
UNION
SELECT id, customer_name FROM orders

-- ORDER BY at end only
SELECT * FROM users
UNION
SELECT * FROM admins
ORDER BY name
```

---

## E3xxx - Semantic Errors

**Note:** Semantic errors require semantic analysis to be enabled.

### E3001 - Undefined Table

Table reference cannot be resolved.

```sql
SELECT * FROM nonexistent_table
```

---

### E3002 - Undefined Column

Column reference cannot be resolved.

```sql
SELECT nonexistent_column FROM users
```

---

### E3003 - Type Mismatch

Type incompatibility in expressions.

```sql
-- Wrong: String instead of number
SELECT * FROM users WHERE age > '18'

-- Right: Numeric value
SELECT * FROM users WHERE age > 18
```

---

### E3004 - Ambiguous Column

Column name could refer to multiple tables.

```sql
-- Wrong: Ambiguous column
SELECT id FROM users, orders WHERE id > 10

-- Right: Qualify column names
SELECT users.id FROM users, orders WHERE users.id > 10
```

---

## E4xxx - Unsupported Features

### E4001 - Unsupported Feature

SQL feature not yet implemented.

**Note:** GoSQLX is under active development. Check documentation for currently supported features.

---

### E4002 - Unsupported Dialect

SQL dialect-specific syntax not supported.

**Note:** GoSQLX supports standard SQL with extensions for PostgreSQL, MySQL, SQL Server, Oracle, and SQLite. Some dialect-specific features may not be available.

---

## Common SQL Patterns

### Window Functions (v1.6.0)

```sql
-- Wrong: Missing OVER clause
SELECT name, ROW_NUMBER() FROM employees

-- Right: Add OVER clause
SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees

-- Window frame with proper specification
SELECT SUM(amount) OVER (ORDER BY date ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales

-- Supported window functions (v1.6.0):
-- ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE()
-- LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE()
-- SUM(), AVG(), COUNT(), MIN(), MAX() with OVER clause
-- PARTITION BY, ORDER BY with NULLS FIRST/LAST
-- Frame specifications: ROWS, RANGE, GROUPS
```

### Common Table Expressions

```sql
-- Wrong: CTE without following statement
WITH user_counts AS (
    SELECT dept, COUNT(*) as cnt FROM employees GROUP BY dept
)

-- Right: Add SELECT statement
WITH user_counts AS (
    SELECT dept, COUNT(*) as cnt FROM employees GROUP BY dept
)
SELECT * FROM user_counts WHERE cnt > 5

-- Multiple CTEs need commas
WITH cte1 AS (SELECT * FROM users),
     cte2 AS (SELECT * FROM orders)
SELECT * FROM cte1
```

### JOIN Operations

```sql
-- Wrong: Missing ON clause
SELECT * FROM users JOIN orders

-- Right: Add ON clause
SELECT * FROM users JOIN orders ON users.id = orders.user_id

-- Or use USING clause
SELECT * FROM users JOIN orders USING (user_id)

-- LATERAL JOIN (v1.6.0)
SELECT * FROM users,
LATERAL (SELECT * FROM orders WHERE user_id = users.id LIMIT 3) o;
```

### PostgreSQL Extensions (v1.6.0)

```sql
-- DISTINCT ON - PostgreSQL-specific row selection
SELECT DISTINCT ON (dept_id) dept_id, name, salary
FROM employees ORDER BY dept_id, salary DESC;

-- FILTER Clause - Conditional aggregation (SQL:2003)
SELECT
    COUNT(*) FILTER (WHERE status = 'active') AS active_count,
    SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
FROM transactions;

-- RETURNING Clause - Return modified rows
INSERT INTO users (name, email) VALUES ('John', 'john@example.com')
RETURNING id, created_at;

UPDATE products SET price = price * 1.1 WHERE category = 'Electronics'
RETURNING id, price;

-- JSON/JSONB Operators
SELECT data->>'name' AS name FROM users;
SELECT * FROM products WHERE attributes @> '{"color": "red"}';
SELECT * FROM users WHERE profile ? 'email';

-- Aggregate ORDER BY
SELECT STRING_AGG(name, ', ' ORDER BY name) FROM users;
SELECT ARRAY_AGG(price ORDER BY price DESC) FROM products;
```

### SQL Standards Compliance (v1.6.0)

```sql
-- FETCH FIRST/NEXT (SQL:1999 F861, F862)
SELECT * FROM users ORDER BY created_at DESC
FETCH FIRST 10 ROWS ONLY;

SELECT * FROM products ORDER BY price
OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY;

-- FETCH with TIES (preserves ties in sort order)
SELECT * FROM users ORDER BY score DESC
FETCH FIRST 5 ROWS WITH TIES;

-- TRUNCATE TABLE (SQL:2008)
TRUNCATE TABLE temp_data;
TRUNCATE TABLE logs RESTART IDENTITY CASCADE;

-- GROUPING SETS, ROLLUP, CUBE (SQL:1999 T431)
SELECT region, product, SUM(sales)
FROM orders
GROUP BY GROUPING SETS ((region), (product), ());

SELECT year, quarter, SUM(revenue)
FROM sales
GROUP BY ROLLUP (year, quarter);

-- MERGE Statement (SQL:2003 F312)
MERGE INTO target t
USING source s ON t.id = s.id
WHEN MATCHED THEN UPDATE SET t.value = s.value
WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value);

-- MATERIALIZED CTE
WITH cte AS MATERIALIZED (
    SELECT * FROM large_table WHERE active = true
)
SELECT * FROM cte;
```

---

## Linter Rules (L001-L010)

While error codes (E1xxx-E4xxx) identify parsing and semantic errors, linter rules (L001-L010) identify style and quality issues. See [LINTING_RULES.md](LINTING_RULES.md) for complete details.

### Linter Rule Summary

| Rule | Name | Severity | Auto-Fix |
|------|------|----------|----------|
| L001 | Trailing Whitespace | Warning | Yes |
| L002 | Mixed Indentation | Error | Yes |
| L003 | Consecutive Blank Lines | Warning | Yes |
| L004 | Indentation Depth | Warning | No |
| L005 | Long Lines | Info | No |
| L006 | SELECT Column Alignment | Info | No |
| L007 | Keyword Case Consistency | Warning | Yes |
| L008 | Comma Placement | Info | No |
| L009 | Aliasing Consistency | Warning | No |
| L010 | Redundant Whitespace | Info | Yes |

### CLI Usage

```bash
# Lint SQL files with all rules
gosqlx lint query.sql

# Auto-fix linter violations
gosqlx lint --auto-fix query.sql

# Fail on warnings
gosqlx lint --fail-on-warn query.sql
```

---

## Security Scanner Findings

The security scanner detects SQL injection patterns and returns findings with severity levels. These are NOT error codes but security warnings.

### Finding Severity Levels

| Severity | Description |
|----------|-------------|
| CRITICAL | Definite injection pattern (e.g., OR 1=1 --) |
| HIGH | Likely injection (suspicious patterns) |
| MEDIUM | Potentially unsafe patterns (needs review) |
| LOW | Informational findings |

### Pattern Types Detected

1. **TAUTOLOGY**: Always-true conditions (1=1, 'a'='a')
2. **COMMENT_BYPASS**: Comment-based bypasses (--, /\*\*/, #)
3. **UNION_BASED**: UNION SELECT patterns, information_schema access
4. **STACKED_QUERY**: Destructive statements after semicolon
5. **TIME_BASED**: SLEEP(), WAITFOR DELAY, pg_sleep(), BENCHMARK()
6. **OUT_OF_BAND**: xp_cmdshell, LOAD_FILE(), UTL_HTTP
7. **DANGEROUS_FUNCTION**: EXEC(), sp_executesql, PREPARE FROM
8. **BOOLEAN_BASED**: Conditional logic exploitation

### CLI Usage

```bash
# Scan SQL for security issues
gosqlx analyze query.sql  # Includes security scanning

# Programmatic usage
scanner := security.NewScanner()
results := scanner.Scan(ast)
for _, finding := range results.Findings {
    fmt.Printf("%s: %s\n", finding.Severity, finding.Description)
}
```

See [pkg/sql/security/scanner.go](/Users/ajitpratapsingh/dev/GoSQLX/pkg/sql/security/scanner.go) for implementation details.

---

## Error Handling in Code

### Check Error Codes

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/errors"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

p := parser.NewParser()
ast, err := p.Parse(tokens)
if err != nil {
    // Check for specific error code
    if errors.IsCode(err, errors.ErrCodeExpectedToken) {
        fmt.Println("SQL syntax error detected")
    }

    // Get error code
    code := errors.GetCode(err)
    fmt.Printf("Error code: %s\n", code)
}
```

### Use Structured Error Information

```go
if parseErr, ok := err.(*errors.Error); ok {
    fmt.Printf("Error %s: %s\n", parseErr.Code, parseErr.Message)
    fmt.Printf("Location: Line %d, Column %d\n",
        parseErr.Location.Line, parseErr.Location.Column)

    if parseErr.Hint != "" {
        fmt.Printf("Hint: %s\n", parseErr.Hint)
    }

    // Error already includes formatted context
    fmt.Println(parseErr.Error())
}
```

---

## Advanced Error Diagnostics (v1.6.0)

### Error Context Formatting

GoSQLX provides rich error context with visual highlighting:

```
Error E2002 at line 3, column 10: expected FROM, got WHERE

  2 | SELECT id, name
  3 | WHERE age > 18
               ^
  4 | ORDER BY name

Hint: Add FROM clause before WHERE
Help: https://docs.gosqlx.dev/errors/E2002
```

### Intelligent Error Suggestions

The error system includes:
- **Typo detection**: Levenshtein distance-based suggestions
- **Context-aware hints**: Smart recommendations based on error type
- **Multi-language support**: Full Unicode error handling
- **Position tracking**: Precise line/column information

### Error Code Categories

Error codes follow a hierarchical structure:
- **E1xxx**: Lexical/tokenization errors (invalid characters, literals)
- **E2xxx**: Syntax/parsing errors (missing clauses, unexpected tokens)
- **E3xxx**: Semantic errors (undefined references, type mismatches)
- **E4xxx**: Unsupported features (not yet implemented)

## Performance Tips

1. **Cache error patterns**: Error suggestions use Levenshtein distance which can be cached
2. **Use error codes**: Check error codes instead of string matching (O(1) comparison)
3. **Structured logging**: Log error codes and locations for debugging
4. **Error recovery**: Use error codes to implement auto-fix logic
5. **LSP integration**: Use Language Server for real-time error detection (v1.6.0)

---

## LSP Integration for Real-Time Error Detection (v1.6.0)

GoSQLX includes a Language Server Protocol implementation for real-time error detection in your IDE.

### VSCode Extension

Install the official GoSQLX VSCode extension for:
- Real-time syntax error highlighting with error codes
- Hover tooltips showing error details and hints
- Quick fixes for common errors
- Inline diagnostics with line/column information

```bash
# Install from VSCode marketplace
ext install gosqlx.gosqlx-vscode

# Or start LSP server manually
gosqlx lsp
gosqlx lsp --log /tmp/lsp.log  # With debug logging
```

### LSP Features
- **textDocument/publishDiagnostics**: Real-time error reporting with codes
- **textDocument/hover**: Error details and documentation
- **textDocument/codeAction**: Quick fixes (add semicolon, uppercase keywords)
- **textDocument/completion**: Context-aware autocomplete
- **textDocument/formatting**: Automatic code formatting

See [LSP_GUIDE.md](LSP_GUIDE.md) for complete LSP documentation.

---

## Getting Help

- **Troubleshooting Guide**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **LSP Guide**: See [LSP_GUIDE.md](LSP_GUIDE.md) for IDE integration
- **GitHub Issues**: [github.com/ajitpratap0/GoSQLX/issues](https://github.com/ajitpratap0/GoSQLX/issues)
- **Help URLs**: Each error includes a help URL: `https://docs.gosqlx.dev/errors/<CODE>`

---

## Changelog

### v1.6.0 (December 2025)
- Updated E2010 with LATERAL JOIN support (now fully supported)
- Clarified E2008 data type support with PostgreSQL extensions
- Enhanced E2007 with recursion depth limit examples
- Updated all examples to reflect v1.6.0 SQL feature support
- Added references to LSP integration for real-time error diagnostics
- Improved error context extraction with better position tracking

### v1.4.0
- Added comprehensive error context formatting
- Added intelligent error suggestions
- Added Unicode support in error messages
- Added window function, CTE, and set operation error patterns

### v1.3.0
- Initial structured error system
- Basic error codes (E1xxx-E4xxx)
- Position tracking and hints

---

## Summary

This comprehensive error code reference covers all 26 error codes in GoSQLX v1.6.0:

- **8 Tokenizer Errors (E1001-E1008)**: Lexical analysis and DoS protection
- **12 Parser Errors (E2001-E2012)**: SQL syntax and parsing failures
- **4 Semantic Errors (E3001-E3004)**: Logical and type validation
- **2 Unsupported Feature Errors (E4001-E4002)**: Features not yet implemented

Additionally, GoSQLX provides:
- **10 Linter Rules (L001-L010)**: Code style and quality checks
- **8 Security Pattern Types**: SQL injection detection
- **LSP Integration**: Real-time error detection in IDEs
- **Intelligent Error Suggestions**: Context-aware hints and fixes

For the latest updates and contributions, visit [github.com/ajitpratap0/GoSQLX](https://github.com/ajitpratap0/GoSQLX).

---

**Last Updated**: December 2025
**Version**: v1.6.0
