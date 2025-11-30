# GoSQLX Error Codes Reference

Comprehensive reference for all error codes in GoSQLX with examples and solutions.

## Quick Reference

| Code | Category | Description |
|------|----------|-------------|
| E1001 | Tokenizer | Unexpected character |
| E1002 | Tokenizer | Unterminated string literal |
| E1003 | Tokenizer | Invalid numeric literal |
| E1004 | Tokenizer | Invalid operator sequence |
| E1005 | Tokenizer | Invalid identifier format |
| E1006 | DoS Protection | Input exceeds maximum size limit (10MB) |
| E1007 | DoS Protection | Token count exceeds limit (1,000,000) |
| E1008 | DoS Protection | Tokenizer panic recovered |
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
| E3001 | Semantic | Undefined table |
| E3002 | Semantic | Undefined column |
| E3003 | Semantic | Type mismatch |
| E3004 | Semantic | Ambiguous column |
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

JOIN type not supported.

```sql
-- Wrong: LATERAL JOIN (may not be supported)
SELECT * FROM users
LATERAL JOIN orders ON users.id = orders.user_id

-- Right: Use standard JOIN types
SELECT * FROM users
LEFT JOIN orders ON users.id = orders.user_id

-- Supported: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL
```

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

### Window Functions

```sql
-- Wrong: Missing OVER clause
SELECT name, ROW_NUMBER() FROM employees

-- Right: Add OVER clause
SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees

-- Window frame requires ORDER BY
SELECT SUM(amount) OVER (ORDER BY date ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales
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
```

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

## Performance Tips

1. **Cache error patterns**: Error suggestions use Levenshtein distance which can be cached
2. **Use error codes**: Check error codes instead of string matching
3. **Structured logging**: Log error codes and locations for debugging
4. **Error recovery**: Use error codes to implement auto-fix logic

---

## Getting Help

- **Troubleshooting Guide**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **GitHub Issues**: [github.com/ajitpratap0/GoSQLX/issues](https://github.com/ajitpratap0/GoSQLX/issues)
- **Help URLs**: Each error includes a help URL: `https://docs.gosqlx.dev/errors/<CODE>`

---

## Changelog

### v1.4.0
- Added comprehensive error context formatting
- Added intelligent error suggestions
- Added Unicode support in error messages
- Added window function, CTE, and set operation error patterns

### v1.3.0
- Initial structured error system
- Basic error codes (E1xxx-E4xxx)
- Position tracking and hints
