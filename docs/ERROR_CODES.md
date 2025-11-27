# GoSQLX Error Codes Reference

This document provides a comprehensive reference for all error codes in GoSQLX with detailed examples, common causes, and solutions.

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

## Error Code Categories

### E1xxx - Tokenizer Errors (Lexical Analysis)

These errors occur during the tokenization phase when GoSQLX converts SQL text into tokens.

#### E1001 - Unexpected Character

**When it occurs**: An unexpected or invalid character is found in the SQL input.

**Example**:
```sql
SELECT * FROM users WHERE name = 'John' & age > 18
                                        ^
```

**Error message**:
```
Error E1001 at line 1, column 39: unexpected character '&'
  1 | SELECT * FROM users WHERE name = 'John' & age > 18
                                              ^
Hint: Remove or escape the character '&'
Help: https://docs.gosqlx.dev/errors/E1001
```

**Common causes**:
- Using unsupported operators (use `AND` instead of `&`, `OR` instead of `|`)
- Special characters in identifiers without proper quoting
- Copy-paste errors introducing non-SQL characters
- Hidden Unicode characters

**Solutions**:
```sql
-- Wrong: Using bitwise operator
SELECT * FROM users WHERE name = 'John' & age > 18

-- Right: Use logical AND operator
SELECT * FROM users WHERE name = 'John' AND age > 18

-- Wrong: Special characters in identifier
SELECT user-id FROM accounts

-- Right: Quote the identifier
SELECT "user-id" FROM accounts
```

---

#### E1002 - Unterminated String

**When it occurs**: A string literal is not properly closed with a matching quote.

**Example**:
```sql
SELECT * FROM users WHERE name = 'John
                                 ^
```

**Error message**:
```
Error E1002 at line 1, column 34: unterminated string literal
  1 | SELECT * FROM users WHERE name = 'John
                                       ^
Hint: Make sure all string literals are properly closed with matching quotes
```

**Common causes**:
- Missing closing quote
- Unescaped quotes within strings
- Multiline strings without proper formatting
- Wrong quote type (mixing ' and ")

**Solutions**:
```sql
-- Wrong: Missing closing quote
SELECT * FROM users WHERE name = 'John

-- Right: Add closing quote
SELECT * FROM users WHERE name = 'John'

-- Wrong: Unescaped quote
SELECT * FROM users WHERE name = 'O'Brien'

-- Right: Escape the quote
SELECT * FROM users WHERE name = 'O''Brien'
```

---

#### E1003 - Invalid Number

**When it occurs**: A numeric literal has invalid format.

**Example**:
```sql
SELECT * FROM products WHERE price > 19.99.5
                                     ^^^^^^^
```

**Error message**:
```
Error E1003 at line 1, column 37: invalid numeric literal: '19.99.5'
  1 | SELECT * FROM products WHERE price > 19.99.5
                                           ^^^^^^^
Hint: Check the numeric format (e.g., 123, 123.45, 1.23e10)
```

**Common causes**:
- Multiple decimal points
- Invalid scientific notation
- Non-numeric characters in numbers
- Trailing/leading decimals without digits

**Solutions**:
```sql
-- Wrong: Multiple decimal points
SELECT * FROM products WHERE price > 19.99.5

-- Right: Valid decimal
SELECT * FROM products WHERE price > 19.99

-- Wrong: Invalid scientific notation
SELECT * FROM data WHERE value = 1.5e

-- Right: Valid scientific notation
SELECT * FROM data WHERE value = 1.5e10
```

---

#### E1004 - Invalid Operator Sequence

**When it occurs**: An invalid operator sequence is encountered in the SQL input.

**Example**:
```sql
SELECT * FROM users WHERE age >= = 18
                              ^^^^
```

**Error message**:
```
Error E1004 at line 1, column 31: invalid operator sequence '>=='
  1 | SELECT * FROM users WHERE age >= = 18
                                    ^^^^
Hint: Check operator syntax (valid operators: =, !=, <, >, <=, >=, <>, ||, etc.)
```

**Common causes**:
- Duplicate operator characters
- Invalid operator combinations
- Typos in comparison operators
- Mixing operators from different SQL dialects

**Solutions**:
```sql
-- Wrong: Double equals
SELECT * FROM users WHERE age >= = 18

-- Right: Single comparison
SELECT * FROM users WHERE age >= 18

-- Wrong: Invalid combination
SELECT * FROM users WHERE name =! 'John'

-- Right: Use correct operator
SELECT * FROM users WHERE name != 'John' OR name <> 'John'
```

---

#### E1005 - Invalid Identifier Format

**When it occurs**: An identifier (table name, column name, etc.) has invalid format.

**Example**:
```sql
SELECT * FROM 123users
              ^^^^^^^^
```

**Error message**:
```
Error E1005 at line 1, column 15: invalid identifier format '123users'
  1 | SELECT * FROM 123users
                    ^^^^^^^^
Hint: Identifiers cannot start with digits. Use quotes for special names: "123users"
```

**Common causes**:
- Identifiers starting with numbers
- Using reserved keywords as unquoted identifiers
- Special characters in identifiers without proper quoting
- Invalid Unicode characters in identifiers

**Solutions**:
```sql
-- Wrong: Identifier starts with number
SELECT * FROM 123users

-- Right: Quote the identifier
SELECT * FROM "123users"

-- Wrong: Reserved keyword as identifier
SELECT select FROM table

-- Right: Quote reserved keywords
SELECT "select" FROM "table"

-- Wrong: Special characters unquoted
SELECT * FROM user-table

-- Right: Quote identifiers with special characters
SELECT * FROM "user-table"
```

---

#### E1006 - Input Too Large

**When it occurs**: Input SQL exceeds the maximum allowed size (10MB).

**Example**:
```sql
-- Attempting to parse a 15MB SQL file
```

**Error message**:
```
Error E1006: input exceeds maximum size limit of 10485760 bytes (received 15728640 bytes)
Hint: Split large SQL files into smaller batches or increase the size limit if appropriate
```

**Common causes**:
- Very large SQL dump files
- Programmatically generated SQL with millions of INSERT statements
- Malicious input attempting denial-of-service attack
- Concatenated SQL files without proper splitting

**Solutions**:
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

#### E1007 - Token Limit Exceeded

**When it occurs**: The number of tokens exceeds the maximum allowed (1,000,000 tokens).

**Example**:
```sql
-- SQL with hundreds of thousands of columns or values
INSERT INTO logs VALUES (...), (...), (...) -- repeated 500,000 times
```

**Error message**:
```
Error E1007: token count exceeds limit of 1000000 tokens
Hint: Break down large batch operations into smaller chunks
```

**Common causes**:
- Massive batch INSERT statements
- Extremely complex queries with thousands of JOINs or subqueries
- Code generation gone wrong
- DoS attack attempts

**Solutions**:
```go
// Wrong: Single massive INSERT
INSERT INTO logs VALUES (1, 'a'), (2, 'b'), ... // 100,000 rows

// Right: Batch into reasonable chunks
batchSize := 1000
for i := 0; i < len(data); i += batchSize {
    batch := data[i:min(i+batchSize, len(data))]
    // Generate INSERT for this batch
    // Parse and execute
}
```

---

#### E1008 - Tokenizer Panic Recovered

**When it occurs**: The tokenizer encountered an internal error and recovered from a panic.

**Example**:
```sql
-- Malformed input that triggers internal tokenizer error
SELECT * FROM users WHERE id = \x00\x00\x00
```

**Error message**:
```
Error E1008: tokenizer panic recovered: runtime error
Hint: The input may contain malformed or malicious content
```

**Common causes**:
- Binary data mixed with SQL text
- Corrupted file encoding
- Null bytes or other control characters in input
- Internal tokenizer bugs (please report these!)

**Solutions**:
```go
// Validate input encoding before parsing
if !utf8.Valid(sqlBytes) {
    return errors.New("invalid UTF-8 encoding")
}

// Sanitize input to remove control characters
sqlBytes = removeControlCharacters(sqlBytes)

// Then parse
ast, err := gosqlx.ParseBytes(sqlBytes)
```

---

### E2xxx - Parser Errors (Syntax Analysis)

These errors occur during parsing when GoSQLX validates SQL grammar and structure.

#### E2001 - Unexpected Token

**When it occurs**: The parser encounters a token that doesn't fit the SQL grammar at this position.

**Example**:
```sql
SELECT * FORM users
         ^^^^
```

**Error message**:
```
Error E2001 at line 1, column 10: unexpected token: IDENT ('FORM')
  1 | SELECT * FORM users
               ^^^^
Hint: Did you mean 'FROM'?
Help: https://docs.gosqlx.dev/errors/E2001
```

**Common causes**:
- Typos in SQL keywords
- Missing or extra tokens
- Incorrect SQL syntax
- Wrong keyword order

**Solutions**:
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

#### E2002 - Expected Token

**When it occurs**: The parser expected a specific token but found something else.

**Example**:
```sql
SELECT * WHERE age > 18
         ^^^^^
```

**Error message**:
```
Error E2002 at line 1, column 10: expected FROM, got WHERE
  1 | SELECT * WHERE age > 18
               ^^^^^
Hint: Add the required 'FROM' clause to complete this statement
```

**Common causes**:
- Missing required keywords
- Incorrect clause order
- Omitted table name or other required elements

**Solutions**:
```sql
-- Wrong: Missing FROM clause
SELECT * WHERE age > 18

-- Right: Add FROM clause
SELECT * FROM users WHERE age > 18

-- Wrong: Wrong order
SELECT * WHERE age > 18 FROM users

-- Right: Correct order
SELECT * FROM users WHERE age > 18
```

---

#### E2003 - Missing Clause

**When it occurs**: A required SQL clause is missing from the statement.

**Example**:
```sql
INSERT users VALUES ('John', 25)
       ^^^^^
```

**Error message**:
```
Error E2003 at line 1, column 8: missing required INTO clause
  1 | INSERT users VALUES ('John', 25)
           ^^^^^
Hint: Add the required 'INTO' clause to complete this statement
```

**Common causes**:
- Forgetting required keywords (INTO, FROM, SET)
- Incomplete statement structure
- Misunderstanding SQL syntax requirements

**Solutions**:
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

#### E2004 - Invalid Syntax

**When it occurs**: General SQL syntax error that doesn't fit other specific categories.

**Example**:
```sql
SELECT * FROM users WHERE WHERE age > 18
                          ^^^^^
```

**Error message**:
```
Error E2004 at line 1, column 27: invalid syntax: duplicate WHERE clause
  1 | SELECT * FROM users WHERE WHERE age > 18
                                ^^^^^
Hint: Check SQL syntax for duplicate or misplaced keywords
```

**Common causes**:
- Duplicate SQL keywords
- Keywords in wrong positions
- Malformed SQL structure
- Missing or extra punctuation

**Solutions**:
```sql
-- Wrong: Duplicate WHERE
SELECT * FROM users WHERE WHERE age > 18

-- Right: Single WHERE clause
SELECT * FROM users WHERE age > 18

-- Wrong: Misplaced keyword
SELECT FROM users * WHERE age > 18

-- Right: Correct keyword order
SELECT * FROM users WHERE age > 18
```

---

#### E2005 - Incomplete Statement

**When it occurs**: A SQL statement is started but not completed.

**Example**:
```sql
SELECT * FROM users WHERE
                          ^
```

**Error message**:
```
Error E2005 at line 1, column 27: incomplete statement: expected expression after WHERE
  1 | SELECT * FROM users WHERE
                                ^
Hint: Complete the WHERE clause with a condition
```

**Common causes**:
- Incomplete WHERE conditions
- Missing VALUES in INSERT
- Incomplete subqueries
- Truncated SQL statements

**Solutions**:
```sql
-- Wrong: Incomplete WHERE
SELECT * FROM users WHERE

-- Right: Complete the condition
SELECT * FROM users WHERE age > 18

-- Wrong: Incomplete INSERT
INSERT INTO users (name, age) VALUES

-- Right: Provide values
INSERT INTO users (name, age) VALUES ('John', 25)

-- Wrong: Incomplete subquery
SELECT * FROM (SELECT * FROM

-- Right: Complete subquery
SELECT * FROM (SELECT * FROM users) AS u
```

---

#### E2006 - Invalid Expression

**When it occurs**: An expression has invalid syntax or structure.

**Example**:
```sql
SELECT * FROM users WHERE age > > 18
                                ^^
```

**Error message**:
```
Error E2006 at line 1, column 33: invalid expression: unexpected operator '>'
  1 | SELECT * FROM users WHERE age > > 18
                                      ^^
Hint: Check expression syntax and operator usage
```

**Common causes**:
- Invalid operator sequences in expressions
- Malformed function calls
- Missing operands
- Invalid comparison syntax

**Solutions**:
```sql
-- Wrong: Double comparison operator
SELECT * FROM users WHERE age > > 18

-- Right: Single operator
SELECT * FROM users WHERE age > 18

-- Wrong: Missing operand
SELECT * FROM users WHERE age >

-- Right: Complete expression
SELECT * FROM users WHERE age > 18

-- Wrong: Invalid function syntax
SELECT COUNT FROM users

-- Right: Proper function call
SELECT COUNT(*) FROM users
```

---

#### E2007 - Recursion Depth Limit Exceeded

**When it occurs**: Expression nesting exceeds the maximum allowed depth (100 levels).

**Example**:
```sql
-- Deeply nested subqueries or expressions
SELECT * FROM (
    SELECT * FROM (
        SELECT * FROM (
            -- ... 100+ levels deep
        )
    )
)
```

**Error message**:
```
Error E2007: expression nesting exceeds maximum depth of 100
Hint: Simplify the query by reducing nesting levels or breaking it into multiple statements
```

**Common causes**:
- Programmatically generated queries with excessive nesting
- Recursive query generation without depth limits
- DoS attack attempts with deeply nested structures
- Overly complex WHERE clauses with many nested conditions

**Solutions**:
```sql
-- Wrong: Excessive nesting
SELECT * FROM users WHERE (((((((status = 'active'))))))))) -- 100+ levels

-- Right: Flatten the structure
SELECT * FROM users WHERE status = 'active'

-- Wrong: Deeply nested subqueries
SELECT * FROM (
    SELECT * FROM (
        SELECT * FROM (
            -- Many levels deep
        )
    )
)

-- Right: Use CTEs to flatten
WITH level1 AS (
    SELECT * FROM base_table
),
level2 AS (
    SELECT * FROM level1 WHERE condition
)
SELECT * FROM level2
```

**Code example for generated queries**:
```go
// Wrong: No depth limit checking
func buildNestedQuery(depth int) string {
    if depth == 0 {
        return "SELECT * FROM base"
    }
    return fmt.Sprintf("SELECT * FROM (%s)", buildNestedQuery(depth-1))
}

// Right: Enforce depth limits
func buildNestedQuery(depth int, maxDepth int) (string, error) {
    if depth > maxDepth {
        return "", errors.New("query depth exceeds limit")
    }
    if depth == 0 {
        return "SELECT * FROM base", nil
    }
    inner, err := buildNestedQuery(depth-1, maxDepth)
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("SELECT * FROM (%s)", inner), nil
}
```

---

#### E2008 - Unsupported Data Type

**When it occurs**: A data type is used that GoSQLX does not currently support.

**Example**:
```sql
CREATE TABLE users (id INT, data XML)
                                 ^^^
```

**Error message**:
```
Error E2008 at line 1, column 33: unsupported data type 'XML'
  1 | CREATE TABLE users (id INT, data XML)
                                      ^^^
Hint: This data type is not yet supported. Supported types include: INT, VARCHAR, TEXT, TIMESTAMP, etc.
```

**Common causes**:
- Using database-specific types not yet implemented
- Typos in data type names
- Using deprecated or non-standard types
- Advanced types like XML, JSON (support varies)

**Solutions**:
```sql
-- Wrong: Unsupported XML type
CREATE TABLE users (id INT, data XML)

-- Right: Use TEXT or VARCHAR for structured data
CREATE TABLE users (id INT, data TEXT)

-- Wrong: Database-specific type
CREATE TABLE logs (id INT, data HSTORE)

-- Right: Use standard types
CREATE TABLE logs (id INT, data JSONB)
```

---

#### E2009 - Unsupported Constraint

**When it occurs**: A constraint type is used that GoSQLX does not currently support.

**Example**:
```sql
CREATE TABLE users (
    id INT,
    CONSTRAINT chk_custom CHECK (custom_function(id) > 0)
)
```

**Error message**:
```
Error E2009 at line 3, column 35: unsupported constraint type with custom function
  3 |     CONSTRAINT chk_custom CHECK (custom_function(id) > 0)
                                        ^^^^^^^^^^^^^
Hint: Complex CHECK constraints with custom functions may not be supported
```

**Common causes**:
- Complex CHECK constraints with functions
- Database-specific constraint syntax
- Advanced constraint features
- Trigger-based constraints

**Solutions**:
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

-- Supported: Standard constraints
CREATE TABLE users (
    id INT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL
)
```

---

#### E2010 - Unsupported JOIN Type

**When it occurs**: A JOIN type is used that GoSQLX does not currently support.

**Example**:
```sql
SELECT * FROM users
LATERAL JOIN orders ON users.id = orders.user_id
^^^^^^^
```

**Error message**:
```
Error E2010 at line 2, column 1: unsupported JOIN type 'LATERAL'
  2 | LATERAL JOIN orders ON users.id = orders.user_id
      ^^^^^^^
Hint: Supported JOIN types: INNER, LEFT, RIGHT, FULL, CROSS, NATURAL
```

**Common causes**:
- Using advanced JOIN types (LATERAL, APPLY)
- Database-specific JOIN syntax
- Typos in JOIN keywords

**Solutions**:
```sql
-- Wrong: LATERAL JOIN (may not be supported)
SELECT * FROM users
LATERAL JOIN orders ON users.id = orders.user_id

-- Right: Use standard JOIN types
SELECT * FROM users
LEFT JOIN orders ON users.id = orders.user_id

-- Supported: Standard JOIN types
SELECT * FROM users u
INNER JOIN orders o ON u.id = o.user_id
LEFT JOIN products p ON o.product_id = p.id
CROSS JOIN categories c
NATURAL JOIN preferences
```

---

#### E2011 - Invalid CTE Syntax

**When it occurs**: The syntax of a Common Table Expression (WITH clause) is invalid.

**Example**:
```sql
WITH user_counts AS
    SELECT dept, COUNT(*) FROM employees GROUP BY dept
SELECT * FROM user_counts
```

**Error message**:
```
Error E2011 at line 2, column 5: invalid CTE syntax: missing parentheses around CTE query
  2 |     SELECT dept, COUNT(*) FROM employees GROUP BY dept
          ^^^^^^
Hint: CTE queries must be enclosed in parentheses: WITH cte_name AS (SELECT ...)
```

**Common causes**:
- Missing parentheses around CTE query
- Missing column list in recursive CTE
- Invalid RECURSIVE syntax
- Missing UNION in recursive CTE

**Solutions**:
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

-- Wrong: Recursive CTE without proper structure
WITH RECURSIVE hierarchy AS (
    SELECT id, parent_id FROM nodes
)
SELECT * FROM hierarchy

-- Right: Proper recursive CTE with UNION
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

#### E2012 - Invalid Set Operation

**When it occurs**: A set operation (UNION, INTERSECT, EXCEPT) has invalid syntax.

**Example**:
```sql
SELECT id FROM users
UNION
SELECT id, name FROM orders
```

**Error message**:
```
Error E2012 at line 3, column 1: invalid set operation: column count mismatch (1 vs 2)
  3 | SELECT id, name FROM orders
      ^^^^^^
Hint: All queries in a set operation must return the same number of columns
```

**Common causes**:
- Mismatched column counts between queries
- Incompatible data types
- Missing ALL keyword when duplicates needed
- ORDER BY in wrong position

**Solutions**:
```sql
-- Wrong: Different column counts
SELECT id FROM users
UNION
SELECT id, name FROM orders

-- Right: Same column count
SELECT id, name FROM users
UNION
SELECT id, customer_name FROM orders

-- Wrong: ORDER BY in subquery
(SELECT * FROM users ORDER BY name)
UNION
(SELECT * FROM admins)

-- Right: ORDER BY at end
SELECT * FROM users
UNION
SELECT * FROM admins
ORDER BY name

-- Use UNION ALL to keep duplicates
SELECT status FROM orders
UNION ALL
SELECT status FROM archived_orders
```

---

### E3xxx - Semantic Errors (Analysis)

These errors occur during semantic analysis when validating table and column references, type compatibility, and other logical constraints.

#### E3001 - Undefined Table

**When it occurs**: A table reference cannot be resolved (semantic analysis feature).

**Example**:
```sql
SELECT * FROM nonexistent_table
```

**Note**: This error requires semantic analysis to be enabled. It validates that referenced tables exist in the schema.

---

#### E3002 - Undefined Column

**When it occurs**: A column reference cannot be resolved (semantic analysis feature).

**Example**:
```sql
SELECT nonexistent_column FROM users
```

**Note**: This error requires semantic analysis to be enabled. It validates that referenced columns exist in their tables.

---

#### E3003 - Type Mismatch

**When it occurs**: Type incompatibility in expressions or comparisons (semantic analysis feature).

**Example**:
```sql
SELECT * FROM users WHERE age = 'not a number'
```

**Note**: This error requires semantic analysis with type checking enabled.

---

#### E3004 - Ambiguous Column

**When it occurs**: A column name could refer to multiple tables (semantic analysis feature).

**Example**:
```sql
SELECT id FROM users, orders WHERE id > 10
```

**Solution**: Qualify column names with table names or aliases:
```sql
SELECT users.id FROM users, orders WHERE users.id > 10
```

---

### E4xxx - Unsupported Features

These errors indicate features that are not yet implemented in GoSQLX.

#### E4001 - Unsupported Feature

**When it occurs**: A SQL feature is not yet supported by GoSQLX.

**Example**:
```sql
-- Some advanced SQL feature not yet implemented
```

**Note**: GoSQLX is under active development. Check the documentation for currently supported features.

---

#### E4002 - Unsupported Dialect

**When it occurs**: SQL dialect-specific syntax is not supported.

**Example**:
```sql
-- Database-specific syntax
```

**Note**: GoSQLX supports standard SQL with extensions for PostgreSQL, MySQL, SQL Server, Oracle, and SQLite. Some dialect-specific features may not be available.

---

### Advanced SQL Features - Common Errors

#### Window Functions

**Missing OVER clause**:
```sql
-- Wrong
SELECT name, ROW_NUMBER() FROM employees

-- Right
SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees
```

**PARTITION BY without OVER**:
```sql
-- Wrong
SELECT name, RANK() PARTITION BY dept FROM employees

-- Right
SELECT name, RANK() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees
```

**Window frame without ORDER BY**:
```sql
-- Wrong
SELECT SUM(amount) OVER (ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales

-- Right
SELECT SUM(amount) OVER (ORDER BY date ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales
```

---

#### Common Table Expressions (CTEs)

**CTE without following statement**:
```sql
-- Wrong
WITH user_counts AS (
    SELECT dept, COUNT(*) as cnt FROM employees GROUP BY dept
)

-- Right
WITH user_counts AS (
    SELECT dept, COUNT(*) as cnt FROM employees GROUP BY dept
)
SELECT * FROM user_counts WHERE cnt > 5
```

**Recursive CTE without UNION**:
```sql
-- Wrong
WITH RECURSIVE emp_tree AS (
    SELECT id, name, manager_id FROM employees
)
SELECT * FROM emp_tree

-- Right
WITH RECURSIVE emp_tree AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL
    UNION ALL
    SELECT e.id, e.name, e.manager_id, et.level + 1
    FROM employees e
    JOIN emp_tree et ON e.manager_id = et.id
)
SELECT * FROM emp_tree
```

**Missing comma between multiple CTEs**:
```sql
-- Wrong
WITH cte1 AS (SELECT * FROM users)
     cte2 AS (SELECT * FROM orders)
SELECT * FROM cte1

-- Right
WITH cte1 AS (SELECT * FROM users),
     cte2 AS (SELECT * FROM orders)
SELECT * FROM cte1
```

---

#### Set Operations (UNION, INTERSECT, EXCEPT)

**Mismatched column counts**:
```sql
-- Wrong
SELECT id, name FROM users
UNION
SELECT id FROM orders

-- Right
SELECT id, name FROM users
UNION
SELECT order_id, customer_name FROM orders
```

**ORDER BY in subquery**:
```sql
-- Wrong
(SELECT * FROM users ORDER BY name)
UNION
(SELECT * FROM admins ORDER BY name)

-- Right
SELECT * FROM users
UNION
SELECT * FROM admins
ORDER BY name
```

---

#### JOIN Operations

**Missing ON/USING clause**:
```sql
-- Wrong
SELECT * FROM users JOIN orders

-- Right
SELECT * FROM users JOIN orders ON users.id = orders.user_id

-- Also Right: Using USING clause
SELECT * FROM users JOIN orders USING (user_id)
```

**Ambiguous column reference**:
```sql
-- Wrong
SELECT id FROM users, orders WHERE id > 10

-- Right
SELECT users.id FROM users, orders WHERE users.id > 10

-- Also Right: Use aliases
SELECT u.id FROM users u, orders o WHERE u.id > 10
```

---

## Error Handling Best Practices

### 1. Check Error Codes Programmatically

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
        // Handle syntax errors
        fmt.Println("SQL syntax error detected")
    }

    // Get error code
    code := errors.GetCode(err)
    fmt.Printf("Error code: %s\n", code)
}
```

### 2. Use Structured Error Information

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

### 3. Format Errors for User Display

```go
import "github.com/ajitpratap0/GoSQLX/pkg/errors"

// Get formatted error with context
formatted := errors.FormatErrorWithContext(err, sqlQuery)
fmt.Println(formatted)

// Get error summary (no context)
summary := errors.FormatErrorSummary(err)
fmt.Println(summary)

// Format with custom suggestion
formatted := errors.FormatErrorWithSuggestion(
    errors.ErrCodeExpectedToken,
    "expected FROM",
    location,
    sqlQuery,
    4, // highlight length
    "Use FROM keyword after SELECT",
)
```

### 4. Extract Error Components

```go
// Check if it's a structured error
if errors.IsStructuredError(err) {
    // Extract location
    if loc, ok := errors.ExtractLocation(err); ok {
        fmt.Printf("Error at line %d, column %d\n", loc.Line, loc.Column)
    }

    // Extract error code
    if code, ok := errors.ExtractErrorCode(err); ok {
        fmt.Printf("Error code: %s\n", code)
    }
}
```

---

## Common Mistake Patterns

GoSQLX provides intelligent suggestions for 20+ common SQL mistakes:

### Type Mismatches

```sql
-- ❌ Wrong: String instead of number
SELECT * FROM users WHERE age > '18'

-- ✓ Right: Numeric value
SELECT * FROM users WHERE age > 18

Hint: Remove quotes around numeric values
```

### Missing Operators

```sql
-- ❌ Wrong: Missing comparison operator
SELECT * FROM users WHERE age 18

-- ✓ Right: Add comparison operator
SELECT * FROM users WHERE age = 18
```

### Aggregate Function Syntax

```sql
-- ❌ Wrong: Missing parentheses
SELECT COUNT * FROM users

-- ✓ Right: Proper function syntax
SELECT COUNT(*) FROM users
```

### GROUP BY Requirements

```sql
-- ❌ Wrong: Missing GROUP BY
SELECT dept, COUNT(*) FROM employees

-- ✓ Right: Add GROUP BY
SELECT dept, COUNT(*) FROM employees GROUP BY dept
```

---

## Performance Tips

When working with errors in production:

1. **Cache error patterns**: Error suggestions use Levenshtein distance which can be cached
2. **Use error codes**: Check error codes instead of string matching
3. **Structured logging**: Log error codes and locations for debugging
4. **Error recovery**: Use error codes to implement auto-fix logic

---

## Getting Help

- **Full Documentation**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for error handling patterns
- **GitHub Issues**: Report bugs or request features at [github.com/ajitpratap0/GoSQLX/issues](https://github.com/ajitpratap0/GoSQLX/issues)
- **Help URLs**: Each error includes a help URL: `https://docs.gosqlx.dev/errors/<CODE>`

---

## Error Code Changelog

### v1.4.0
- Added comprehensive error context formatting
- Added intelligent error suggestions
- Added Unicode support in error messages
- Added window function error patterns
- Added CTE error patterns
- Added set operation error patterns

### v1.3.0
- Initial structured error system
- Basic error codes (E1xxx-E4xxx)
- Position tracking
- Simple hints
