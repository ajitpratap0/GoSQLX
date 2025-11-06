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
| E2001 | Parser | Unexpected token |
| E2002 | Parser | Expected token not found |
| E2003 | Parser | Missing required clause |
| E2004 | Parser | General syntax error |
| E2005 | Parser | Incomplete statement |
| E2006 | Parser | Invalid expression |
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

p := parser.New()
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

- **Full Documentation**: See [ERROR_REFERENCE.md](ERROR_REFERENCE.md) for detailed error descriptions
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
