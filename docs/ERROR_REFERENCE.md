# GoSQLX Error Reference

This document provides a comprehensive reference for all error codes in GoSQLX, including descriptions, common causes, and solutions.

## Error Code System

GoSQLX uses a structured error code system for programmatic error handling:

- **E1xxx**: Tokenizer errors (lexical analysis)
- **E2xxx**: Parser syntax errors (grammatical analysis)
- **E3xxx**: Semantic errors (logical errors)
- **E4xxx**: Unsupported features

## Using Error Codes Programmatically

```go
import (
    "github.com/ajitpratap0/GoSQLX/pkg/errors"
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

ast, err := gosqlx.Parse("SELECT * FORM users")
if err != nil {
    // Check for specific error code
    if errors.IsCode(err, errors.ErrCodeExpectedToken) {
        fmt.Println("Syntax error detected")
    }

    // Get error code
    code := errors.GetCode(err)
    fmt.Printf("Error code: %s\n", code)
}
```

---

## Tokenizer Errors (E1xxx)

### E1001 - Unexpected Character

**Description**: An unexpected or invalid character was encountered during tokenization.

**Example**:
```
Error E1001 at line 1, column 39: unexpected character '&'
  1 | SELECT * FROM users WHERE name = 'John' & age > 18
                                              ^
Hint: Remove or escape the character '&'
```

**Common Causes**:
- Using unsupported operators (use `AND` instead of `&`)
- Special characters in identifiers without proper quoting
- Copy-paste errors introducing non-SQL characters

**Solutions**:
- Replace `&` with `AND` for logical operations
- Use double quotes for identifiers with special characters: `"my-table"`
- Check for hidden characters (especially in copy-pasted SQL)

---

### E1002 - Unterminated String

**Description**: A string literal was not properly closed with a matching quote.

**Example**:
```
Error E1002 at line 1, column 34: unterminated string literal
  1 | SELECT * FROM users WHERE name = 'John
                                         ^
Hint: Make sure all string literals are properly closed with matching quotes
```

**Common Causes**:
- Missing closing quote in string literal
- Unescaped quotes within strings
- Multiline strings without proper formatting

**Solutions**:
- Add the missing closing quote
- Escape quotes within strings: `'O''Brien'` or use different quote type
- For multiline strings, use proper SQL multiline syntax

---

### E1003 - Invalid Number

**Description**: A numeric literal has invalid format.

**Example**:
```
Error E1003 at line 1, column 33: invalid numeric literal: '18.45.6'
  1 | SELECT * FROM users WHERE age > 18.45.6
                                      ^^^^^^^
Hint: Check the numeric format (e.g., 123, 123.45, 1.23e10)
```

**Common Causes**:
- Multiple decimal points
- Invalid scientific notation
- Non-numeric characters in number

**Solutions**:
- Use valid decimal format: `18.45`
- For scientific notation: `1.23e10`
- Remove non-numeric characters

---

### E1004 - Invalid Operator

**Description**: An invalid operator sequence was encountered.

**Example**:
```
Error E1004 at line 1, column 15: invalid operator sequence
```

**Common Causes**:
- Typos in operators (`=>` instead of `>=`)
- Unsupported operators from other SQL dialects
- Incorrect spacing in multi-character operators

**Solutions**:
- Use standard SQL operators: `>=`, `<=`, `<>`, `!=`
- Check SQL dialect compatibility
- Ensure proper spacing: `< =` is different from `<=`

---

### E1005 - Invalid Identifier

**Description**: An identifier (table, column, or alias name) has invalid format.

**Example**:
```
Error E1005 at line 1, column 20: invalid identifier format
```

**Common Causes**:
- Starting identifier with a number
- Using reserved keywords without quotes
- Special characters in unquoted identifiers

**Solutions**:
- Start identifiers with letters or underscore
- Quote identifiers with reserved keywords: `"SELECT"`
- Use quotes for special characters: `"my-column"`

---

## Parser Errors (E2xxx)

### E2001 - Unexpected Token

**Description**: The parser encountered a token that doesn't fit the SQL grammar at this position.

**Example**:
```
Error E2001 at line 1, column 10: unexpected token: IDENT ('FORM')
  1 | SELECT * FORM users
                ^^^^
Hint: Did you mean 'FROM'?
```

**Common Causes**:
- Typos in SQL keywords
- Missing or extra tokens
- Incorrect SQL syntax

**Solutions**:
- Fix typos (the hint often suggests the correct keyword)
- Review SQL syntax for this statement type
- Check for missing commas or parentheses

---

### E2002 - Expected Token

**Description**: The parser expected a specific token but found something else.

**Example**:
```
Error E2002 at line 1, column 10: expected FROM, got FORM
  1 | SELECT * FORM users
                ^^^^
Hint: Did you mean 'FROM' instead of 'FORM'?
```

**Common Causes**:
- Typos in keywords
- Missing required clauses
- Incorrect keyword order

**Solutions**:
- Use the suggested correction from the hint
- Add the missing keyword
- Reorder clauses according to SQL syntax: SELECT → FROM → WHERE → GROUP BY → ORDER BY

---

### E2003 - Missing Clause

**Description**: A required SQL clause is missing from the statement.

**Example**:
```
Error E2003 at line 1, column 10: missing required FROM clause
  1 | SELECT * users
                ^
Hint: Add the required 'FROM' clause to complete this statement
```

**Common Causes**:
- Incomplete SQL statement
- Omitting required keywords
- Misunderstanding SQL syntax

**Solutions**:
- Add the missing clause: `SELECT * FROM users`
- Review required clauses for this statement type
- Consult SQL documentation for proper syntax

---

### E2004 - Invalid Syntax

**Description**: General syntax error that doesn't fit other specific categories.

**Example**:
```
Error E2004 at line 1, column 15: invalid syntax: missing table name
  1 | SELECT * FROM WHERE age > 18
                    ^
Hint: Review the SQL syntax documentation for this statement type
```

**Common Causes**:
- Missing required elements
- Incorrect clause order
- Unsupported SQL patterns

**Solutions**:
- Add the missing element (table name, column name, etc.)
- Reorder clauses according to SQL syntax
- Simplify complex queries to identify the issue

---

### E2005 - Incomplete Statement

**Description**: The SQL statement is incomplete and ends unexpectedly.

**Example**:
```
Error E2005 at line 1, column 14: incomplete SQL statement
  1 | SELECT * FROM
                   ^
Hint: Complete the SQL statement or check for missing clauses
```

**Common Causes**:
- Truncated SQL query
- Missing table name or other required elements
- Unfinished WHERE or JOIN clause

**Solutions**:
- Complete the statement with required elements
- Add the table name after FROM
- Finish all open clauses

---

### E2006 - Invalid Expression

**Description**: An expression (column reference, calculation, etc.) has invalid syntax.

**Example**:
```
Error E2006 at line 1, column 20: invalid expression syntax
```

**Common Causes**:
- Unmatched parentheses in expressions
- Invalid operator usage
- Incorrect function call syntax

**Solutions**:
- Balance all parentheses: `(price * quantity)`
- Use correct operators for the data type
- Check function syntax: `COUNT(*)`, `SUM(price)`

---

## Semantic Errors (E3xxx)

### E3001 - Undefined Table

**Description**: Referenced table is not defined in the query or database schema.

**Example**:
```
Error E3001 at line 1, column 15: undefined table: 'user'
```

**Common Causes**:
- Typo in table name
- Table doesn't exist
- Missing JOIN for referenced table

**Solutions**:
- Fix table name typo
- Verify table exists in schema
- Add appropriate JOIN clause

---

### E3002 - Undefined Column

**Description**: Referenced column is not defined for the table.

**Example**:
```
Error E3002 at line 1, column 20: undefined column: 'nam'
```

**Common Causes**:
- Typo in column name
- Column doesn't exist in table
- Referencing column before defining alias

**Solutions**:
- Fix column name typo
- Verify column exists in table schema
- Define aliases before referencing them

---

### E3003 - Type Mismatch

**Description**: Operation involves incompatible data types.

**Example**:
```
Error E3003 at line 1, column 30: type mismatch: cannot compare string with number
```

**Common Causes**:
- Comparing incompatible types
- Invalid function arguments
- Incorrect arithmetic operations

**Solutions**:
- Cast values to compatible types
- Use appropriate comparison operators
- Check function parameter types

---

### E3004 - Ambiguous Column

**Description**: Column reference is ambiguous (exists in multiple tables).

**Example**:
```
Error E3004 at line 1, column 8: ambiguous column reference: 'id'
```

**Common Causes**:
- Column exists in multiple joined tables
- Missing table qualifier
- Unclear which table the column belongs to

**Solutions**:
- Qualify column with table name: `users.id`
- Use table aliases: `u.id` where `u` is alias for `users`
- Ensure column references are unique

---

## Unsupported Features (E4xxx)

### E4001 - Unsupported Feature

**Description**: The SQL feature is not yet supported by GoSQLX.

**Example**:
```
Error E4001 at line 1, column 25: unsupported feature: recursive CTEs
  1 | WITH RECURSIVE cte AS ...
                              ^
Hint: This feature is not yet supported. Check the documentation for supported SQL features
```

**Common Causes**:
- Using advanced SQL features not yet implemented
- Dialect-specific syntax
- New SQL standard features

**Solutions**:
- Check GoSQLX documentation for supported features
- Use alternative SQL patterns if available
- Consider submitting a feature request on GitHub

---

### E4002 - Unsupported Dialect

**Description**: SQL dialect-specific syntax that is not supported.

**Example**:
```
Error E4002 at line 1, column 15: unsupported dialect: PostgreSQL-specific syntax
```

**Common Causes**:
- Using PostgreSQL/MySQL/Oracle-specific syntax
- Dialect-specific functions or operators
- Non-standard SQL extensions

**Solutions**:
- Use standard SQL syntax
- Check dialect compatibility in documentation
- Consider using multi-dialect compatible alternatives

---

## Error Handling Best Practices

### 1. Always Check Error Codes

```go
ast, err := gosqlx.Parse(sql)
if err != nil {
    switch errors.GetCode(err) {
    case errors.ErrCodeExpectedToken:
        // Handle syntax errors
        log.Printf("Syntax error: %v", err)
    case errors.ErrCodeUnsupportedFeature:
        // Handle unsupported features
        log.Printf("Feature not supported: %v", err)
    default:
        // Handle other errors
        log.Printf("Parse error: %v", err)
    }
}
```

### 2. Extract Context for User Display

```go
if parseErr, ok := err.(*errors.Error); ok {
    fmt.Printf("Error %s: %s\n", parseErr.Code, parseErr.Message)
    fmt.Printf("Location: Line %d, Column %d\n",
        parseErr.Location.Line, parseErr.Location.Column)
    if parseErr.Hint != "" {
        fmt.Printf("Hint: %s\n", parseErr.Hint)
    }
}
```

### 3. Log Structured Errors

```go
if parseErr, ok := err.(*errors.Error); ok {
    logger.WithFields(map[string]interface{}{
        "error_code": parseErr.Code,
        "line":       parseErr.Location.Line,
        "column":     parseErr.Location.Column,
        "sql":        sql,
    }).Error("SQL parse error")
}
```

### 4. Build Error Recovery Logic

```go
func validateSQL(sql string) error {
    _, err := gosqlx.Parse(sql)
    if err != nil {
        if errors.IsCode(err, errors.ErrCodeExpectedToken) {
            // Try to auto-fix common typos
            return attemptAutoFix(sql, err)
        }
        return err
    }
    return nil
}
```

---

## Getting Help

- **Documentation**: https://docs.gosqlx.dev
- **GitHub Issues**: https://github.com/ajitpratap0/GoSQLX/issues
- **Discussions**: https://github.com/ajitpratap0/GoSQLX/discussions

Each error includes a help URL with more details: `https://docs.gosqlx.dev/errors/<ERROR_CODE>`
