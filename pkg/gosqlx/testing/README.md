# GoSQLX Testing Helpers

A comprehensive testing helper package for writing SQL parsing tests with GoSQLX. This package provides assertion and requirement functions that integrate seamlessly with Go's standard `testing` package.

## Features

- **Validation Helpers**: Assert or require SQL validity
- **Formatting Assertions**: Test SQL formatting output
- **Metadata Extraction**: Assert tables and columns referenced in SQL
- **Statement Type Checking**: Verify parsed AST statement types
- **Error Testing**: Assert specific error conditions
- **Clear Error Messages**: Descriptive failures with SQL context
- **T.Helper() Support**: Proper test failure reporting at the call site

## Installation

This package is part of GoSQLX. Import it in your tests:

```go
import (
    "testing"
    gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
)
```

## Quick Start

```go
func TestUserQueries(t *testing.T) {
    // Assert SQL is valid
    gosqlxtesting.AssertValidSQL(t, "SELECT * FROM users WHERE active = true")

    // Verify tables referenced
    gosqlxtesting.AssertTables(t,
        "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
        []string{"users", "orders"})

    // Verify columns selected
    gosqlxtesting.AssertColumns(t,
        "SELECT id, name, email FROM users",
        []string{"id", "name", "email"})

    // Verify statement type
    gosqlxtesting.AssertParsesTo(t,
        "INSERT INTO users (name) VALUES ('John')",
        &ast.InsertStatement{})
}
```

## API Reference

### Validation Functions

#### AssertValidSQL
```go
func AssertValidSQL(t TestingT, sql string) bool
```
Asserts that SQL is syntactically valid. Test continues on failure.

**Example:**
```go
gosqlxtesting.AssertValidSQL(t, "SELECT * FROM users")
```

#### AssertInvalidSQL
```go
func AssertInvalidSQL(t TestingT, sql string) bool
```
Asserts that SQL is syntactically invalid. Test continues on failure.

**Example:**
```go
gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM WHERE")
```

#### RequireValidSQL
```go
func RequireValidSQL(t TestingT, sql string)
```
Requires SQL to be valid. Test stops immediately on failure.

**Example:**
```go
gosqlxtesting.RequireValidSQL(t, "SELECT * FROM users")
// Code below only executes if SQL is valid
```

#### RequireInvalidSQL
```go
func RequireInvalidSQL(t TestingT, sql string)
```
Requires SQL to be invalid. Test stops immediately on failure.

**Example:**
```go
gosqlxtesting.RequireInvalidSQL(t, "SELECT FROM")
```

### Formatting Functions

#### AssertFormattedSQL
```go
func AssertFormattedSQL(t TestingT, sql, expected string) bool
```
Asserts that SQL formats to match expected output.

**Example:**
```go
gosqlxtesting.AssertFormattedSQL(t,
    "select * from users",
    "SELECT * FROM users")
```

### Metadata Extraction Functions

#### AssertTables
```go
func AssertTables(t TestingT, sql string, expectedTables []string) bool
```
Asserts that SQL references the expected tables (order-independent).

**Examples:**
```go
// Simple SELECT
gosqlxtesting.AssertTables(t,
    "SELECT * FROM users",
    []string{"users"})

// JOIN query
gosqlxtesting.AssertTables(t,
    "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
    []string{"users", "orders"})

// Multiple JOINs
gosqlxtesting.AssertTables(t,
    "SELECT * FROM users u LEFT JOIN orders o ON u.id = o.user_id RIGHT JOIN products p",
    []string{"users", "orders", "products"})

// INSERT/UPDATE/DELETE
gosqlxtesting.AssertTables(t, "INSERT INTO users (name) VALUES ('John')", []string{"users"})
gosqlxtesting.AssertTables(t, "UPDATE orders SET status = 'shipped'", []string{"orders"})
gosqlxtesting.AssertTables(t, "DELETE FROM old_records", []string{"old_records"})
```

#### AssertColumns
```go
func AssertColumns(t TestingT, sql string, expectedColumns []string) bool
```
Asserts that SELECT statement selects the expected columns (order-independent).

**Examples:**
```go
// Simple column list
gosqlxtesting.AssertColumns(t,
    "SELECT id, name, email FROM users",
    []string{"id", "name", "email"})

// Order doesn't matter
gosqlxtesting.AssertColumns(t,
    "SELECT name, id, email FROM users",
    []string{"email", "id", "name"}) // Still passes

// With WHERE clause (only SELECT columns are extracted)
gosqlxtesting.AssertColumns(t,
    "SELECT id, name FROM users WHERE active = true",
    []string{"id", "name"})
```

### Statement Type Functions

#### AssertParsesTo
```go
func AssertParsesTo(t TestingT, sql string, expectedType interface{}) bool
```
Asserts that SQL parses to a specific AST statement type.

**Examples:**
```go
gosqlxtesting.AssertParsesTo(t, "SELECT * FROM users", &ast.SelectStatement{})
gosqlxtesting.AssertParsesTo(t, "INSERT INTO users (name) VALUES ('John')", &ast.InsertStatement{})
gosqlxtesting.AssertParsesTo(t, "UPDATE users SET active = false", &ast.UpdateStatement{})
gosqlxtesting.AssertParsesTo(t, "DELETE FROM users", &ast.DeleteStatement{})
```

### Error Testing Functions

#### AssertErrorContains
```go
func AssertErrorContains(t TestingT, sql, expectedSubstring string) bool
```
Asserts that parsing SQL produces an error containing the expected substring.

**Examples:**
```go
gosqlxtesting.AssertErrorContains(t, "SELECT FROM WHERE", "parsing")
gosqlxtesting.AssertErrorContains(t, "INVALID SQL", "tokenization")
```

### Advanced Functions

#### RequireParse
```go
func RequireParse(t TestingT, sql string) *ast.AST
```
Requires SQL to parse successfully and returns the AST. Test stops on failure.

**Example:**
```go
astNode := gosqlxtesting.RequireParse(t, "SELECT id, name FROM users")

// Make custom assertions on the AST
if selectStmt, ok := astNode.Statements[0].(*ast.SelectStatement); ok {
    if len(selectStmt.Columns) != 2 {
        t.Errorf("Expected 2 columns, got %d", len(selectStmt.Columns))
    }
}
```

## Comprehensive Test Example

```go
func TestUserManagement(t *testing.T) {
    // Test valid user queries
    userQuery := "SELECT id, name, email FROM users WHERE active = true"

    // Validate syntax
    gosqlxtesting.RequireValidSQL(t, userQuery)

    // Verify metadata
    gosqlxtesting.AssertTables(t, userQuery, []string{"users"})
    gosqlxtesting.AssertColumns(t, userQuery, []string{"id", "name", "email"})

    // Verify statement type
    gosqlxtesting.AssertParsesTo(t, userQuery, &ast.SelectStatement{})

    // Test invalid variations
    gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM users WHERE")
    gosqlxtesting.AssertErrorContains(t, "SELECT * FROM", "parsing")
}
```

## Testing Different SQL Features

### Window Functions
```go
func TestWindowFunctions(t *testing.T) {
    windowQuery := `
        SELECT
            name,
            salary,
            ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
        FROM employees
    `

    gosqlxtesting.RequireValidSQL(t, windowQuery)
    gosqlxtesting.AssertTables(t, windowQuery, []string{"employees"})
    gosqlxtesting.AssertColumns(t, windowQuery, []string{"name", "salary"})
}
```

### Common Table Expressions (CTEs)
```go
func TestCTEs(t *testing.T) {
    cteQuery := `
        WITH active_users AS (
            SELECT id, name FROM users WHERE active = true
        )
        SELECT name FROM active_users
    `

    gosqlxtesting.RequireValidSQL(t, cteQuery)
    gosqlxtesting.AssertTables(t, cteQuery, []string{"users"})
}
```

### JOIN Queries
```go
func TestJoins(t *testing.T) {
    testCases := []struct {
        name   string
        query  string
        tables []string
    }{
        {
            name:   "INNER JOIN",
            query:  "SELECT * FROM users u INNER JOIN orders o ON u.id = o.user_id",
            tables: []string{"users", "orders"},
        },
        {
            name:   "Multiple JOINs",
            query:  "SELECT * FROM users u JOIN orders o ON u.id = o.user_id JOIN products p ON o.product_id = p.id",
            tables: []string{"users", "orders", "products"},
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            gosqlxtesting.RequireValidSQL(t, tc.query)
            gosqlxtesting.AssertTables(t, tc.query, tc.tables)
        })
    }
}
```

## Design Decisions

### TestingT Interface
The package uses a `TestingT` interface instead of `*testing.T` directly. This allows:
- Easy mocking in the package's own tests
- Compatibility with testing frameworks that wrap `*testing.T`
- Future extensibility

### Order-Independent Comparisons
`AssertTables` and `AssertColumns` compare slices in an order-independent way, as SQL doesn't guarantee order for these metadata elements.

### Synthetic Table Filtering
The table extraction automatically filters out synthetic table names that the parser may generate internally (e.g., tables with parentheses or `_with_` patterns).

### Clear Error Messages
All assertion functions provide:
- The SQL that was being tested (truncated to 100 chars if needed)
- Expected vs actual values
- Contextual information about the failure

### T.Helper() Support
All functions call `t.Helper()` to ensure test failures are reported at the call site, not inside the helper functions.

## Coverage

The testing package achieves **93.7% test coverage**, ensuring reliability for your test suites.

## Contributing

When adding new helper functions:
1. Follow the naming convention: `Assert*` for soft assertions, `Require*` for hard requirements
2. Always call `t.Helper()` as the first line
3. Provide clear, descriptive error messages
4. Add comprehensive tests
5. Add godoc examples in `example_test.go`

## License

Part of the GoSQLX project. See the main project LICENSE for details.
