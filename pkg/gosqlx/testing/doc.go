/*
Package testing provides comprehensive test helpers for SQL parsing validation.

This package offers convenient assertion and requirement functions for testing SQL
parsing, formatting, and metadata extraction in Go test suites. It integrates
seamlessly with Go's standard testing package and follows patterns similar to
testify/assert and testify/require.

# Overview

The testing package simplifies writing tests for SQL parsing by providing:
  - Clear, descriptive error messages with SQL context
  - Proper test failure reporting with t.Helper() for accurate stack traces
  - Both assertion (test continues) and requirement (test stops) styles
  - Metadata extraction helpers for validating tables and columns
  - SQL validity checking for positive and negative test cases

# Quick Start

Basic SQL validation:

	import (
	    "testing"
	    sqltest "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
	)

	func TestBasicSQL(t *testing.T) {
	    // Assert SQL is valid
	    sqltest.AssertValidSQL(t, "SELECT * FROM users")

	    // Assert SQL is invalid
	    sqltest.AssertInvalidSQL(t, "SELECT FROM WHERE")

	    // Require SQL to parse (stops test on failure)
	    ast := sqltest.RequireParse(t, "SELECT id, name FROM users")
	    // Continue working with ast
	}

# Assertion vs Requirement Functions

The package provides two styles of test helpers:

Assert functions (AssertValidSQL, AssertInvalidSQL, etc.):
  - Report failures with t.Errorf()
  - Test continues after failure
  - Use for non-critical checks or when testing multiple conditions
  - Return bool indicating success (true) or failure (false)

Require functions (RequireValidSQL, RequireParse, etc.):
  - Report failures with t.Fatalf()
  - Test stops immediately on failure
  - Use for critical preconditions that must pass
  - Do not return values (test terminates on failure)

# Metadata Validation

Test that SQL queries reference the expected tables and columns:

	func TestQueryMetadata(t *testing.T) {
	    sql := "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id"

	    // Verify table references
	    sqltest.AssertTables(t, sql, []string{"users", "orders"})

	    // Verify column references
	    sqltest.AssertColumns(t, sql, []string{"name", "total", "id", "user_id"})
	}

# AST Type Verification

Verify that SQL parses to the expected statement type:

	func TestStatementTypes(t *testing.T) {
	    sqltest.AssertParsesTo(t, "SELECT * FROM users", &ast.SelectStatement{})
	    sqltest.AssertParsesTo(t, "INSERT INTO users VALUES (1, 'John')", &ast.InsertStatement{})
	    sqltest.AssertParsesTo(t, "UPDATE users SET name = 'Jane'", &ast.UpdateStatement{})
	    sqltest.AssertParsesTo(t, "DELETE FROM users", &ast.DeleteStatement{})
	}

# Error Message Testing

Test that parsing produces specific error messages:

	func TestParsingErrors(t *testing.T) {
	    // Verify error contains expected substring
	    sqltest.AssertErrorContains(t, "SELECT FROM WHERE", "unexpected token")

	    // Verify SQL is invalid without checking specific message
	    sqltest.AssertInvalidSQL(t, "INVALID SQL SYNTAX HERE")
	}

# Formatting Validation

Test SQL formatting (note: full formatting support coming in future release):

	func TestFormatting(t *testing.T) {
	    input := "select * from users"
	    expected := "SELECT * FROM users;"
	    sqltest.AssertFormattedSQL(t, input, expected)
	}

# Table-Driven Tests

Use the helpers in table-driven tests for comprehensive coverage:

	func TestSQLQueries(t *testing.T) {
	    tests := []struct {
	        name   string
	        sql    string
	        valid  bool
	        tables []string
	    }{
	        {
	            name:   "simple select",
	            sql:    "SELECT * FROM users",
	            valid:  true,
	            tables: []string{"users"},
	        },
	        {
	            name:   "join query",
	            sql:    "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
	            valid:  true,
	            tables: []string{"users", "orders"},
	        },
	        {
	            name:  "invalid syntax",
	            sql:   "SELECT FROM WHERE",
	            valid: false,
	        },
	    }

	    for _, tt := range tests {
	        t.Run(tt.name, func(t *testing.T) {
	            if tt.valid {
	                sqltest.AssertValidSQL(t, tt.sql)
	                if tt.tables != nil {
	                    sqltest.AssertTables(t, tt.sql, tt.tables)
	                }
	            } else {
	                sqltest.AssertInvalidSQL(t, tt.sql)
	            }
	        })
	    }
	}

# PostgreSQL v1.6.0 Features

Test PostgreSQL-specific features supported in GoSQLX v1.6.0:

	func TestPostgreSQLFeatures(t *testing.T) {
	    // JSON operators
	    sqltest.AssertValidSQL(t, "SELECT data->>'name' FROM users")
	    sqltest.AssertValidSQL(t, "SELECT * FROM users WHERE data @> '{\"status\":\"active\"}'")

	    // LATERAL JOIN
	    sqltest.AssertValidSQL(t, `
	        SELECT u.name, o.order_date
	        FROM users u,
	        LATERAL (SELECT * FROM orders WHERE user_id = u.id LIMIT 3) o
	    `)

	    // FILTER clause
	    sqltest.AssertValidSQL(t, `
	        SELECT COUNT(*) FILTER (WHERE status = 'active') FROM users
	    `)

	    // RETURNING clause
	    sqltest.AssertValidSQL(t, `
	        INSERT INTO users (name) VALUES ('John') RETURNING id, created_at
	    `)

	    // DISTINCT ON
	    sqltest.AssertValidSQL(t, `
	        SELECT DISTINCT ON (dept_id) dept_id, name
	        FROM employees ORDER BY dept_id, salary DESC
	    `)
	}

# Advanced SQL Features

Test SQL-99 and SQL:2003 features:

	func TestAdvancedFeatures(t *testing.T) {
	    // Window functions
	    sqltest.AssertValidSQL(t, `
	        SELECT name, salary,
	            RANK() OVER (PARTITION BY dept ORDER BY salary DESC)
	        FROM employees
	    `)

	    // CTEs with RECURSIVE
	    sqltest.AssertValidSQL(t, `
	        WITH RECURSIVE org_chart AS (
	            SELECT id, name, manager_id FROM employees WHERE manager_id IS NULL
	            UNION ALL
	            SELECT e.id, e.name, e.manager_id
	            FROM employees e JOIN org_chart o ON e.manager_id = o.id
	        )
	        SELECT * FROM org_chart
	    `)

	    // GROUPING SETS
	    sqltest.AssertValidSQL(t, `
	        SELECT region, product, SUM(sales)
	        FROM orders
	        GROUP BY GROUPING SETS ((region), (product), (region, product))
	    `)

	    // MERGE statement
	    sqltest.AssertValidSQL(t, `
	        MERGE INTO target t
	        USING source s ON t.id = s.id
	        WHEN MATCHED THEN UPDATE SET t.value = s.value
	        WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)
	    `)
	}

# Best Practices

 1. Use t.Helper() pattern: All functions call t.Helper() to report failures at
    the correct line in your test code, not in the helper function.

2. Choose assertion vs requirement appropriately:

  - Use Assert* for multiple checks in one test

  - Use Require* when failure makes subsequent checks meaningless

    3. Truncated error messages: Long SQL strings are automatically truncated in
    error messages (max 100 characters) for readability.

    4. Order independence: Table and column assertions compare sets, not ordered
    lists. ["users", "orders"] matches ["orders", "users"].

    5. Test both positive and negative cases: Always test that valid SQL passes
    and invalid SQL fails to ensure comprehensive coverage.

# Thread Safety

All test helper functions are safe to call concurrently from different goroutines
running parallel tests (t.Parallel()). Each test gets its own testing.T instance,
so there are no shared resources.

# Performance

The test helpers parse SQL using the full GoSQLX parser, which is optimized
for performance:
  - Parsing: <1ms for typical queries
  - Metadata extraction: <100μs for complex queries
  - Object pooling: Automatic memory reuse across test cases

For test suites with hundreds or thousands of SQL test cases, the helpers
provide excellent performance with minimal overhead.

# Error Message Format

All assertion failures include formatted error messages with context:

	Expected valid SQL, but got error:
	  SQL: SELECT * FROM users WHERE id = ?
	  Error: parsing failed: unexpected token at line 1, column 35

	SQL table references do not match expected:
	  SQL: SELECT * FROM users u JOIN orders o ON u.id = o.user_id
	  Expected: [orders users]
	  Got: [orders posts users]

# Integration with Test Frameworks

While designed for Go's standard testing package, the helpers work with any
framework that provides a compatible testing.T interface:

	type TestingT interface {
	    Helper()
	    Errorf(format string, args ...interface{})
	    Fatalf(format string, args ...interface{})
	}

This allows integration with frameworks like Ginkgo, testify, or custom test runners.

# Example Test Suite

Complete example of a comprehensive SQL test suite:

	package myapp_test

	import (
	    "testing"
	    sqltest "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
	    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	)

	func TestUserQueries(t *testing.T) {
	    t.Run("list all users", func(t *testing.T) {
	        sql := "SELECT id, name, email FROM users WHERE active = true"
	        sqltest.AssertValidSQL(t, sql)
	        sqltest.AssertTables(t, sql, []string{"users"})
	        sqltest.AssertColumns(t, sql, []string{"id", "name", "email", "active"})
	        sqltest.AssertParsesTo(t, sql, &ast.SelectStatement{})
	    })

	    t.Run("user with orders", func(t *testing.T) {
	        sql := `
	            SELECT u.name, COUNT(o.id) as order_count
	            FROM users u
	            LEFT JOIN orders o ON u.id = o.user_id
	            GROUP BY u.name
	        `
	        sqltest.AssertValidSQL(t, sql)
	        sqltest.AssertTables(t, sql, []string{"users", "orders"})
	    })

	    t.Run("invalid query", func(t *testing.T) {
	        sqltest.AssertInvalidSQL(t, "SELECT FROM users WHERE")
	        sqltest.AssertErrorContains(t, "SELECT FROM WHERE", "unexpected")
	    })
	}

# See Also

  - gosqlx package: Main high-level API for SQL parsing
  - gosqlx.Parse: Core parsing function used by these helpers
  - gosqlx.ExtractTables, ExtractColumns: Metadata extraction
  - ast package: AST node type definitions

# Version

Package testing is part of GoSQLX v1.6.0+.

For the latest documentation and examples, visit:
https://github.com/ajitpratap0/GoSQLX
*/
package testing
