package testing_test

import (
	"testing"

	gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ExampleAssertValidSQL demonstrates validating SQL syntax in tests.
func ExampleAssertValidSQL() {
	// In a real test function
	t := &testing.T{} // This would be passed from the test framework

	// Assert that SQL is valid
	gosqlxtesting.AssertValidSQL(t, "SELECT * FROM users WHERE active = true")

	// Multiple validations
	gosqlxtesting.AssertValidSQL(t, "SELECT id, name FROM users")
	gosqlxtesting.AssertValidSQL(t, "INSERT INTO users (name) VALUES ('John')")
	gosqlxtesting.AssertValidSQL(t, "UPDATE users SET active = false WHERE id = 1")
}

// ExampleAssertInvalidSQL demonstrates testing that SQL is invalid.
func ExampleAssertInvalidSQL() {
	t := &testing.T{}

	// Assert that malformed SQL is detected
	gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM WHERE")
	gosqlxtesting.AssertInvalidSQL(t, "INSERT INTO")
	gosqlxtesting.AssertInvalidSQL(t, "UPDATE SET name = 'test'")
}

// ExampleRequireValidSQL demonstrates stopping tests on invalid SQL.
func ExampleRequireValidSQL() {
	t := &testing.T{}

	// Require valid SQL - test stops if invalid
	gosqlxtesting.RequireValidSQL(t, "SELECT * FROM users")

	// This line only executes if SQL is valid
	// ... rest of test code
}

// ExampleAssertFormattedSQL demonstrates testing SQL formatting.
func ExampleAssertFormattedSQL() {
	t := &testing.T{}

	// Test that SQL formats as expected
	sql := "SELECT * FROM users"
	expected := "SELECT * FROM users"

	gosqlxtesting.AssertFormattedSQL(t, sql, expected)
}

// ExampleAssertTables demonstrates extracting and validating table references.
func ExampleAssertTables() {
	t := &testing.T{}

	// Simple SELECT from single table
	gosqlxtesting.AssertTables(t,
		"SELECT * FROM users",
		[]string{"users"})

	// JOIN query with multiple tables
	gosqlxtesting.AssertTables(t,
		"SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
		[]string{"users", "orders"})

	// Complex query with multiple JOINs
	gosqlxtesting.AssertTables(t,
		`SELECT u.name, o.total, p.name
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		RIGHT JOIN products p ON o.product_id = p.id`,
		[]string{"users", "orders", "products"})

	// INSERT statement
	gosqlxtesting.AssertTables(t,
		"INSERT INTO users (name) VALUES ('John')",
		[]string{"users"})

	// UPDATE statement
	gosqlxtesting.AssertTables(t,
		"UPDATE orders SET status = 'shipped' WHERE id = 1",
		[]string{"orders"})

	// DELETE statement
	gosqlxtesting.AssertTables(t,
		"DELETE FROM old_records WHERE created_at < '2020-01-01'",
		[]string{"old_records"})
}

// ExampleAssertColumns demonstrates extracting and validating column references.
func ExampleAssertColumns() {
	t := &testing.T{}

	// Simple column selection
	gosqlxtesting.AssertColumns(t,
		"SELECT id, name, email FROM users",
		[]string{"id", "name", "email"})

	// With WHERE clause (only SELECT columns are extracted)
	gosqlxtesting.AssertColumns(t,
		"SELECT id, name FROM users WHERE active = true",
		[]string{"id", "name"})

	// Order doesn't matter - both assertions pass
	gosqlxtesting.AssertColumns(t,
		"SELECT name, id, email FROM users",
		[]string{"email", "id", "name"})
}

// ExampleAssertParsesTo demonstrates validating statement types.
func ExampleAssertParsesTo() {
	t := &testing.T{}

	// Verify SQL parses as SELECT statement
	gosqlxtesting.AssertParsesTo(t,
		"SELECT * FROM users",
		&ast.SelectStatement{})

	// Verify SQL parses as INSERT statement
	gosqlxtesting.AssertParsesTo(t,
		"INSERT INTO users (name) VALUES ('John')",
		&ast.InsertStatement{})

	// Verify SQL parses as UPDATE statement
	gosqlxtesting.AssertParsesTo(t,
		"UPDATE users SET active = false",
		&ast.UpdateStatement{})

	// Verify SQL parses as DELETE statement
	gosqlxtesting.AssertParsesTo(t,
		"DELETE FROM users WHERE id = 1",
		&ast.DeleteStatement{})
}

// ExampleAssertErrorContains demonstrates testing specific error conditions.
func ExampleAssertErrorContains() {
	t := &testing.T{}

	// Test that specific error messages are produced
	gosqlxtesting.AssertErrorContains(t,
		"SELECT FROM WHERE",
		"parsing")

	// Test for tokenization errors
	gosqlxtesting.AssertErrorContains(t,
		"SELECT * FROM users WHERE name = 'unterminated",
		"tokenization")
}

// ExampleRequireParse demonstrates getting the AST for further testing.
func ExampleRequireParse() {
	t := &testing.T{}

	// Parse SQL and get AST for custom assertions
	astNode := gosqlxtesting.RequireParse(t, "SELECT id, name FROM users")

	// Now you can make custom assertions on the AST
	if len(astNode.Statements) == 0 {
		t.Error("Expected at least one statement")
	}

	// Type assert to specific statement type
	if selectStmt, ok := astNode.Statements[0].(*ast.SelectStatement); ok {
		if len(selectStmt.Columns) != 2 {
			t.Errorf("Expected 2 columns, got %d", len(selectStmt.Columns))
		}
	}
}

// Example_comprehensiveTest shows a complete test using multiple helpers.
func Example_comprehensiveTest() {
	t := &testing.T{}

	// Test a user query feature
	userQuery := "SELECT id, name, email FROM users WHERE active = true"

	// Validate it's syntactically correct
	gosqlxtesting.RequireValidSQL(t, userQuery)

	// Verify the tables referenced
	gosqlxtesting.AssertTables(t, userQuery, []string{"users"})

	// Verify the columns selected
	gosqlxtesting.AssertColumns(t, userQuery, []string{"id", "name", "email"})

	// Verify it's a SELECT statement
	gosqlxtesting.AssertParsesTo(t, userQuery, &ast.SelectStatement{})

	// Test invalid query variations
	gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM users WHERE")
	gosqlxtesting.AssertErrorContains(t, "SELECT * FROM", "parsing")
}

// Example_windowFunctions demonstrates testing window function queries.
func Example_windowFunctions() {
	t := &testing.T{}

	// Window function query
	windowQuery := `
		SELECT
			name,
			salary,
			ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
		FROM employees
	`

	// Validate complex window function syntax
	gosqlxtesting.RequireValidSQL(t, windowQuery)

	// Verify table reference
	gosqlxtesting.AssertTables(t, windowQuery, []string{"employees"})

	// Verify columns (note: window functions are not extracted as columns)
	gosqlxtesting.AssertColumns(t, windowQuery, []string{"name", "salary"})
}

// Example_cteQueries demonstrates testing Common Table Expression queries.
func Example_cteQueries() {
	t := &testing.T{}

	// CTE query
	cteQuery := `
		WITH active_users AS (
			SELECT id, name FROM users WHERE active = true
		)
		SELECT name FROM active_users
	`

	// Validate CTE syntax
	gosqlxtesting.RequireValidSQL(t, cteQuery)

	// Verify table reference (only actual tables, not CTEs)
	gosqlxtesting.AssertTables(t, cteQuery, []string{"users"})
}

// Example_joinQueries demonstrates testing various JOIN types.
func Example_joinQueries() {
	t := &testing.T{}

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
			name:   "LEFT JOIN",
			query:  "SELECT * FROM users u LEFT JOIN orders o ON u.id = o.user_id",
			tables: []string{"users", "orders"},
		},
		{
			name:   "RIGHT JOIN",
			query:  "SELECT * FROM users u RIGHT JOIN orders o ON u.id = o.user_id",
			tables: []string{"users", "orders"},
		},
		{
			name: "Multiple JOINs",
			query: `SELECT * FROM users u
					JOIN orders o ON u.id = o.user_id
					JOIN products p ON o.product_id = p.id`,
			tables: []string{"users", "orders", "products"},
		},
	}

	for _, tc := range testCases {
		// Validate each query type
		gosqlxtesting.RequireValidSQL(t, tc.query)
		gosqlxtesting.AssertTables(t, tc.query, tc.tables)
	}
}

// Example_dmlStatements demonstrates testing DML operations.
func Example_dmlStatements() {
	t := &testing.T{}

	// INSERT statement
	insertSQL := "INSERT INTO users (id, name, email) VALUES (1, 'John', 'john@example.com')"
	gosqlxtesting.RequireValidSQL(t, insertSQL)
	gosqlxtesting.AssertTables(t, insertSQL, []string{"users"})
	gosqlxtesting.AssertParsesTo(t, insertSQL, &ast.InsertStatement{})

	// UPDATE statement
	updateSQL := "UPDATE users SET name = 'Jane' WHERE id = 1"
	gosqlxtesting.RequireValidSQL(t, updateSQL)
	gosqlxtesting.AssertTables(t, updateSQL, []string{"users"})
	gosqlxtesting.AssertParsesTo(t, updateSQL, &ast.UpdateStatement{})

	// DELETE statement
	deleteSQL := "DELETE FROM users WHERE inactive = true"
	gosqlxtesting.RequireValidSQL(t, deleteSQL)
	gosqlxtesting.AssertTables(t, deleteSQL, []string{"users"})
	gosqlxtesting.AssertParsesTo(t, deleteSQL, &ast.DeleteStatement{})
}
