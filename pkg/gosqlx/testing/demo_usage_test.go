package testing_test

import (
	"testing"

	gosqlxtesting "github.com/ajitpratap0/GoSQLX/pkg/gosqlx/testing"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Demo: Basic SQL validation in tests
func TestDemo_BasicValidation(t *testing.T) {
	// Test that valid SQL is recognized
	gosqlxtesting.AssertValidSQL(t, "SELECT * FROM users")
	gosqlxtesting.AssertValidSQL(t, "INSERT INTO users (name) VALUES ('Alice')")
	gosqlxtesting.AssertValidSQL(t, "UPDATE users SET active = true WHERE id = 1")
	gosqlxtesting.AssertValidSQL(t, "DELETE FROM users WHERE inactive = true")

	// Test that invalid SQL is detected
	gosqlxtesting.AssertInvalidSQL(t, "SELECT FROM WHERE")
	gosqlxtesting.AssertInvalidSQL(t, "INSERT INTO")
	gosqlxtesting.AssertInvalidSQL(t, "UPDATE SET name = 'test'")
}

// Demo: Testing table references
func TestDemo_TableExtraction(t *testing.T) {
	// Simple single table
	gosqlxtesting.AssertTables(t,
		"SELECT * FROM users",
		[]string{"users"})

	// JOIN with multiple tables
	gosqlxtesting.AssertTables(t,
		"SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
		[]string{"users", "orders"})

	// Complex multi-table query
	gosqlxtesting.AssertTables(t,
		`SELECT u.name, o.total, p.name
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		RIGHT JOIN products p ON o.product_id = p.id`,
		[]string{"users", "orders", "products"})

	// DML statements
	gosqlxtesting.AssertTables(t, "INSERT INTO users (name) VALUES ('Bob')", []string{"users"})
	gosqlxtesting.AssertTables(t, "UPDATE orders SET status = 'shipped'", []string{"orders"})
	gosqlxtesting.AssertTables(t, "DELETE FROM temp_data", []string{"temp_data"})
}

// Demo: Testing column selection
func TestDemo_ColumnExtraction(t *testing.T) {
	// Simple column list
	gosqlxtesting.AssertColumns(t,
		"SELECT id, name, email FROM users",
		[]string{"id", "name", "email"})

	// Order doesn't matter
	gosqlxtesting.AssertColumns(t,
		"SELECT email, id, name FROM users",
		[]string{"name", "email", "id"})

	// Columns from function calls
	gosqlxtesting.AssertColumns(t,
		"SELECT COUNT(id), MAX(salary) FROM employees",
		[]string{"id", "salary"})

	// Wildcard select (no columns extracted)
	gosqlxtesting.AssertColumns(t,
		"SELECT * FROM users",
		[]string{})
}

// Demo: Testing statement types
func TestDemo_StatementTypes(t *testing.T) {
	// Verify SELECT statement
	gosqlxtesting.AssertParsesTo(t,
		"SELECT * FROM users WHERE active = true",
		&ast.SelectStatement{})

	// Verify INSERT statement
	gosqlxtesting.AssertParsesTo(t,
		"INSERT INTO users (id, name) VALUES (1, 'Charlie')",
		&ast.InsertStatement{})

	// Verify UPDATE statement
	gosqlxtesting.AssertParsesTo(t,
		"UPDATE users SET email = 'new@example.com' WHERE id = 1",
		&ast.UpdateStatement{})

	// Verify DELETE statement
	gosqlxtesting.AssertParsesTo(t,
		"DELETE FROM users WHERE created_at < '2020-01-01'",
		&ast.DeleteStatement{})
}

// Demo: Testing error conditions
func TestDemo_ErrorTesting(t *testing.T) {
	// Test that specific errors are produced
	gosqlxtesting.AssertErrorContains(t,
		"SELECT FROM WHERE",
		"parsing")

	gosqlxtesting.AssertErrorContains(t,
		"INVALID SYNTAX HERE",
		"parsing")
}

// Demo: Using RequireParse for custom assertions
func TestDemo_CustomAssertions(t *testing.T) {
	sql := "SELECT id, name, email FROM users WHERE active = true"

	// Parse and get AST
	astNode := gosqlxtesting.RequireParse(t, sql)

	// Custom assertions on the AST
	if len(astNode.Statements) == 0 {
		t.Fatal("Expected at least one statement")
	}

	selectStmt, ok := astNode.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astNode.Statements[0])
	}

	// Assert on specific AST properties
	if len(selectStmt.Columns) != 3 {
		t.Errorf("Expected 3 columns, got %d", len(selectStmt.Columns))
	}

	if selectStmt.Where == nil {
		t.Error("Expected WHERE clause to be present")
	}
}

// Demo: Table-driven tests with testing helpers
func TestDemo_TableDrivenTests(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		shouldBeValid bool
		tables        []string
	}{
		{
			name:          "Simple SELECT",
			sql:           "SELECT * FROM users",
			shouldBeValid: true,
			tables:        []string{"users"},
		},
		{
			name:          "JOIN query",
			sql:           "SELECT * FROM users u JOIN orders o ON u.id = o.user_id",
			shouldBeValid: true,
			tables:        []string{"users", "orders"},
		},
		{
			name:          "Invalid syntax",
			sql:           "SELECT FROM WHERE",
			shouldBeValid: false,
			tables:        nil,
		},
		{
			name:          "UPDATE statement",
			sql:           "UPDATE products SET price = 100 WHERE id = 1",
			shouldBeValid: true,
			tables:        []string{"products"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldBeValid {
				gosqlxtesting.RequireValidSQL(t, tt.sql)
				if tt.tables != nil {
					gosqlxtesting.AssertTables(t, tt.sql, tt.tables)
				}
			} else {
				gosqlxtesting.AssertInvalidSQL(t, tt.sql)
			}
		})
	}
}

// Demo: Testing window functions
func TestDemo_WindowFunctions(t *testing.T) {
	windowQuery := `
		SELECT
			employee_id,
			department,
			salary,
			ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as dept_rank,
			AVG(salary) OVER (PARTITION BY department) as dept_avg_salary
		FROM employees
	`

	// Validate window function syntax
	gosqlxtesting.RequireValidSQL(t, windowQuery)

	// Check tables
	gosqlxtesting.AssertTables(t, windowQuery, []string{"employees"})

	// Check columns (window functions themselves are not extracted as regular columns)
	gosqlxtesting.AssertColumns(t, windowQuery, []string{"employee_id", "department", "salary"})

	// Verify it's a SELECT statement
	gosqlxtesting.AssertParsesTo(t, windowQuery, &ast.SelectStatement{})
}

// Demo: Testing CTEs (Common Table Expressions)
func TestDemo_CTEs(t *testing.T) {
	cteQuery := `
		WITH active_users AS (
			SELECT id, name, email FROM users WHERE active = true
		)
		SELECT name FROM active_users
	`

	// Validate CTE syntax
	gosqlxtesting.RequireValidSQL(t, cteQuery)

	// Check that actual tables (not CTEs) are extracted
	// Note: Currently CTEs are also extracted as tables
	gosqlxtesting.AssertTables(t, cteQuery, []string{"users", "active_users"})
}

// Demo: Testing set operations
func TestDemo_SetOperations(t *testing.T) {
	// UNION
	unionQuery := "SELECT id, name FROM users UNION SELECT id, name FROM admins"
	gosqlxtesting.RequireValidSQL(t, unionQuery)
	gosqlxtesting.AssertTables(t, unionQuery, []string{"users", "admins"})

	// UNION ALL
	unionAllQuery := "SELECT * FROM products UNION ALL SELECT * FROM archived_products"
	gosqlxtesting.RequireValidSQL(t, unionAllQuery)
	gosqlxtesting.AssertTables(t, unionAllQuery, []string{"products", "archived_products"})
}

// Demo: Application test - User management queries
func TestDemo_UserManagementApp(t *testing.T) {
	t.Run("GetActiveUsers", func(t *testing.T) {
		query := "SELECT id, name, email, created_at FROM users WHERE active = true ORDER BY created_at DESC"

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"users"})
		gosqlxtesting.AssertColumns(t, query, []string{"id", "name", "email", "created_at"})
		gosqlxtesting.AssertParsesTo(t, query, &ast.SelectStatement{})
	})

	t.Run("CreateUser", func(t *testing.T) {
		query := "INSERT INTO users (name, email) VALUES ('Diana', 'diana@example.com')"

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"users"})
		gosqlxtesting.AssertParsesTo(t, query, &ast.InsertStatement{})
	})

	t.Run("UpdateUserEmail", func(t *testing.T) {
		query := "UPDATE users SET email = 'newemail@example.com', updated_at = CURRENT_TIMESTAMP WHERE id = 123"

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"users"})
		gosqlxtesting.AssertParsesTo(t, query, &ast.UpdateStatement{})
	})

	t.Run("DeleteInactiveUsers", func(t *testing.T) {
		query := "DELETE FROM users WHERE active = false AND last_login < '2022-01-01'"

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"users"})
		gosqlxtesting.AssertParsesTo(t, query, &ast.DeleteStatement{})
	})
}

// Demo: Application test - Order analytics queries
func TestDemo_OrderAnalyticsApp(t *testing.T) {
	t.Run("OrdersByUser", func(t *testing.T) {
		query := `
			SELECT
				u.id,
				u.name,
				COUNT(o.id) as order_count,
				SUM(o.total) as total_spent
			FROM users u
			LEFT JOIN orders o ON u.id = o.user_id
			GROUP BY u.id, u.name
			ORDER BY total_spent DESC
		`

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"users", "orders"})
	})

	t.Run("TopSellingProducts", func(t *testing.T) {
		query := `
			SELECT
				p.id,
				p.name,
				COUNT(oi.id) as times_ordered,
				RANK() OVER (ORDER BY COUNT(oi.id) DESC) as popularity_rank
			FROM products p
			JOIN order_items oi ON p.id = oi.product_id
			GROUP BY p.id, p.name
		`

		gosqlxtesting.RequireValidSQL(t, query)
		gosqlxtesting.AssertTables(t, query, []string{"products", "order_items"})
		gosqlxtesting.AssertColumns(t, query, []string{"id", "name"})
	})
}
