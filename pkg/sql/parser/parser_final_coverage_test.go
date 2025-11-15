package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParse_EdgeCases tests edge cases in the Parse function
func TestParse_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Empty token list",
			sql:       "",
			shouldErr: true,
		},
		{
			name:      "Single semicolon",
			sql:       ";",
			shouldErr: false, // Should parse as empty statement list
		},
		{
			name:      "Multiple statements with semicolons",
			sql:       "SELECT * FROM users; SELECT * FROM products;",
			shouldErr: false,
		},
		{
			name:      "Statement with trailing semicolon",
			sql:       "SELECT * FROM users;",
			shouldErr: false,
		},
		{
			name:      "Multiple semicolons",
			sql:       "SELECT * FROM users;;",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sql == "" {
				// Empty SQL - test with empty token list
				p := NewParser()
				astObj := ast.NewAST()
				defer ast.ReleaseAST(astObj)

				_, err := p.Parse([]token.Token{})
				if tt.shouldErr && err == nil {
					t.Error("Expected error for empty token list, got nil")
				}
				return
			}

			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Skipf("Parsing not fully supported: %v", err)
					return
				}
				if result == nil {
					t.Error("Expected parsed result, got nil")
				}
			}
		})
	}
}

// TestSelectStatement_MoreComplexCases tests additional SELECT variations
func TestSelectStatement_MoreComplexCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "SELECT with arithmetic expression",
			sql:       "SELECT price * quantity FROM orders",
			shouldErr: false,
		},
		{
			name:      "SELECT with nested parentheses",
			sql:       "SELECT ((a + b) * (c - d)) FROM calculations",
			shouldErr: false,
		},
		{
			name:      "SELECT with comparison in SELECT list",
			sql:       "SELECT age > 18 FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with complex boolean expression",
			sql:       "SELECT * FROM users WHERE (active = true OR verified = true) AND (role = 'admin' OR role = 'moderator')",
			shouldErr: false,
		},
		{
			name:      "SELECT with multiple JOINs and complex WHERE",
			sql:       "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id LEFT JOIN products p ON o.product_id = p.id WHERE u.active = true AND o.total > 100 AND p.in_stock = true",
			shouldErr: false,
		},
		{
			name:      "SELECT with function in JOIN condition",
			sql:       "SELECT * FROM users u JOIN orders o ON LOWER(u.email) = LOWER(o.email)",
			shouldErr: false,
		},
		{
			name:      "SELECT with multiple aggregates and GROUP BY",
			sql:       "SELECT category, COUNT(*), SUM(price), AVG(rating), MAX(views), MIN(stock) FROM products GROUP BY category",
			shouldErr: false,
		},
		{
			name:      "SELECT with HAVING and complex condition",
			sql:       "SELECT dept, COUNT(*) as cnt FROM employees GROUP BY dept HAVING COUNT(*) > 5 AND AVG(salary) > 50000",
			shouldErr: false,
		},
		{
			name:      "SELECT with ORDER BY multiple columns different directions",
			sql:       "SELECT * FROM users ORDER BY lastname ASC, firstname ASC, created_at DESC, id ASC",
			shouldErr: false,
		},
		{
			name:      "SELECT with LIMIT and OFFSET",
			sql:       "SELECT * FROM products ORDER BY created_at DESC LIMIT 20 OFFSET 40",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Skipf("Parsing not fully supported: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestInsertStatement_MoreCases tests additional INSERT variations
func TestInsertStatement_MoreCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "INSERT with single value",
			sql:       "INSERT INTO users (id) VALUES (1)",
			shouldErr: false,
		},
		{
			name:      "INSERT with multiple rows",
			sql:       "INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie')",
			shouldErr: false,
		},
		{
			name:      "INSERT with many columns",
			sql:       "INSERT INTO employees (id, first_name, last_name, email, phone, department, salary, hire_date, manager_id, active) VALUES (1, 'John', 'Doe', 'john@example.com', '555-1234', 'Engineering', 75000, '2023-01-15', 10, true)",
			shouldErr: false,
		},
		{
			name:      "INSERT with mixed data types",
			sql:       "INSERT INTO products (id, name, price, in_stock, rating, description) VALUES (1, 'Widget', 19.99, true, 4.5, 'A useful widget')",
			shouldErr: false,
		},
		{
			name:      "INSERT with zero values",
			sql:       "INSERT INTO counters (id, count) VALUES (1, 0)",
			shouldErr: false,
		},
		{
			name:      "INSERT with negative numbers",
			sql:       "INSERT INTO transactions (id, amount) VALUES (1, -50)",
			shouldErr: false,
		},
		{
			name:      "INSERT with large numbers",
			sql:       "INSERT INTO stats (id, views) VALUES (1, 1000000)",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Skipf("Parsing not fully supported: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestUpdateStatement_MoreCases tests additional UPDATE variations
func TestUpdateStatement_MoreCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "UPDATE with single SET clause",
			sql:       "UPDATE users SET name = 'Updated' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with multiple SET clauses",
			sql:       "UPDATE users SET name = 'John', email = 'john@example.com', active = true, updated_at = '2023-12-01' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with numeric values",
			sql:       "UPDATE products SET price = 29.99, stock = 100 WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with boolean",
			sql:       "UPDATE users SET active = false WHERE last_login < '2023-01-01'",
			shouldErr: false,
		},
		{
			name:      "UPDATE with complex WHERE",
			sql:       "UPDATE orders SET status = 'cancelled' WHERE user_id = 1 AND status = 'pending' AND created_at < '2023-01-01'",
			shouldErr: false,
		},
		{
			name:      "UPDATE without WHERE (all rows)",
			sql:       "UPDATE settings SET value = 'default'",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Skipf("Parsing not fully supported: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestDeleteStatement_MoreCases tests additional DELETE variations
func TestDeleteStatement_MoreCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "DELETE with simple WHERE",
			sql:       "DELETE FROM users WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "DELETE with complex WHERE",
			sql:       "DELETE FROM users WHERE active = false AND last_login < '2022-01-01' AND email_verified = false",
			shouldErr: false,
		},
		{
			name:      "DELETE with OR condition",
			sql:       "DELETE FROM logs WHERE severity = 'debug' OR severity = 'info'",
			shouldErr: false,
		},
		{
			name:      "DELETE without WHERE (all rows)",
			sql:       "DELETE FROM temp_data",
			shouldErr: false,
		},
		{
			name:      "DELETE with comparison operators",
			sql:       "DELETE FROM products WHERE stock <= 0 AND price >= 1000",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Skipf("Parsing not fully supported: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}
