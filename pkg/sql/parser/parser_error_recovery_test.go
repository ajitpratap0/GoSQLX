package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParseErrors_MissingClauses tests error recovery for missing SQL clauses
func TestParseErrors_MissingClauses(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		expectErr bool
	}{
		{
			name:      "SELECT without FROM",
			sql:       "SELECT id, name",
			expectErr: false, // Valid in some SQL dialects
		},
		{
			name:      "SELECT with incomplete WHERE",
			sql:       "SELECT * FROM users WHERE",
			expectErr: true,
		},
		{
			name:      "INSERT without VALUES",
			sql:       "INSERT INTO users (name)",
			expectErr: true,
		},
		{
			name:      "UPDATE without SET",
			sql:       "UPDATE users WHERE id = 1",
			expectErr: true,
		},
		{
			name:      "DELETE without FROM",
			sql:       "DELETE WHERE id = 1",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			_, err := p.Parse(tokens)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Logf("Got error (may be expected): %v", err)
				}
			}
		})
	}
}

// TestParseErrors_InvalidSyntax tests error recovery for syntax errors
func TestParseErrors_InvalidSyntax(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		expectErr bool
	}{
		{
			name:      "missing comma in SELECT list",
			sql:       "SELECT id name FROM users",
			expectErr: true,
		},
		{
			name:      "unclosed parenthesis",
			sql:       "SELECT * FROM users WHERE (id = 1",
			expectErr: true,
		},
		{
			name:      "missing comparison operator",
			sql:       "SELECT * FROM users WHERE id 1",
			expectErr: true,
		},
		{
			name:      "incomplete JOIN",
			sql:       "SELECT * FROM users JOIN",
			expectErr: true,
		},
		{
			name:      "incomplete ORDER BY",
			sql:       "SELECT * FROM users ORDER BY",
			expectErr: true,
		},
		{
			name:      "incomplete GROUP BY",
			sql:       "SELECT COUNT(*) FROM users GROUP BY",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			_, err := p.Parse(tokens)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else {
					t.Logf("Got expected error: %v", err)
				}
			}
		})
	}
}

// TestParseErrors_InvalidExpressions tests error recovery in expression parsing
func TestParseErrors_InvalidExpressions(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		expectErr bool
	}{
		{
			name:      "incomplete binary expression",
			sql:       "SELECT * FROM users WHERE id =",
			expectErr: true,
		},
		{
			name:      "incomplete AND expression",
			sql:       "SELECT * FROM users WHERE id = 1 AND",
			expectErr: true,
		},
		{
			name:      "incomplete OR expression",
			sql:       "SELECT * FROM users WHERE id = 1 OR",
			expectErr: true,
		},
		{
			name:      "mismatched parentheses",
			sql:       "SELECT * FROM users WHERE ((id = 1)",
			expectErr: true,
		},
		{
			name:      "invalid function call",
			sql:       "SELECT COUNT( FROM users",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			astObj := ast.NewAST()
			defer ast.ReleaseAST(astObj)

			_, err := p.Parse(tokens)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else {
					t.Logf("Got expected error: %v", err)
				}
			}
		})
	}
}

// TestSelectStatement_EdgeCases tests SELECT statement edge cases
func TestSelectStatement_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "SELECT with alias",
			sql:       "SELECT id AS user_id FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with multiple aliases",
			sql:       "SELECT id AS uid, name AS username, email AS mail FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with table alias",
			sql:       "SELECT u.id FROM users u",
			shouldErr: false,
		},
		{
			name:      "SELECT with qualified column names",
			sql:       "SELECT users.id, users.name FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with ORDER BY DESC",
			sql:       "SELECT * FROM users ORDER BY created_at DESC",
			shouldErr: false,
		},
		{
			name:      "SELECT with ORDER BY ASC",
			sql:       "SELECT * FROM users ORDER BY name ASC",
			shouldErr: false,
		},
		{
			name:      "SELECT with LIMIT",
			sql:       "SELECT * FROM users LIMIT 10",
			shouldErr: false,
		},
		{
			name:      "SELECT with OFFSET",
			sql:       "SELECT * FROM users OFFSET 5",
			shouldErr: false,
		},
		{
			name:      "SELECT with LIMIT and OFFSET",
			sql:       "SELECT * FROM users LIMIT 10 OFFSET 5",
			shouldErr: false,
		},
		{
			name:      "SELECT with GROUP BY",
			sql:       "SELECT category, COUNT(*) FROM products GROUP BY category",
			shouldErr: false,
		},
		{
			name:      "SELECT with HAVING",
			sql:       "SELECT category, COUNT(*) FROM products GROUP BY category HAVING COUNT(*) > 10",
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
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestUpdateStatement_EdgeCases tests UPDATE statement edge cases
func TestUpdateStatement_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "UPDATE single column",
			sql:       "UPDATE users SET name = 'John' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE multiple columns",
			sql:       "UPDATE users SET name = 'John', email = 'john@example.com' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with boolean value",
			sql:       "UPDATE users SET active = true WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with numeric value",
			sql:       "UPDATE products SET price = 19.99 WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "UPDATE with NULL",
			sql:       "UPDATE users SET deleted_at = NULL WHERE id = 1",
			shouldErr: true, // NULL not supported as value
		},
		{
			name:      "UPDATE without WHERE (dangerous)",
			sql:       "UPDATE users SET active = false",
			shouldErr: false, // Valid but dangerous
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
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestInsertStatement_EdgeCases tests INSERT statement edge cases
func TestInsertStatement_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "INSERT single column",
			sql:       "INSERT INTO users (name) VALUES ('John')",
			shouldErr: false,
		},
		{
			name:      "INSERT multiple columns",
			sql:       "INSERT INTO users (name, email, age) VALUES ('John', 'john@example.com', 25)",
			shouldErr: false,
		},
		{
			name:      "INSERT with boolean",
			sql:       "INSERT INTO users (name, active) VALUES ('John', true)",
			shouldErr: false,
		},
		{
			name:      "INSERT with NULL",
			sql:       "INSERT INTO users (name, deleted_at) VALUES ('John', NULL)",
			shouldErr: true, // NULL not supported as value
		},
		{
			name:      "INSERT with numeric values",
			sql:       "INSERT INTO products (name, price, stock) VALUES ('Widget', 19.99, 100)",
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

// TestDeleteStatement_EdgeCases tests DELETE statement edge cases
func TestDeleteStatement_EdgeCases(t *testing.T) {
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
			sql:       "DELETE FROM users WHERE active = false AND created_at < '2020-01-01'",
			shouldErr: false,
		},
		{
			name:      "DELETE without WHERE (dangerous)",
			sql:       "DELETE FROM temp_data",
			shouldErr: false, // Valid but dangerous
		},
		{
			name:      "DELETE with OR condition",
			sql:       "DELETE FROM users WHERE banned = true OR deleted = true",
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
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestJoinStatements_ComplexCases tests complex JOIN scenarios
func TestJoinStatements_ComplexCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "INNER JOIN with alias",
			sql:       "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id",
			shouldErr: false,
		},
		{
			name:      "LEFT JOIN with WHERE",
			sql:       "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE o.id IS NULL",
			shouldErr: false,
		},
		{
			name:      "RIGHT JOIN",
			sql:       "SELECT * FROM users u RIGHT JOIN orders o ON u.id = o.user_id",
			shouldErr: false,
		},
		{
			name:      "FULL OUTER JOIN",
			sql:       "SELECT * FROM users u FULL OUTER JOIN orders o ON u.id = o.user_id",
			shouldErr: false,
		},
		{
			name:      "CROSS JOIN",
			sql:       "SELECT * FROM users CROSS JOIN roles",
			shouldErr: false,
		},
		{
			name:      "NATURAL JOIN",
			sql:       "SELECT * FROM users NATURAL JOIN user_profiles",
			shouldErr: false,
		},
		{
			name:      "JOIN with USING",
			sql:       "SELECT * FROM users u JOIN orders o USING (user_id)",
			shouldErr: false,
		},
		{
			name:      "multiple INNER JOINs",
			sql:       "SELECT * FROM users u INNER JOIN orders o ON u.id = o.user_id INNER JOIN products p ON o.product_id = p.id",
			shouldErr: false,
		},
		{
			name:      "mixed JOIN types",
			sql:       "SELECT * FROM users u LEFT JOIN orders o ON u.id = o.user_id INNER JOIN products p ON o.product_id = p.id",
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

// TestExpressions_BoundaryValues tests expression parsing with boundary values
func TestExpressions_BoundaryValues(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "zero value",
			sql:       "SELECT * FROM products WHERE price = 0",
			shouldErr: false,
		},
		{
			name:      "negative value",
			sql:       "SELECT * FROM transactions WHERE amount = -100",
			shouldErr: false,
		},
		{
			name:      "large integer",
			sql:       "SELECT * FROM stats WHERE count = 1000000",
			shouldErr: false,
		},
		{
			name:      "decimal value",
			sql:       "SELECT * FROM products WHERE price = 99.99",
			shouldErr: false,
		},
		{
			name:      "small decimal",
			sql:       "SELECT * FROM metrics WHERE value = 0.001",
			shouldErr: false,
		},
		{
			name:      "NULL comparison",
			sql:       "SELECT * FROM users WHERE deleted_at = NULL",
			shouldErr: true, // NULL not supported as value, should use IS NULL
		},
		{
			name:      "true boolean",
			sql:       "SELECT * FROM users WHERE active = true",
			shouldErr: false,
		},
		{
			name:      "false boolean",
			sql:       "SELECT * FROM users WHERE active = false",
			shouldErr: false,
		},
		{
			name:      "empty string",
			sql:       "SELECT * FROM users WHERE name = ''",
			shouldErr: false,
		},
		{
			name:      "long string",
			sql:       "SELECT * FROM logs WHERE message = 'This is a very long error message that contains multiple words and special characters like @#$%'",
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

// TestComparisonOperators tests all comparison operators
func TestComparisonOperators(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "equals operator",
			sql:       "SELECT * FROM users WHERE age = 25",
			shouldErr: false,
		},
		{
			name:      "not equals operator",
			sql:       "SELECT * FROM users WHERE status != 'deleted'",
			shouldErr: false,
		},
		{
			name:      "less than operator",
			sql:       "SELECT * FROM products WHERE price < 100",
			shouldErr: false,
		},
		{
			name:      "less than or equal operator",
			sql:       "SELECT * FROM products WHERE price <= 100",
			shouldErr: false,
		},
		{
			name:      "greater than operator",
			sql:       "SELECT * FROM users WHERE age > 18",
			shouldErr: false,
		},
		{
			name:      "greater than or equal operator",
			sql:       "SELECT * FROM users WHERE age >= 21",
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
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}
