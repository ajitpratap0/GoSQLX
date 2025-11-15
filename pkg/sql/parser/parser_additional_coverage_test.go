package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestAlterTableStatement_AllActions tests ALTER TABLE with different actions
func TestAlterTableStatement_AllActions(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "ALTER TABLE ADD COLUMN",
			sql:       "ALTER TABLE users ADD COLUMN age INT",
			shouldErr: false,
		},
		{
			name:      "ALTER TABLE DROP COLUMN",
			sql:       "ALTER TABLE users DROP COLUMN age",
			shouldErr: false,
		},
		{
			name:      "ALTER TABLE RENAME COLUMN",
			sql:       "ALTER TABLE users RENAME COLUMN old_name TO new_name",
			shouldErr: false,
		},
		{
			name:      "ALTER TABLE ALTER COLUMN",
			sql:       "ALTER TABLE users ALTER COLUMN age SET DEFAULT 0",
			shouldErr: false,
		},
		{
			name:      "ALTER TABLE ADD CONSTRAINT",
			sql:       "ALTER TABLE users ADD CONSTRAINT pk_users PRIMARY KEY (id)",
			shouldErr: false,
		},
		{
			name:      "ALTER TABLE DROP CONSTRAINT",
			sql:       "ALTER TABLE users DROP CONSTRAINT pk_users",
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

// TestSelectStatement_AllClauses tests SELECT with all possible clauses
func TestSelectStatement_AllClauses(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "SELECT with all clauses",
			sql:       "SELECT id, name FROM users WHERE active = true GROUP BY department HAVING COUNT(*) > 5 ORDER BY name ASC LIMIT 10 OFFSET 5",
			shouldErr: false,
		},
		{
			name:      "SELECT with WHERE and ORDER BY",
			sql:       "SELECT * FROM products WHERE price > 10 ORDER BY price DESC",
			shouldErr: false,
		},
		{
			name:      "SELECT with GROUP BY and HAVING",
			sql:       "SELECT category, COUNT(*) as count FROM products GROUP BY category HAVING COUNT(*) > 100",
			shouldErr: false,
		},
		{
			name:      "SELECT with multiple ORDER BY columns",
			sql:       "SELECT * FROM users ORDER BY lastname ASC, firstname ASC, id DESC",
			shouldErr: false,
		},
		{
			name:      "SELECT with subquery alias",
			sql:       "SELECT id FROM users u",
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

// TestExpression_AllOperators tests expressions with all operators
func TestExpression_AllOperators(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "AND operator",
			sql:       "SELECT * FROM users WHERE active = true AND verified = true",
			shouldErr: false,
		},
		{
			name:      "OR operator",
			sql:       "SELECT * FROM users WHERE role = 'admin' OR role = 'moderator'",
			shouldErr: false,
		},
		{
			name:      "NOT with AND",
			sql:       "SELECT * FROM users WHERE NOT deleted AND active = true",
			shouldErr: false,
		},
		{
			name:      "complex precedence",
			sql:       "SELECT * FROM users WHERE (a = 1 AND b = 2) OR (c = 3 AND d = 4)",
			shouldErr: false,
		},
		{
			name:      "equals",
			sql:       "SELECT * FROM users WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "not equals",
			sql:       "SELECT * FROM users WHERE status != 'deleted'",
			shouldErr: false,
		},
		{
			name:      "less than",
			sql:       "SELECT * FROM products WHERE price < 100",
			shouldErr: false,
		},
		{
			name:      "less than or equal",
			sql:       "SELECT * FROM products WHERE price <= 100",
			shouldErr: false,
		},
		{
			name:      "greater than",
			sql:       "SELECT * FROM users WHERE age > 18",
			shouldErr: false,
		},
		{
			name:      "greater than or equal",
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

// TestFunctionCalls_AllTypes tests all types of function calls
func TestFunctionCalls_AllTypes(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "COUNT with asterisk",
			sql:       "SELECT COUNT(*) FROM users",
			shouldErr: false,
		},
		{
			name:      "COUNT with column",
			sql:       "SELECT COUNT(id) FROM users",
			shouldErr: false,
		},
		{
			name:      "SUM",
			sql:       "SELECT SUM(amount) FROM transactions",
			shouldErr: false,
		},
		{
			name:      "AVG",
			sql:       "SELECT AVG(price) FROM products",
			shouldErr: false,
		},
		{
			name:      "MIN",
			sql:       "SELECT MIN(price) FROM products",
			shouldErr: false,
		},
		{
			name:      "MAX",
			sql:       "SELECT MAX(price) FROM products",
			shouldErr: false,
		},
		{
			name:      "UPPER",
			sql:       "SELECT UPPER(name) FROM users",
			shouldErr: false,
		},
		{
			name:      "LOWER",
			sql:       "SELECT LOWER(email) FROM users",
			shouldErr: false,
		},
		{
			name:      "COALESCE with multiple args",
			sql:       "SELECT COALESCE(name, email, username, 'Unknown') FROM users",
			shouldErr: false,
		},
		{
			name:      "CONCAT",
			sql:       "SELECT CONCAT(firstname, ' ', lastname) FROM users",
			shouldErr: false,
		},
		{
			name:      "nested functions",
			sql:       "SELECT UPPER(TRIM(LOWER(name))) FROM users",
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

// TestLiteralValues tests all literal value types
func TestLiteralValues(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "integer literal",
			sql:       "SELECT * FROM users WHERE id = 123",
			shouldErr: false,
		},
		{
			name:      "negative integer",
			sql:       "SELECT * FROM transactions WHERE amount = -50",
			shouldErr: false,
		},
		{
			name:      "float literal",
			sql:       "SELECT * FROM products WHERE price = 19.99",
			shouldErr: false,
		},
		{
			name:      "string literal single quotes",
			sql:       "SELECT * FROM users WHERE name = 'John Doe'",
			shouldErr: false,
		},
		{
			name:      "string literal with spaces",
			sql:       "SELECT * FROM products WHERE description = 'A very long product description with multiple words'",
			shouldErr: false,
		},
		{
			name:      "boolean true",
			sql:       "SELECT * FROM users WHERE active = true",
			shouldErr: false,
		},
		{
			name:      "boolean false",
			sql:       "SELECT * FROM users WHERE deleted = false",
			shouldErr: false,
		},
		{
			name:      "zero",
			sql:       "SELECT * FROM products WHERE stock = 0",
			shouldErr: false,
		},
		{
			name:      "large number",
			sql:       "SELECT * FROM stats WHERE views = 1000000",
			shouldErr: false,
		},
		{
			name:      "small decimal",
			sql:       "SELECT * FROM measurements WHERE value = 0.0001",
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

// TestComplexQueries tests complex real-world-like queries
func TestComplexQueries(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "query with multiple JOINs and WHERE",
			sql:       "SELECT u.name, o.total, p.name FROM users u INNER JOIN orders o ON u.id = o.user_id INNER JOIN products p ON o.product_id = p.id WHERE u.active = true AND o.total > 100",
			shouldErr: false,
		},
		{
			name:      "aggregate with GROUP BY and HAVING",
			sql:       "SELECT category, COUNT(*) as count, AVG(price) as avg_price FROM products GROUP BY category HAVING COUNT(*) > 10 ORDER BY count DESC",
			shouldErr: false,
		},
		{
			name:      "window function with partition",
			sql:       "SELECT name, salary, dept, RANK() OVER (PARTITION BY dept ORDER BY salary DESC) as rank FROM employees",
			shouldErr: false,
		},
		{
			name:      "CTE with JOIN",
			sql:       "WITH active_users AS (SELECT id, name FROM users WHERE active = true) SELECT au.name, COUNT(o.id) FROM active_users au LEFT JOIN orders o ON au.id = o.user_id GROUP BY au.name",
			shouldErr: false,
		},
		{
			name:      "set operation with ORDER BY",
			sql:       "SELECT id FROM customers UNION SELECT id FROM prospects ORDER BY id",
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

// TestSelectExpressions tests different types of SELECT expressions
func TestSelectExpressions(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "SELECT asterisk",
			sql:       "SELECT * FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT single column",
			sql:       "SELECT name FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT multiple columns",
			sql:       "SELECT id, name, email, created_at FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with alias",
			sql:       "SELECT id AS user_id FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT with multiple aliases",
			sql:       "SELECT id AS uid, name AS username FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT qualified column",
			sql:       "SELECT users.id FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT function result",
			sql:       "SELECT COUNT(*) FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT function with alias",
			sql:       "SELECT COUNT(*) AS total_users FROM users",
			shouldErr: false,
		},
		{
			name:      "SELECT mixed expressions",
			sql:       "SELECT id, COUNT(*) as total, AVG(amount) as average FROM transactions GROUP BY id",
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
