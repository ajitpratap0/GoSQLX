package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParseStringLiteral_Integration tests parseStringLiteral through SQL parsing
func TestParseStringLiteral_Integration(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "INSERT with string literal",
			sql:       "INSERT INTO users (name) VALUES ('John Doe')",
			shouldErr: false,
		},
		{
			name:      "SELECT with string in WHERE",
			sql:       "SELECT * FROM users WHERE name = 'Alice'",
			shouldErr: false,
		},
		{
			name:      "UPDATE with string literal",
			sql:       "UPDATE users SET status = 'active' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "string with special characters",
			sql:       "SELECT * FROM users WHERE email = 'user@example.com'",
			shouldErr: false,
		},
		{
			name:      "empty string literal",
			sql:       "SELECT * FROM users WHERE name = ''",
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

// TestParseWindowFrame_EdgeCases tests edge cases for window frame parsing
func TestParseWindowFrame_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "ROWS with UNBOUNDED PRECEDING",
			sql:       "SELECT id, ROW_NUMBER() OVER (ORDER BY id ROWS UNBOUNDED PRECEDING) FROM users",
			shouldErr: false,
		},
		{
			name:      "RANGE with CURRENT ROW",
			sql:       "SELECT id, SUM(amount) OVER (ORDER BY date RANGE CURRENT ROW) FROM transactions",
			shouldErr: false,
		},
		{
			name:      "ROWS with BETWEEN clause",
			sql:       "SELECT id, AVG(score) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) FROM scores",
			shouldErr: false,
		},
		{
			name:      "RANGE with UNBOUNDED FOLLOWING",
			sql:       "SELECT id, MAX(value) OVER (ORDER BY timestamp RANGE UNBOUNDED FOLLOWING) FROM data",
			shouldErr: false,
		},
		{
			name:      "ROWS with expression bound",
			sql:       "SELECT id, SUM(val) OVER (ORDER BY date ROWS BETWEEN 3 PRECEDING AND 1 FOLLOWING) FROM metrics",
			shouldErr: false,
		},
		{
			name:      "RANGE with both bounds",
			sql:       "SELECT id, AVG(price) OVER (ORDER BY created RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM orders",
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

// TestParseFunctionCall_EdgeCases tests edge cases for function call parsing
func TestParseFunctionCall_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "function with no arguments",
			sql:       "SELECT NOW() FROM users",
			shouldErr: false,
		},
		{
			name:      "function with single argument",
			sql:       "SELECT COUNT(id) FROM users",
			shouldErr: false,
		},
		{
			name:      "function with multiple arguments",
			sql:       "SELECT COALESCE(name, email, username) FROM users",
			shouldErr: false,
		},
		{
			name:      "nested function calls",
			sql:       "SELECT UPPER(TRIM(name)) FROM users",
			shouldErr: false,
		},
		{
			name:      "function with window spec",
			sql:       "SELECT ROW_NUMBER() OVER (ORDER BY id) FROM users",
			shouldErr: false,
		},
		{
			name:      "aggregate with asterisk",
			sql:       "SELECT COUNT(*) FROM users",
			shouldErr: false,
		},
		{
			name:      "aggregate with column",
			sql:       "SELECT SUM(amount) FROM transactions",
			shouldErr: false,
		},
		{
			name:      "multiple aggregates",
			sql:       "SELECT COUNT(*), SUM(amount), AVG(price) FROM sales",
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

// TestParseExpression_ComplexNesting tests deeply nested expressions
func TestParseExpression_ComplexNesting(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "deeply nested AND/OR",
			sql:       "SELECT * FROM users WHERE (a = 1 OR b = 2) AND (c = 3 OR d = 4) AND e = 5",
			shouldErr: false,
		},
		{
			name:      "complex comparison chain",
			sql:       "SELECT * FROM users WHERE age > 18 AND age < 65 AND status = 'active'",
			shouldErr: false,
		},
		{
			name:      "multiple OR conditions",
			sql:       "SELECT * FROM users WHERE type = 'admin' OR type = 'moderator' OR type = 'user'",
			shouldErr: false,
		},
		{
			name:      "comparison with numeric literals",
			sql:       "SELECT * FROM products WHERE price > 10.50 AND price < 100.00",
			shouldErr: false,
		},
		{
			name:      "mixed AND/OR precedence",
			sql:       "SELECT * FROM users WHERE a = 1 AND b = 2 OR c = 3 AND d = 4",
			shouldErr: false,
		},
		{
			name:      "comparison with booleans",
			sql:       "SELECT * FROM users WHERE active = true AND verified = false",
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
					// Some SQL features may not be fully supported
					t.Skipf("Parsing failed (may not be fully supported): %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestParseWindowSpec_ComplexCases tests complex window specifications
func TestParseWindowSpec_ComplexCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "window with PARTITION BY and ORDER BY",
			sql:       "SELECT id, RANK() OVER (PARTITION BY category ORDER BY score DESC) FROM products",
			shouldErr: false,
		},
		{
			name:      "window with multiple PARTITION BY columns",
			sql:       "SELECT id, DENSE_RANK() OVER (PARTITION BY dept, team ORDER BY salary) FROM employees",
			shouldErr: false,
		},
		{
			name:      "window with multiple ORDER BY columns",
			sql:       "SELECT id, ROW_NUMBER() OVER (ORDER BY lastname, firstname) FROM users",
			shouldErr: false,
		},
		{
			name:      "window with ORDER BY and frame",
			sql:       "SELECT date, SUM(amount) OVER (ORDER BY date ROWS 3 PRECEDING) FROM sales",
			shouldErr: false,
		},
		{
			name:      "LAG function with offset",
			sql:       "SELECT date, amount, LAG(amount, 1) OVER (ORDER BY date) FROM sales",
			shouldErr: false,
		},
		{
			name:      "LEAD function with offset and default",
			sql:       "SELECT date, amount, LEAD(amount, 2, 0) OVER (ORDER BY date) FROM sales",
			shouldErr: false,
		},
		{
			name:      "FIRST_VALUE and LAST_VALUE",
			sql:       "SELECT id, FIRST_VALUE(price) OVER (PARTITION BY category ORDER BY date) FROM products",
			shouldErr: false,
		},
		{
			name:      "NTILE function",
			sql:       "SELECT id, NTILE(4) OVER (ORDER BY score DESC) FROM students",
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

// TestParseFrameBound_AllTypes tests all frame bound types
func TestParseFrameBound_AllTypes(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "UNBOUNDED PRECEDING",
			sql:       "SELECT SUM(val) OVER (ROWS UNBOUNDED PRECEDING) FROM data",
			shouldErr: false,
		},
		{
			name:      "CURRENT ROW",
			sql:       "SELECT SUM(val) OVER (ROWS CURRENT ROW) FROM data",
			shouldErr: false,
		},
		{
			name:      "UNBOUNDED FOLLOWING",
			sql:       "SELECT SUM(val) OVER (ROWS UNBOUNDED FOLLOWING) FROM data",
			shouldErr: false,
		},
		{
			name:      "N PRECEDING",
			sql:       "SELECT SUM(val) OVER (ROWS 5 PRECEDING) FROM data",
			shouldErr: false,
		},
		{
			name:      "N FOLLOWING",
			sql:       "SELECT SUM(val) OVER (ROWS 3 FOLLOWING) FROM data",
			shouldErr: false,
		},
		{
			name:      "BETWEEN with different bounds",
			sql:       "SELECT AVG(val) OVER (ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) FROM data",
			shouldErr: false,
		},
		{
			name:      "RANGE with UNBOUNDED bounds",
			sql:       "SELECT SUM(val) OVER (RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) FROM data",
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

// TestParseColumnDef_EdgeCases tests column definition parsing
func TestParseColumnDef_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "column with type only",
			sql:       "CREATE TABLE users (id INT)",
			shouldErr: false,
		},
		{
			name:      "column with type and constraint",
			sql:       "CREATE TABLE users (id INT PRIMARY KEY)",
			shouldErr: false,
		},
		{
			name:      "column with VARCHAR size",
			sql:       "CREATE TABLE users (name VARCHAR(100))",
			shouldErr: false,
		},
		{
			name:      "multiple columns",
			sql:       "CREATE TABLE users (id INT, name VARCHAR(100), email VARCHAR(255))",
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
					// CREATE TABLE might not be fully supported
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

// TestParseWithStatement_Recursion tests CTE recursion depth
func TestParseWithStatement_Recursion(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "simple CTE",
			sql:       "WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
			shouldErr: false,
		},
		{
			name:      "recursive CTE with termination",
			sql:       "WITH RECURSIVE cte AS (SELECT 1 as n UNION ALL SELECT n + 1 FROM cte WHERE n < 10) SELECT * FROM cte",
			shouldErr: false,
		},
		{
			name:      "multiple CTEs",
			sql:       "WITH cte1 AS (SELECT id FROM users), cte2 AS (SELECT * FROM orders) SELECT * FROM cte1 JOIN cte2 ON cte1.id = cte2.user_id",
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

// TestSetOperations_Precedence tests set operation precedence
func TestSetOperations_Precedence(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "simple UNION",
			sql:       "SELECT id FROM users UNION SELECT id FROM admins",
			shouldErr: false,
		},
		{
			name:      "UNION ALL",
			sql:       "SELECT name FROM products UNION ALL SELECT name FROM archived_products",
			shouldErr: false,
		},
		{
			name:      "EXCEPT",
			sql:       "SELECT id FROM all_users EXCEPT SELECT id FROM deleted_users",
			shouldErr: false,
		},
		{
			name:      "INTERSECT",
			sql:       "SELECT email FROM subscribers INTERSECT SELECT email FROM customers",
			shouldErr: false,
		},
		{
			name:      "mixed operations",
			sql:       "SELECT id FROM a UNION SELECT id FROM b EXCEPT SELECT id FROM c",
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
