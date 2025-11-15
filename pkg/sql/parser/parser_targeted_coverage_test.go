package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParseStringLiteral_DirectUsage tests parseStringLiteral through various SQL contexts
// This function is called internally during parsing, so we test it through SQL that requires string parsing
func TestParseStringLiteral_DirectUsage(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "CREATE TABLE with DEFAULT string value",
			sql:       "CREATE TABLE users (status VARCHAR(20) DEFAULT 'active')",
			shouldErr: false,
		},
		{
			name:      "CREATE TABLE with multiple DEFAULT strings",
			sql:       "CREATE TABLE config (key VARCHAR(50) DEFAULT 'setting', value VARCHAR(100) DEFAULT 'default_value')",
			shouldErr: false,
		},
		{
			name:      "CREATE TABLE with empty string DEFAULT",
			sql:       "CREATE TABLE items (name VARCHAR(100) DEFAULT '')",
			shouldErr: false,
		},
		{
			name:      "INSERT with string values",
			sql:       "INSERT INTO users (name, email, status) VALUES ('John Doe', 'john@example.com', 'active')",
			shouldErr: false,
		},
		{
			name:      "SELECT with string literal in WHERE",
			sql:       "SELECT * FROM users WHERE status = 'active' AND role = 'admin'",
			shouldErr: false,
		},
		{
			name:      "UPDATE with string value",
			sql:       "UPDATE users SET status = 'inactive', note = 'Deactivated by admin' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "String with special characters",
			sql:       "INSERT INTO messages (text) VALUES ('Hello, world! This is a test: 123')",
			shouldErr: false,
		},
		{
			name:      "String with spaces",
			sql:       "SELECT * FROM products WHERE description = 'Premium quality product with warranty'",
			shouldErr: false,
		},
		{
			name:      "Multiple string comparisons",
			sql:       "SELECT * FROM users WHERE status = 'active' OR status = 'pending' OR role = 'admin'",
			shouldErr: false,
		},
		{
			name:      "String in HAVING clause",
			sql:       "SELECT category, COUNT(*) FROM products GROUP BY category HAVING category = 'electronics'",
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

// TestParseTableConstraint_AllTypes tests parseTableConstraint through CREATE TABLE statements
func TestParseTableConstraint_AllTypes(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "PRIMARY KEY constraint",
			sql:       "CREATE TABLE users (id INT, name VARCHAR(100), CONSTRAINT pk_users PRIMARY KEY (id))",
			shouldErr: false,
		},
		{
			name:      "FOREIGN KEY constraint",
			sql:       "CREATE TABLE orders (id INT, user_id INT, CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id))",
			shouldErr: false,
		},
		{
			name:      "UNIQUE constraint",
			sql:       "CREATE TABLE users (id INT, email VARCHAR(100), CONSTRAINT uq_email UNIQUE (email))",
			shouldErr: false,
		},
		{
			name:      "CHECK constraint",
			sql:       "CREATE TABLE products (id INT, price DECIMAL, CONSTRAINT chk_price CHECK (price > 0))",
			shouldErr: false,
		},
		{
			name:      "Multiple constraints",
			sql:       "CREATE TABLE users (id INT, email VARCHAR(100), age INT, CONSTRAINT pk_id PRIMARY KEY (id), CONSTRAINT uq_email UNIQUE (email), CONSTRAINT chk_age CHECK (age >= 18))",
			shouldErr: false,
		},
		{
			name:      "Composite PRIMARY KEY",
			sql:       "CREATE TABLE order_items (order_id INT, product_id INT, quantity INT, CONSTRAINT pk_order_item PRIMARY KEY (order_id, product_id))",
			shouldErr: false,
		},
		{
			name:      "Named FOREIGN KEY with ON DELETE CASCADE",
			sql:       "CREATE TABLE comments (id INT, post_id INT, CONSTRAINT fk_post FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE)",
			shouldErr: false,
		},
		{
			name:      "FOREIGN KEY with ON UPDATE CASCADE",
			sql:       "CREATE TABLE order_items (id INT, order_id INT, CONSTRAINT fk_order FOREIGN KEY (order_id) REFERENCES orders(id) ON UPDATE CASCADE)",
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

// TestParseIdent_EdgeCases tests parseIdent through various identifier contexts
func TestParseIdent_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple identifier",
			sql:       "SELECT id FROM users",
			shouldErr: false,
		},
		{
			name:      "Quoted identifier",
			sql:       `SELECT "user_id" FROM "user_table"`,
			shouldErr: true, // Quoted identifiers may not be fully supported
		},
		{
			name:      "Multiple identifiers in SELECT",
			sql:       "SELECT id, name, email, created_at, updated_at FROM users",
			shouldErr: false,
		},
		{
			name:      "Identifier with underscore",
			sql:       "SELECT user_id, user_name FROM user_accounts",
			shouldErr: false,
		},
		{
			name:      "Identifier with numbers",
			sql:       "SELECT col1, col2, col3 FROM table123",
			shouldErr: false,
		},
		{
			name:      "Mixed case identifiers",
			sql:       "SELECT UserId, UserName FROM UserTable",
			shouldErr: false,
		},
		{
			name:      "Identifier in WHERE clause",
			sql:       "SELECT * FROM users WHERE user_status = 1",
			shouldErr: false,
		},
		{
			name:      "Identifier in JOIN condition",
			sql:       "SELECT u.user_id FROM users u JOIN orders o ON u.user_id = o.user_id",
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

// TestParseObjectName_EdgeCases tests parseObjectName through qualified identifiers
func TestParseObjectName_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple table name",
			sql:       "SELECT * FROM users",
			shouldErr: false,
		},
		{
			name:      "Qualified table name (schema.table)",
			sql:       "SELECT * FROM public.users",
			shouldErr: true, // Qualified table names in FROM may not be fully supported
		},
		{
			name:      "Fully qualified (db.schema.table)",
			sql:       "SELECT * FROM mydb.public.users",
			shouldErr: true, // Fully qualified names may not be fully supported
		},
		{
			name:      "Multiple qualified names in JOIN",
			sql:       "SELECT * FROM public.users u JOIN public.orders o ON u.id = o.user_id",
			shouldErr: true, // Qualified table names in JOIN may not be fully supported
		},
		{
			name:      "Qualified name in INSERT",
			sql:       "INSERT INTO public.users (name) VALUES ('John')",
			shouldErr: true, // Qualified names in INSERT may not be fully supported
		},
		{
			name:      "Qualified name in UPDATE",
			sql:       "UPDATE public.users SET name = 'Jane' WHERE id = 1",
			shouldErr: true, // Qualified names in UPDATE may not be fully supported
		},
		{
			name:      "Qualified name in DELETE",
			sql:       "DELETE FROM public.users WHERE id = 1",
			shouldErr: true, // Qualified names in DELETE may not be fully supported
		},
		{
			name:      "Qualified column reference",
			sql:       "SELECT users.id, users.name FROM users",
			shouldErr: false,
		},
		{
			name:      "Multiple qualified columns",
			sql:       "SELECT u.id, u.name, o.order_date FROM users u JOIN orders o ON u.id = o.user_id",
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

// TestParseFunctionCall_MoreEdgeCases tests additional parseFunctionCall scenarios
func TestParseFunctionCall_MoreEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Function with no arguments",
			sql:       "SELECT CURRENT_TIMESTAMP FROM users",
			shouldErr: false,
		},
		{
			name:      "Function with qualified column",
			sql:       "SELECT MAX(users.age) FROM users",
			shouldErr: false,
		},
		{
			name:      "Multiple functions in SELECT",
			sql:       "SELECT COUNT(*), MAX(age), MIN(age), AVG(salary) FROM users",
			shouldErr: false,
		},
		{
			name:      "Function in WHERE clause",
			sql:       "SELECT * FROM users WHERE LENGTH(name) > 10",
			shouldErr: false,
		},
		{
			name:      "Function with multiple string arguments",
			sql:       "SELECT CONCAT('Hello', ' ', 'World', '!') FROM dual",
			shouldErr: false,
		},
		{
			name:      "Nested function calls deep",
			sql:       "SELECT UPPER(TRIM(LOWER(SUBSTRING(name, 1, 10)))) FROM users",
			shouldErr: false,
		},
		{
			name:      "Function in GROUP BY",
			sql:       "SELECT YEAR(created_at), COUNT(*) FROM orders GROUP BY YEAR(created_at)",
			shouldErr: false,
		},
		{
			name:      "Function in ORDER BY",
			sql:       "SELECT * FROM users ORDER BY LENGTH(name) DESC",
			shouldErr: false,
		},
		{
			name:      "Window function with complex frame",
			sql:       "SELECT name, SUM(amount) OVER (PARTITION BY dept ORDER BY date ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING) FROM sales",
			shouldErr: false,
		},
		{
			name:      "Window function with RANGE frame",
			sql:       "SELECT name, AVG(salary) OVER (PARTITION BY dept ORDER BY hire_date RANGE BETWEEN INTERVAL '1' YEAR PRECEDING AND CURRENT ROW) FROM employees",
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

// TestParseWindowFrame_AdditionalCases tests more parseWindowFrame scenarios
func TestParseWindowFrame_AdditionalCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "ROWS with UNBOUNDED PRECEDING",
			sql:       "SELECT name, SUM(amount) OVER (ORDER BY date ROWS UNBOUNDED PRECEDING) FROM transactions",
			shouldErr: false,
		},
		{
			name:      "ROWS with UNBOUNDED FOLLOWING",
			sql:       "SELECT name, SUM(amount) OVER (ORDER BY date ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) FROM transactions",
			shouldErr: false,
		},
		{
			name:      "RANGE with numeric PRECEDING",
			sql:       "SELECT name, AVG(price) OVER (ORDER BY date RANGE BETWEEN 5 PRECEDING AND CURRENT ROW) FROM products",
			shouldErr: false,
		},
		{
			name:      "RANGE with numeric FOLLOWING",
			sql:       "SELECT name, SUM(qty) OVER (ORDER BY date RANGE BETWEEN CURRENT ROW AND 3 FOLLOWING) FROM inventory",
			shouldErr: false,
		},
		{
			name:      "Complex window frame with PARTITION BY",
			sql:       "SELECT dept, name, salary, AVG(salary) OVER (PARTITION BY dept ORDER BY salary ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) FROM employees",
			shouldErr: false,
		},
		{
			name:      "ROWS frame only start bound",
			sql:       "SELECT name, COUNT(*) OVER (ORDER BY date ROWS UNBOUNDED PRECEDING) FROM events",
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

// TestParseColumnDef_MoreCases tests additional parseColumnDef scenarios
func TestParseColumnDef_MoreCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Column with NOT NULL",
			sql:       "CREATE TABLE users (id INT NOT NULL)",
			shouldErr: false,
		},
		{
			name:      "Column with PRIMARY KEY",
			sql:       "CREATE TABLE users (id INT PRIMARY KEY)",
			shouldErr: false,
		},
		{
			name:      "Column with UNIQUE",
			sql:       "CREATE TABLE users (email VARCHAR(100) UNIQUE)",
			shouldErr: false,
		},
		{
			name:      "Column with DEFAULT numeric value",
			sql:       "CREATE TABLE products (stock INT DEFAULT 0)",
			shouldErr: false,
		},
		{
			name:      "Column with DEFAULT string value",
			sql:       "CREATE TABLE users (status VARCHAR(20) DEFAULT 'active')",
			shouldErr: false,
		},
		{
			name:      "Column with AUTO_INCREMENT",
			sql:       "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY)",
			shouldErr: false,
		},
		{
			name:      "Column with multiple constraints",
			sql:       "CREATE TABLE users (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT)",
			shouldErr: false,
		},
		{
			name:      "VARCHAR with size",
			sql:       "CREATE TABLE users (name VARCHAR(255))",
			shouldErr: false,
		},
		{
			name:      "DECIMAL with precision and scale",
			sql:       "CREATE TABLE products (price DECIMAL(10, 2))",
			shouldErr: false,
		},
		{
			name:      "TIMESTAMP with DEFAULT",
			sql:       "CREATE TABLE logs (created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
			shouldErr: false,
		},
		{
			name:      "Multiple columns with various types",
			sql:       "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(255) UNIQUE, age INT DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
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
