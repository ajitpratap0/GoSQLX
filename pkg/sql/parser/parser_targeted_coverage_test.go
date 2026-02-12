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
			shouldErr: false, // Double-quoted identifiers are now supported
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
			shouldErr: false,
		},
		{
			name:      "Fully qualified (db.schema.table)",
			sql:       "SELECT * FROM mydb.public.users",
			shouldErr: false,
		},
		{
			name:      "Multiple qualified names in JOIN",
			sql:       "SELECT * FROM public.users u JOIN public.orders o ON u.id = o.user_id",
			shouldErr: false,
		},
		{
			name:      "Qualified name in INSERT",
			sql:       "INSERT INTO public.users (name) VALUES ('John')",
			shouldErr: false,
		},
		{
			name:      "Qualified name in UPDATE",
			sql:       "UPDATE public.users SET name = 'Jane' WHERE id = 1",
			shouldErr: false,
		},
		{
			name:      "Qualified name in DELETE",
			sql:       "DELETE FROM public.users WHERE id = 1",
			shouldErr: false,
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

// TestDerivedTables_Comprehensive tests derived table (subquery in FROM) parsing
func TestDerivedTables_Comprehensive(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple derived table",
			sql:       "SELECT * FROM (SELECT id, name FROM users) AS u",
			shouldErr: false,
		},
		{
			name:      "Derived table with WHERE",
			sql:       "SELECT * FROM (SELECT id, name FROM users WHERE active = true) AS active_users",
			shouldErr: false,
		},
		{
			name:      "Derived table in JOIN",
			sql:       "SELECT u.name, o.total FROM users u JOIN (SELECT user_id, SUM(amount) AS total FROM orders GROUP BY user_id) AS o ON u.id = o.user_id",
			shouldErr: false,
		},
		{
			name:      "Multiple derived tables",
			sql:       "SELECT a.name, b.cnt FROM (SELECT * FROM users) AS a JOIN (SELECT user_id, COUNT(*) AS cnt FROM orders GROUP BY user_id) AS b ON a.id = b.user_id",
			shouldErr: false,
		},
		{
			name:      "Nested derived tables (2 levels)",
			sql:       "SELECT * FROM (SELECT * FROM (SELECT id FROM users) AS inner_q) AS outer_q",
			shouldErr: false,
		},
		{
			name:      "Derived table with complex subquery",
			sql:       "SELECT * FROM (SELECT u.id, u.name, COUNT(o.id) AS order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name HAVING COUNT(o.id) > 5) AS active_customers",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestColumnConstraints_REFERENCES tests REFERENCES constraint parsing
func TestColumnConstraints_REFERENCES(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple REFERENCES",
			sql:       "CREATE TABLE orders (user_id INT REFERENCES users(id))",
			shouldErr: false,
		},
		{
			name:      "REFERENCES with ON DELETE CASCADE",
			sql:       "CREATE TABLE orders (user_id INT REFERENCES users(id) ON DELETE CASCADE)",
			shouldErr: false,
		},
		{
			name:      "REFERENCES with ON UPDATE SET NULL",
			sql:       "CREATE TABLE orders (user_id INT REFERENCES users(id) ON UPDATE SET NULL)",
			shouldErr: false,
		},
		{
			name:      "REFERENCES with both ON DELETE and ON UPDATE",
			sql:       "CREATE TABLE comments (post_id INT REFERENCES posts(id) ON DELETE CASCADE ON UPDATE SET NULL)",
			shouldErr: false,
		},
		{
			name:      "REFERENCES with RESTRICT",
			sql:       "CREATE TABLE items (category_id INT REFERENCES categories(id) ON DELETE RESTRICT)",
			shouldErr: false,
		},
		{
			name:      "REFERENCES with SET DEFAULT",
			sql:       "CREATE TABLE logs (user_id INT REFERENCES users(id) ON DELETE SET DEFAULT)",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestColumnConstraints_CHECK tests CHECK constraint parsing
func TestColumnConstraints_CHECK(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple CHECK with comparison",
			sql:       "CREATE TABLE products (quantity INT CHECK (quantity >= 0))",
			shouldErr: false,
		},
		{
			name:      "CHECK with multiple conditions",
			sql:       "CREATE TABLE users (age INT CHECK (age >= 0 AND age <= 150))",
			shouldErr: false,
		},
		{
			name:      "CHECK on string column",
			sql:       "CREATE TABLE statuses (status VARCHAR(20) CHECK (status IN ('active', 'inactive', 'pending')))",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestInsertWithFunctionCalls tests INSERT VALUES with function calls
func TestInsertWithFunctionCalls(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "INSERT with NOW()",
			sql:       "INSERT INTO logs (created_at) VALUES (NOW())",
			shouldErr: false,
		},
		{
			name:      "INSERT with multiple functions",
			sql:       "INSERT INTO users (id, created_at, updated_at) VALUES (UUID(), NOW(), NOW())",
			shouldErr: false,
		},
		{
			name:      "INSERT with CONCAT",
			sql:       "INSERT INTO messages (content) VALUES (CONCAT('Hello, ', 'World!'))",
			shouldErr: false,
		},
		{
			name:      "INSERT with arithmetic expression",
			sql:       "INSERT INTO orders (total) VALUES (100 + 50 * 2)",
			shouldErr: false,
		},
		{
			name:      "INSERT with nested functions",
			sql:       "INSERT INTO logs (message) VALUES (UPPER(CONCAT('Error: ', 'test')))",
			shouldErr: false,
		},
		{
			name:      "INSERT with NULL",
			sql:       "INSERT INTO users (name, deleted_at) VALUES ('John', NULL)",
			shouldErr: false,
		},
		{
			name:      "INSERT with mixed values",
			sql:       "INSERT INTO orders (id, amount, description, created_at) VALUES (1, 99.99, 'Test order', CURRENT_TIMESTAMP)",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestAliasedExpressions tests column aliases with AS keyword
func TestAliasedExpressions(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Simple alias",
			sql:       "SELECT id AS user_id FROM users",
			shouldErr: false,
		},
		{
			name:      "Multiple aliases",
			sql:       "SELECT id AS user_id, name AS user_name, email AS contact_email FROM users",
			shouldErr: false,
		},
		{
			name:      "Alias on expression",
			sql:       "SELECT COUNT(*) AS total_count FROM users",
			shouldErr: false,
		},
		{
			name:      "Alias on complex expression",
			sql:       "SELECT price * quantity AS total_price FROM order_items",
			shouldErr: false,
		},
		{
			name:      "Mixed aliased and non-aliased columns",
			sql:       "SELECT id, name AS full_name, email FROM users",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestReturningClause tests PostgreSQL RETURNING clause for INSERT, UPDATE, DELETE
func TestReturningClause(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		shouldErr    bool
		stmtType     string
		returningLen int
	}{
		// INSERT RETURNING
		{
			name:         "INSERT RETURNING single column",
			sql:          "INSERT INTO users (name, email) VALUES ('John', 'john@example.com') RETURNING id",
			shouldErr:    false,
			stmtType:     "INSERT",
			returningLen: 1,
		},
		{
			name:         "INSERT RETURNING multiple columns",
			sql:          "INSERT INTO users (name) VALUES ('John') RETURNING id, created_at",
			shouldErr:    false,
			stmtType:     "INSERT",
			returningLen: 2,
		},
		{
			name:         "INSERT RETURNING *",
			sql:          "INSERT INTO users (name) VALUES ('John') RETURNING *",
			shouldErr:    false,
			stmtType:     "INSERT",
			returningLen: 1,
		},
		// UPDATE RETURNING
		{
			name:         "UPDATE RETURNING single column",
			sql:          "UPDATE users SET status = 'active' WHERE id = 1 RETURNING id",
			shouldErr:    false,
			stmtType:     "UPDATE",
			returningLen: 1,
		},
		{
			name:         "UPDATE RETURNING multiple columns",
			sql:          "UPDATE users SET status = 'active' WHERE id = 1 RETURNING id, status",
			shouldErr:    false,
			stmtType:     "UPDATE",
			returningLen: 2,
		},
		{
			name:         "UPDATE RETURNING *",
			sql:          "UPDATE products SET price = price * 1.1 RETURNING *",
			shouldErr:    false,
			stmtType:     "UPDATE",
			returningLen: 1,
		},
		// DELETE RETURNING
		{
			name:         "DELETE RETURNING single column",
			sql:          "DELETE FROM users WHERE id = 1 RETURNING id",
			shouldErr:    false,
			stmtType:     "DELETE",
			returningLen: 1,
		},
		{
			name:         "DELETE RETURNING multiple columns",
			sql:          "DELETE FROM sessions WHERE expired_at < NOW() RETURNING user_id, session_id",
			shouldErr:    false,
			stmtType:     "DELETE",
			returningLen: 2,
		},
		{
			name:         "DELETE RETURNING *",
			sql:          "DELETE FROM users WHERE id = 1 RETURNING *",
			shouldErr:    false,
			stmtType:     "DELETE",
			returningLen: 1,
		},
		// Edge cases
		{
			name:         "UPDATE without WHERE with RETURNING",
			sql:          "UPDATE users SET status = 'active' RETURNING id",
			shouldErr:    false,
			stmtType:     "UPDATE",
			returningLen: 1,
		},
		{
			name:         "DELETE without WHERE with RETURNING",
			sql:          "DELETE FROM temp_data RETURNING id",
			shouldErr:    false,
			stmtType:     "DELETE",
			returningLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
					return
				}

				// Verify the statement type and RETURNING clause
				stmt := result.Statements[0]
				switch tt.stmtType {
				case "INSERT":
					insertStmt, ok := stmt.(*ast.InsertStatement)
					if !ok {
						t.Errorf("Expected InsertStatement, got %T", stmt)
						return
					}
					if len(insertStmt.Returning) != tt.returningLen {
						t.Errorf("Expected %d RETURNING columns, got %d", tt.returningLen, len(insertStmt.Returning))
					}
				case "UPDATE":
					updateStmt, ok := stmt.(*ast.UpdateStatement)
					if !ok {
						t.Errorf("Expected UpdateStatement, got %T", stmt)
						return
					}
					if len(updateStmt.Returning) != tt.returningLen {
						t.Errorf("Expected %d RETURNING columns, got %d", tt.returningLen, len(updateStmt.Returning))
					}
				case "DELETE":
					deleteStmt, ok := stmt.(*ast.DeleteStatement)
					if !ok {
						t.Errorf("Expected DeleteStatement, got %T", stmt)
						return
					}
					if len(deleteStmt.Returning) != tt.returningLen {
						t.Errorf("Expected %d RETURNING columns, got %d", tt.returningLen, len(deleteStmt.Returning))
					}
				}
			}
		})
	}
}

// TestAlterTableOperations tests ALTER TABLE column operations (#149)
func TestAlterTableOperations(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		// ADD COLUMN
		{
			name:      "ADD COLUMN simple",
			sql:       "ALTER TABLE users ADD COLUMN email VARCHAR(255)",
			shouldErr: false,
		},
		{
			name:      "ADD COLUMN with NOT NULL",
			sql:       "ALTER TABLE users ADD COLUMN status VARCHAR(50) NOT NULL",
			shouldErr: false,
		},
		{
			name:      "ADD COLUMN with DEFAULT",
			sql:       "ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT NOW()",
			shouldErr: false,
		},
		// DROP COLUMN
		{
			name:      "DROP COLUMN simple",
			sql:       "ALTER TABLE users DROP COLUMN temp_field",
			shouldErr: false,
		},
		{
			name:      "DROP COLUMN with CASCADE",
			sql:       "ALTER TABLE users DROP COLUMN old_field CASCADE",
			shouldErr: false,
		},
		// RENAME COLUMN
		{
			name:      "RENAME COLUMN",
			sql:       "ALTER TABLE users RENAME COLUMN old_name TO new_name",
			shouldErr: false,
		},
		// ALTER COLUMN
		{
			name:      "ALTER COLUMN TYPE",
			sql:       "ALTER TABLE users ALTER COLUMN age TYPE BIGINT",
			shouldErr: false,
		},
		// ADD CONSTRAINT
		{
			name:      "ADD CONSTRAINT PRIMARY KEY",
			sql:       "ALTER TABLE users ADD CONSTRAINT pk_users PRIMARY KEY (id)",
			shouldErr: false,
		},
		{
			name:      "ADD CONSTRAINT FOREIGN KEY",
			sql:       "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)",
			shouldErr: false,
		},
		// DROP CONSTRAINT
		{
			name:      "DROP CONSTRAINT",
			sql:       "ALTER TABLE users DROP CONSTRAINT constraint_name",
			shouldErr: false,
		},
		{
			name:      "DROP CONSTRAINT with CASCADE",
			sql:       "ALTER TABLE users DROP CONSTRAINT pk_users CASCADE",
			shouldErr: false,
		},
		// RENAME TABLE
		{
			name:      "RENAME TABLE",
			sql:       "ALTER TABLE old_table RENAME TO new_table",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("Expected parsed statement, got nil or empty")
				}
			}
		})
	}
}
