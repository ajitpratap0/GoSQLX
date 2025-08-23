package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestSQLCompatibility validates GoSQLX support for various SQL dialects
func TestSQLCompatibility(t *testing.T) {
	testCases := []struct {
		name    string
		dialect string
		sql     string
		wantErr bool
	}{
		// PostgreSQL specific features
		{
			name:    "PostgreSQL array operators",
			dialect: "PostgreSQL",
			sql:     `SELECT * FROM users WHERE tags @> ARRAY['admin']`,
			wantErr: false,
		},
		{
			name:    "PostgreSQL JSON operators",
			dialect: "PostgreSQL",
			sql:     `SELECT data->>'name' FROM users WHERE data @> '{"active": true}'`,
			wantErr: false,
		},
		{
			name:    "PostgreSQL parameter syntax",
			dialect: "PostgreSQL",
			sql:     `SELECT * FROM users WHERE id = @user_id AND status = @status`,
			wantErr: false,
		},

		// MySQL specific features
		{
			name:    "MySQL LIMIT syntax",
			dialect: "MySQL",
			sql:     `SELECT * FROM users LIMIT 10, 20`,
			wantErr: false,
		},
		{
			name:    "MySQL backtick identifiers",
			dialect: "MySQL",
			sql:     "SELECT `user_id`, `name` FROM `users`",
			wantErr: false,
		},

		// SQL Server specific features
		{
			name:    "SQL Server TOP clause",
			dialect: "SQL Server",
			sql:     `SELECT TOP 10 * FROM users`,
			wantErr: false,
		},
		{
			name:    "SQL Server square bracket identifiers",
			dialect: "SQL Server",
			sql:     `SELECT [user_id], [name] FROM [users]`,
			wantErr: false,
		},

		// Oracle specific features
		{
			name:    "Oracle ROWNUM",
			dialect: "Oracle",
			sql:     `SELECT * FROM users WHERE ROWNUM <= 10`,
			wantErr: false,
		},
		{
			name:    "Oracle dual table",
			dialect: "Oracle",
			sql:     `SELECT SYSDATE FROM dual`,
			wantErr: false,
		},

		// SQLite specific features
		{
			name:    "SQLite PRAGMA",
			dialect: "SQLite",
			sql:     `PRAGMA table_info(users)`,
			wantErr: false,
		},

		// Common SQL features across all dialects
		{
			name:    "Basic SELECT with WHERE",
			dialect: "All",
			sql:     `SELECT id, name FROM users WHERE active = true`,
			wantErr: false,
		},
		{
			name:    "JOIN operations",
			dialect: "All",
			sql:     `SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id`,
			wantErr: false,
		},
		{
			name:    "GROUP BY with HAVING",
			dialect: "All",
			sql:     `SELECT department, COUNT(*) FROM users GROUP BY department HAVING COUNT(*) > 5`,
			wantErr: false,
		},
		{
			name:    "INSERT with VALUES",
			dialect: "All",
			sql:     `INSERT INTO users (name, email) VALUES ('John', 'john@example.com')`,
			wantErr: false,
		},
		{
			name:    "UPDATE with WHERE",
			dialect: "All",
			sql:     `UPDATE users SET status = 'active' WHERE last_login > '2024-01-01'`,
			wantErr: false,
		},
		{
			name:    "DELETE with WHERE",
			dialect: "All",
			sql:     `DELETE FROM users WHERE status = 'inactive'`,
			wantErr: false,
		},
		{
			name:    "CREATE TABLE",
			dialect: "All",
			sql: `CREATE TABLE users (
				id INTEGER PRIMARY KEY,
				name VARCHAR(100) NOT NULL,
				email VARCHAR(255) UNIQUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`,
			wantErr: false,
		},
		{
			name:    "ALTER TABLE",
			dialect: "All",
			sql:     `ALTER TABLE users ADD COLUMN phone VARCHAR(20)`,
			wantErr: false,
		},
		{
			name:    "CREATE INDEX",
			dialect: "All",
			sql:     `CREATE INDEX idx_users_email ON users(email)`,
			wantErr: false,
		},
		{
			name:    "DROP TABLE",
			dialect: "All",
			sql:     `DROP TABLE IF EXISTS temp_users`,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			// Tokenize the SQL
			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				if !tc.wantErr {
					t.Errorf("Tokenizer error for %s SQL: %v", tc.dialect, err)
				}
				return
			}

			// Validate we got tokens
			if len(tokens) == 0 {
				t.Errorf("No tokens generated for %s SQL", tc.dialect)
				return
			}

			// For now, successful tokenization is our compatibility check
			// Future: Add parser validation when dialect-specific parsing is implemented
			if tc.wantErr {
				t.Errorf("Expected error for %s SQL but got none", tc.dialect)
			}
		})
	}
}

// TestComplexQueries validates handling of complex real-world queries
func TestComplexQueries(t *testing.T) {
	complexQueries := []string{
		// Complex analytical query
		`WITH monthly_sales AS (
			SELECT 
				DATE_TRUNC('month', order_date) as month,
				SUM(total_amount) as total_sales,
				COUNT(DISTINCT customer_id) as unique_customers
			FROM orders
			WHERE order_date >= '2024-01-01'
			GROUP BY DATE_TRUNC('month', order_date)
		)
		SELECT 
			month,
			total_sales,
			unique_customers,
			LAG(total_sales) OVER (ORDER BY month) as prev_month_sales,
			total_sales - LAG(total_sales) OVER (ORDER BY month) as growth
		FROM monthly_sales
		ORDER BY month DESC`,

		// Multi-table join with subqueries
		`SELECT 
			u.name,
			u.email,
			(SELECT COUNT(*) FROM orders WHERE user_id = u.id) as order_count,
			(SELECT SUM(amount) FROM payments WHERE user_id = u.id) as total_paid
		FROM users u
		LEFT JOIN user_preferences up ON u.id = up.user_id
		WHERE u.created_at >= '2024-01-01'
			AND u.status = 'active'
			AND (up.newsletter = true OR up.newsletter IS NULL)
		ORDER BY order_count DESC
		LIMIT 100`,

		// Complex INSERT with SELECT
		`INSERT INTO user_statistics (user_id, stat_date, total_orders, total_spent, avg_order_value)
		SELECT 
			u.id,
			CURRENT_DATE,
			COUNT(o.id),
			COALESCE(SUM(o.total), 0),
			CASE 
				WHEN COUNT(o.id) > 0 THEN SUM(o.total) / COUNT(o.id)
				ELSE 0
			END
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id AND o.status = 'completed'
		GROUP BY u.id`,
	}

	for i, query := range complexQueries {
		t.Run(string(rune('A'+i))+"_ComplexQuery", func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(query))
			if err != nil {
				t.Errorf("Failed to tokenize complex query: %v", err)
				return
			}

			if len(tokens) < 10 {
				t.Errorf("Complex query generated too few tokens: %d", len(tokens))
			}
		})
	}
}

// TestUnicodeSQL validates international character support
func TestUnicodeSQL(t *testing.T) {
	unicodeQueries := []struct {
		language string
		sql      string
	}{
		{
			language: "Japanese",
			sql:      `SELECT "名前", "年齢" FROM "ユーザー" WHERE "国" = '日本'`,
		},
		{
			language: "Chinese",
			sql:      `SELECT "姓名", "年龄" FROM "用户" WHERE "城市" = '北京'`,
		},
		{
			language: "Russian",
			sql:      `SELECT "имя", "возраст" FROM "пользователи" WHERE "город" = 'Москва'`,
		},
		{
			language: "Arabic",
			sql:      `SELECT "الاسم", "العمر" FROM "المستخدمون" WHERE "المدينة" = 'دبي'`,
		},
		{
			language: "Korean",
			sql:      `SELECT "이름", "나이" FROM "사용자" WHERE "도시" = '서울'`,
		},
		{
			language: "Emoji",
			sql:      `SELECT * FROM users WHERE status = '🚀' AND mood = '😊'`,
		},
	}

	for _, tc := range unicodeQueries {
		t.Run(tc.language, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Errorf("Failed to tokenize %s SQL: %v", tc.language, err)
				return
			}

			if len(tokens) == 0 {
				t.Errorf("No tokens generated for %s SQL", tc.language)
			}
		})
	}
}
