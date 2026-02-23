package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestMySQLLimitOffsetSyntax tests MySQL-style LIMIT offset, count
func TestMySQLLimitOffsetSyntax(t *testing.T) {
	tests := []struct {
		name       string
		sql        string
		wantLimit  int
		wantOffset int
	}{
		{
			name:       "LIMIT offset, count",
			sql:        "SELECT * FROM posts LIMIT 10, 20",
			wantLimit:  20,
			wantOffset: 10,
		},
		{
			name:       "LIMIT count only",
			sql:        "SELECT * FROM posts LIMIT 5",
			wantLimit:  5,
			wantOffset: 0,
		},
		{
			name:       "LIMIT with ORDER BY",
			sql:        "SELECT * FROM posts ORDER BY id DESC LIMIT 0, 50",
			wantLimit:  50,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseWithDialect(tt.sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
			if len(result.Statements) == 0 {
				t.Fatal("expected at least one statement")
			}
			sel, ok := result.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", result.Statements[0])
			}
			if sel.Limit == nil {
				t.Fatal("expected non-nil Limit")
			}
			if *sel.Limit != tt.wantLimit {
				t.Errorf("Limit = %d, want %d", *sel.Limit, tt.wantLimit)
			}
			if tt.wantOffset > 0 {
				if sel.Offset == nil {
					t.Fatal("expected non-nil Offset")
				}
				if *sel.Offset != tt.wantOffset {
					t.Errorf("Offset = %d, want %d", *sel.Offset, tt.wantOffset)
				}
			}
		})
	}
}

// TestMySQLOnDuplicateKeyUpdate tests ON DUPLICATE KEY UPDATE parsing
func TestMySQLOnDuplicateKeyUpdate(t *testing.T) {
	sql := `INSERT INTO user_stats (user_id, login_count) VALUES (1, 1)
		ON DUPLICATE KEY UPDATE login_count = login_count + 1`

	result, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}
	if stmt.OnDuplicateKey == nil {
		t.Fatal("expected non-nil OnDuplicateKey")
	}
	if len(stmt.OnDuplicateKey.Updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(stmt.OnDuplicateKey.Updates))
	}
	col, ok := stmt.OnDuplicateKey.Updates[0].Column.(*ast.Identifier)
	if !ok || col.Name != "login_count" {
		t.Errorf("expected column login_count, got %v", stmt.OnDuplicateKey.Updates[0].Column)
	}
}

// TestMySQLBacktickIdentifiers tests backtick-quoted identifiers
func TestMySQLBacktickIdentifiers(t *testing.T) {
	tests := []string{
		"SELECT `id`, `name` FROM `users`",
		"SELECT `tbl`.`col` FROM `mydb`.`tbl`",
		"SELECT `select` FROM `from`",
	}

	for _, sql := range tests {
		t.Run(sql, func(t *testing.T) {
			_, err := ParseWithDialect(sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
		})
	}
}

// TestMySQLShowStatements tests SHOW command parsing
func TestMySQLShowStatements(t *testing.T) {
	tests := []struct {
		sql      string
		showType string
		objName  string
	}{
		{"SHOW TABLES", "TABLES", ""},
		{"SHOW DATABASES", "DATABASES", ""},
		{"SHOW CREATE TABLE users", "CREATE TABLE", "users"},
	}

	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			result, err := ParseWithDialect(tt.sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
			show, ok := result.Statements[0].(*ast.ShowStatement)
			if !ok {
				t.Fatalf("expected ShowStatement, got %T", result.Statements[0])
			}
			if show.ShowType != tt.showType {
				t.Errorf("ShowType = %q, want %q", show.ShowType, tt.showType)
			}
			if tt.objName != "" && show.ObjectName != tt.objName {
				t.Errorf("ObjectName = %q, want %q", show.ObjectName, tt.objName)
			}
		})
	}
}

// TestMySQLDescribeStatement tests DESCRIBE command parsing
func TestMySQLDescribeStatement(t *testing.T) {
	tests := []string{
		"DESCRIBE users",
		"DESCRIBE schema1.users",
	}

	for _, sql := range tests {
		t.Run(sql, func(t *testing.T) {
			result, err := ParseWithDialect(sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
			desc, ok := result.Statements[0].(*ast.DescribeStatement)
			if !ok {
				t.Fatalf("expected DescribeStatement, got %T", result.Statements[0])
			}
			if desc.TableName == "" {
				t.Error("expected non-empty TableName")
			}
		})
	}
}

// TestMySQLReplaceInto tests REPLACE INTO parsing
func TestMySQLReplaceInto(t *testing.T) {
	sql := "REPLACE INTO cache (key_name, value) VALUES ('k1', 'v1')"

	result, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.ReplaceStatement)
	if !ok {
		t.Fatalf("expected ReplaceStatement, got %T", result.Statements[0])
	}
	if stmt.TableName != "cache" {
		t.Errorf("TableName = %q, want cache", stmt.TableName)
	}
	if len(stmt.Columns) != 2 {
		t.Errorf("expected 2 columns, got %d", len(stmt.Columns))
	}
	if len(stmt.Values) != 1 {
		t.Errorf("expected 1 value row, got %d", len(stmt.Values))
	}
}

// TestMySQLUpdateWithLimit tests UPDATE ... LIMIT
func TestMySQLUpdateWithLimit(t *testing.T) {
	sql := "UPDATE users SET active = 0 WHERE last_login < '2024-01-01' LIMIT 100"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLDeleteWithLimit tests DELETE ... LIMIT
func TestMySQLDeleteWithLimit(t *testing.T) {
	sql := "DELETE FROM logs WHERE created_at < '2024-01-01' LIMIT 1000"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLIntervalNumericSyntax tests INTERVAL 1 DAY style
func TestMySQLIntervalNumericSyntax(t *testing.T) {
	sql := "SELECT DATE_ADD(NOW(), INTERVAL 30 DAY) FROM dual"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLIFFunction tests IF() function
func TestMySQLIFFunction(t *testing.T) {
	sql := "SELECT IF(salary > 50000, 'High', 'Low') FROM employees"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLGroupConcat tests GROUP_CONCAT with SEPARATOR
func TestMySQLGroupConcat(t *testing.T) {
	sql := "SELECT GROUP_CONCAT(name ORDER BY name SEPARATOR ', ') FROM users GROUP BY dept"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLMatchAgainst tests MATCH AGAINST full-text search
func TestMySQLMatchAgainst(t *testing.T) {
	sql := "SELECT * FROM articles WHERE MATCH(title, content) AGAINST('search term' IN NATURAL LANGUAGE MODE)"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLRegexp tests REGEXP operator
func TestMySQLRegexp(t *testing.T) {
	sql := "SELECT * FROM users WHERE email REGEXP '^[a-z]+@[a-z]+$'"
	_, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
}

// TestMySQLTestdataIntegration runs all 30 MySQL test files
func TestMySQLTestdataIntegration(t *testing.T) {
	files, err := filepath.Glob("../../../testdata/mysql/*.sql")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Skip("no MySQL test files found")
	}

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}
			lines := strings.Split(string(data), "\n")
			var sqlLines []string
			for _, l := range lines {
				trimmed := strings.TrimSpace(l)
				if trimmed == "" || strings.HasPrefix(trimmed, "--") {
					continue
				}
				sqlLines = append(sqlLines, l)
			}
			sql := strings.Join(sqlLines, "\n")
			_, err = ParseWithDialect(sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("ParseWithDialect failed: %v", err)
			}
		})
	}
}
