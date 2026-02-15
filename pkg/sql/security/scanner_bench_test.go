package security

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQL is a helper function to parse SQL and return the AST
func parseSQL(b *testing.B, sql string) *ast.AST {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		b.Fatalf("Failed to tokenize: %v", err)
	}

	p := parser.NewParser()
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		b.Fatalf("Failed to parse: %v", err)
	}
	return tree
}

// BenchmarkScanner_CleanSQL benchmarks scanning clean SQL
func BenchmarkScanner_CleanSQL(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC"
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

// BenchmarkScanner_CleanSQL_Raw benchmarks scanning raw SQL string
func BenchmarkScanner_CleanSQL_Raw(b *testing.B) {
	sql := "SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC"
	scanner := NewScanner()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sql)
	}
}

// BenchmarkScanner_TautologyDetection benchmarks tautology pattern detection
func BenchmarkScanner_TautologyDetection(b *testing.B) {
	sqls := []string{
		"SELECT * FROM users WHERE 1=1",
		"SELECT * FROM users WHERE 'a'='a'",
		"SELECT * FROM users WHERE id=id",
	}
	scanner := NewScanner()

	// Parse all SQL queries
	trees := make([]*ast.AST, len(sqls))
	for i, sql := range sqls {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			b.Fatalf("Failed to tokenize: %v", err)
		}

		p := parser.NewParser()
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Failed to parse: %v", err)
		}
		trees[i] = tree
	}

	// Cleanup
	defer func() {
		for _, tree := range trees {
			ast.ReleaseAST(tree)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(trees[i%len(trees)])
	}
}

// BenchmarkScanner_UnionInjection benchmarks UNION-based injection detection
func BenchmarkScanner_UnionInjection(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1 UNION SELECT null, username, password FROM admin_users"
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

// BenchmarkScanner_CommentBypass benchmarks comment-based bypass detection
func BenchmarkScanner_CommentBypass(b *testing.B) {
	sqls := []string{
		"SELECT * FROM users WHERE id = 1 -- AND password = 'x'",
		"SELECT * FROM users WHERE id = 1 /* comment */ OR 1=1",
		"SELECT * FROM users # comment",
	}
	scanner := NewScanner()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sqls[i%len(sqls)])
	}
}

// BenchmarkScanner_DangerousFunctions benchmarks dangerous function detection
func BenchmarkScanner_DangerousFunctions(b *testing.B) {
	sqls := []string{
		"EXEC sp_executesql @sql",
		"SELECT LOAD_FILE('/etc/passwd')",
		"SELECT * FROM users; xp_cmdshell 'dir'",
	}
	scanner := NewScanner()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sqls[i%len(sqls)])
	}
}

// BenchmarkScanner_ComplexQuery benchmarks scanning complex SQL queries
func BenchmarkScanner_ComplexQuery(b *testing.B) {
	sql := `
		SELECT
			u.id, u.name, u.email,
			o.order_id, o.total,
			p.product_name
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		INNER JOIN products p ON o.product_id = p.id
		WHERE u.active = true
			AND o.order_date > '2023-01-01'
			AND p.category IN ('electronics', 'books')
		ORDER BY o.order_date DESC
		LIMIT 100
	`
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

// BenchmarkScanner_LargeQuery benchmarks scanning large SQL queries
func BenchmarkScanner_LargeQuery(b *testing.B) {
	// Generate a large query with many columns
	sql := generateLargeSelectQuery(100) // 100 columns
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

// BenchmarkScanner_Parallel benchmarks concurrent scanning
func BenchmarkScanner_Parallel(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1 OR 1=1"

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		scanner := NewScanner()
		for pb.Next() {
			scanner.Scan(tree)
		}
	})
}

// BenchmarkScanner_ParallelRawSQL benchmarks concurrent raw SQL scanning
func BenchmarkScanner_ParallelRawSQL(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1 -- OR 1=1"

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		scanner := NewScanner()
		for pb.Next() {
			scanner.ScanSQL(sql)
		}
	})
}

// BenchmarkScanner_MultipleStatements benchmarks scanning multiple statements
func BenchmarkScanner_MultipleStatements(b *testing.B) {
	sqls := []string{
		"SELECT * FROM users WHERE id = 1",
		"UPDATE users SET name = 'test' WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"INSERT INTO users (name, email) VALUES ('test', 'test@example.com')",
	}
	scanner := NewScanner()

	// Parse all SQL queries
	trees := make([]*ast.AST, len(sqls))
	for i, sql := range sqls {
		tkz := tokenizer.GetTokenizer()
		tokens, err := tkz.Tokenize([]byte(sql))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			b.Fatalf("Failed to tokenize: %v", err)
		}

		p := parser.NewParser()
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Failed to parse: %v", err)
		}
		trees[i] = tree
	}

	// Cleanup
	defer func() {
		for _, tree := range trees {
			ast.ReleaseAST(tree)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(trees[i%len(trees)])
	}
}

// BenchmarkScanner_WithSeverityFilter benchmarks scanning with severity filtering
func BenchmarkScanner_WithSeverityFilter(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1 OR 1=1 -- comment"

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	severities := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

	for _, severity := range severities {
		b.Run(string(severity), func(b *testing.B) {
			scanner, err := NewScannerWithSeverity(severity)
			if err != nil {
				b.Fatalf("Failed to create scanner: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanner.Scan(tree)
			}
		})
	}
}

// BenchmarkScanner_TimeBasedInjection benchmarks time-based injection detection
func BenchmarkScanner_TimeBasedInjection(b *testing.B) {
	sqls := []string{
		"SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
		"SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'",
		"SELECT * FROM users WHERE id = 1 AND pg_sleep(5)",
	}
	scanner := NewScanner()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sqls[i%len(sqls)])
	}
}

// BenchmarkScanner_OutOfBandInjection benchmarks out-of-band injection detection
func BenchmarkScanner_OutOfBandInjection(b *testing.B) {
	sqls := []string{
		"SELECT LOAD_FILE('/etc/passwd')",
		"SELECT * FROM users INTO OUTFILE '/tmp/users.txt'",
		"EXEC xp_cmdshell 'whoami'",
	}
	scanner := NewScanner()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sqls[i%len(sqls)])
	}
}

// BenchmarkScanner_SystemTableAccess benchmarks system table access detection
func BenchmarkScanner_SystemTableAccess(b *testing.B) {
	sql := "SELECT * FROM users UNION SELECT table_name FROM information_schema.tables"
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

// BenchmarkScanner_MixedPatterns benchmarks detection of multiple injection patterns
func BenchmarkScanner_MixedPatterns(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT null, username, password FROM admin_users -- bypass"
	scanner := NewScanner()

	tree := parseSQL(b, sql)
	defer ast.ReleaseAST(tree)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := scanner.Scan(tree)
		_ = result // Prevent optimization
	}
}

// generateLargeSelectQuery generates a SELECT query with specified number of columns
func generateLargeSelectQuery(columns int) string {
	query := "SELECT "
	for i := 0; i < columns; i++ {
		if i > 0 {
			query += ", "
		}
		query += fmt.Sprintf("col%d", i)
	}
	query += " FROM large_table WHERE active = true"
	return query
}
