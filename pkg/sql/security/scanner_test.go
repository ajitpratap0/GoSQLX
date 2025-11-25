package security

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.MinSeverity != SeverityLow {
		t.Errorf("expected MinSeverity to be SeverityLow, got %v", scanner.MinSeverity)
	}
}

func TestNewScannerWithSeverity(t *testing.T) {
	scanner, err := NewScannerWithSeverity(SeverityHigh)
	if err != nil {
		t.Fatalf("NewScannerWithSeverity returned error: %v", err)
	}
	if scanner.MinSeverity != SeverityHigh {
		t.Errorf("expected MinSeverity to be SeverityHigh, got %v", scanner.MinSeverity)
	}
}

func TestNewScannerWithSeverity_InvalidSeverity(t *testing.T) {
	scanner, err := NewScannerWithSeverity(Severity("INVALID"))
	if err == nil {
		t.Error("expected error for invalid severity, got nil")
	}
	if scanner != nil {
		t.Error("expected nil scanner for invalid severity")
	}
}

func TestScan_NilAST(t *testing.T) {
	scanner := NewScanner()
	result := scanner.Scan(nil)
	if result == nil {
		t.Fatal("Scan returned nil for nil AST")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for nil AST, got %d", len(result.Findings))
	}
}

func TestScan_EmptyAST(t *testing.T) {
	scanner := NewScanner()
	tree := &ast.AST{Statements: []ast.Statement{}}
	result := scanner.Scan(tree)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for empty AST, got %d", len(result.Findings))
	}
}

func TestScan_Tautology_NumericEquality(t *testing.T) {
	scanner := NewScanner()

	// Create AST with WHERE 1=1
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected at least one critical finding for 1=1 tautology")
	}

	found := false
	for _, f := range result.Findings {
		if f.Pattern == PatternTautology {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TAUTOLOGY pattern to be detected")
	}
}

func TestScan_Tautology_StringEquality(t *testing.T) {
	scanner := NewScanner()

	// Create AST with WHERE 'a'='a' using LiteralValue type
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "a", Type: "STRING"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "a", Type: "STRING"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected at least one critical finding for 'a'='a' tautology")
	}
}

func TestScan_Tautology_IdentifierEquality(t *testing.T) {
	scanner := NewScanner()

	// Create AST with WHERE col=col
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "col"},
			Operator: "=",
			Right:    &ast.Identifier{Name: "col"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected at least one critical finding for col=col tautology")
	}
}

func TestScan_OrTautology(t *testing.T) {
	scanner := NewScanner()

	// Create AST with WHERE username='admin' OR 1=1
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "username"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "admin", Type: "STRING"},
			},
			Operator: "OR",
			Right: &ast.BinaryExpression{
				Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount < 2 {
		t.Errorf("expected at least 2 critical findings for OR 1=1, got %d", result.CriticalCount)
	}
}

func TestScan_TimeBasedFunction(t *testing.T) {
	scanner := NewScanner()

	// Create AST with SLEEP function call
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{
			&ast.FunctionCall{
				Name:      "SLEEP",
				Arguments: []ast.Expression{&ast.LiteralValue{Value: "5", Type: "INTEGER"}},
			},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.HighCount == 0 {
		t.Error("expected at least one high severity finding for SLEEP function")
	}

	found := false
	for _, f := range result.Findings {
		if f.Pattern == PatternTimeBased {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TIME_BASED pattern to be detected")
	}
}

func TestScan_DangerousFunction_LoadFile(t *testing.T) {
	scanner := NewScanner()

	// Create AST with LOAD_FILE function call
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{
			&ast.FunctionCall{
				Name:      "LOAD_FILE",
				Arguments: []ast.Expression{&ast.LiteralValue{Value: "/etc/passwd", Type: "STRING"}},
			},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected at least one critical finding for LOAD_FILE function")
	}
}

func TestScan_UnionWithNulls(t *testing.T) {
	scanner := NewScanner()

	// Create UNION SELECT NULL, NULL, NULL
	setOp := &ast.SetOperation{
		Left: &ast.SelectStatement{
			Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
		},
		Operator: "UNION",
		Right: &ast.SelectStatement{
			Columns: []ast.Expression{
				&ast.Identifier{Name: "NULL"},
				&ast.Identifier{Name: "NULL"},
				&ast.Identifier{Name: "NULL"},
			},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{setOp}}
	result := scanner.Scan(tree)

	if result.HighCount == 0 {
		t.Error("expected at least one high severity finding for UNION with multiple NULLs")
	}
}

func TestScan_UnionSystemTables(t *testing.T) {
	scanner := NewScanner()

	testCases := []string{
		"information_schema.tables",
		"sys.objects",
		"mysql.user",
		"pg_catalog.pg_tables",
	}

	for _, tableName := range testCases {
		setOp := &ast.SetOperation{
			Left: &ast.SelectStatement{
				Columns: []ast.Expression{&ast.Identifier{Name: "id"}},
			},
			Operator: "UNION",
			Right: &ast.SelectStatement{
				Columns:   []ast.Expression{&ast.Identifier{Name: "table_name"}},
				TableName: tableName,
			},
		}

		tree := &ast.AST{Statements: []ast.Statement{setOp}}
		result := scanner.Scan(tree)

		if result.CriticalCount == 0 {
			t.Errorf("expected critical finding for UNION SELECT from %s", tableName)
		}
	}
}

func TestScan_UpdateWithTautology(t *testing.T) {
	scanner := NewScanner()

	// UPDATE users SET admin=1 WHERE 1=1
	updateStmt := &ast.UpdateStatement{
		TableName: "users",
		Updates: []ast.UpdateExpression{
			{Column: &ast.Identifier{Name: "admin"}, Value: &ast.LiteralValue{Value: "1", Type: "INTEGER"}},
		},
		Where: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{updateStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected critical finding for UPDATE with 1=1 tautology")
	}
}

func TestScan_DeleteWithTautology(t *testing.T) {
	scanner := NewScanner()

	// DELETE FROM users WHERE 1=1
	deleteStmt := &ast.DeleteStatement{
		TableName: "users",
		Where: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{deleteStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected critical finding for DELETE with 1=1 tautology")
	}
}

func TestScanSQL_CommentPatterns(t *testing.T) {
	scanner := NewScanner()

	testCases := []struct {
		sql         string
		shouldFind  bool
		description string
	}{
		{"SELECT * FROM users WHERE id = 1 --", true, "single-line comment at end"},
		{"SELECT * FROM users WHERE id = '1'--", true, "comment after quote"},
		{"SELECT * FROM users /* WHERE id = 1 */", true, "block comment"},
		{"SELECT * FROM users", false, "no comments"},
	}

	for _, tc := range testCases {
		result := scanner.ScanSQL(tc.sql)
		hasCommentFinding := false
		for _, f := range result.Findings {
			if f.Pattern == PatternComment {
				hasCommentFinding = true
				break
			}
		}

		if tc.shouldFind && !hasCommentFinding {
			t.Errorf("expected comment pattern in: %s", tc.description)
		}
	}
}

func TestScanSQL_TimeBasedPatterns(t *testing.T) {
	scanner := NewScanner()

	testCases := []string{
		"SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
		"SELECT * FROM users; WAITFOR DELAY '0:0:5'",
		"SELECT pg_sleep(10)",
		"SELECT BENCHMARK(1000000, MD5('test'))",
	}

	for _, sql := range testCases {
		result := scanner.ScanSQL(sql)
		hasTimeBased := false
		for _, f := range result.Findings {
			if f.Pattern == PatternTimeBased {
				hasTimeBased = true
				break
			}
		}

		if !hasTimeBased {
			t.Errorf("expected time-based pattern in: %s", sql)
		}
	}
}

func TestScanSQL_OutOfBandPatterns(t *testing.T) {
	scanner := NewScanner()

	testCases := []string{
		"EXEC xp_cmdshell 'dir'",
		"SELECT LOAD_FILE('/etc/passwd')",
		"SELECT * INTO OUTFILE '/tmp/data.txt'",
		"SELECT * INTO DUMPFILE '/tmp/shell.php'",
	}

	for _, sql := range testCases {
		result := scanner.ScanSQL(sql)
		hasOutOfBand := false
		for _, f := range result.Findings {
			if f.Pattern == PatternOutOfBand {
				hasOutOfBand = true
				break
			}
		}

		if !hasOutOfBand {
			t.Errorf("expected out-of-band pattern in: %s", sql)
		}
	}
}

func TestSeverityFiltering(t *testing.T) {
	// Create scanner that only includes HIGH and above
	scanner, err := NewScannerWithSeverity(SeverityHigh)
	if err != nil {
		t.Fatalf("NewScannerWithSeverity returned error: %v", err)
	}

	// SQL comment is typically MEDIUM severity
	result := scanner.ScanSQL("SELECT * FROM users /* comment */")

	// Should not include low/medium findings
	for _, f := range result.Findings {
		if f.Severity == SeverityLow || f.Severity == SeverityMedium {
			t.Errorf("found %s severity finding when filtering for HIGH+", f.Severity)
		}
	}
}

func TestScanResult_Methods(t *testing.T) {
	result := &ScanResult{
		Findings:      []Finding{{Severity: SeverityCritical}},
		TotalCount:    1,
		CriticalCount: 1,
	}

	if !result.HasCritical() {
		t.Error("HasCritical should return true")
	}
	if !result.HasHighOrAbove() {
		t.Error("HasHighOrAbove should return true")
	}
	if result.IsClean() {
		t.Error("IsClean should return false")
	}

	cleanResult := &ScanResult{TotalCount: 0}
	if !cleanResult.IsClean() {
		t.Error("IsClean should return true for empty result")
	}
}

func TestScan_HavingClause(t *testing.T) {
	scanner := NewScanner()

	// SELECT ... HAVING 1=1
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "COUNT(*)"}},
		Having: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected critical finding for HAVING 1=1 tautology")
	}
}

func TestScan_NestedExpressions(t *testing.T) {
	scanner := NewScanner()

	// WHERE NOT (1=1) - using UnaryExpression
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.UnaryExpression{
			Operator: ast.Not,
			Expr: &ast.BinaryExpression{
				Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount == 0 {
		t.Error("expected critical finding for nested (1=1) tautology")
	}
}

func TestScan_NoFalsePositives_LegitimateQueries(t *testing.T) {
	scanner := NewScanner()

	// Legitimate query with equality check
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "id"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	if result.CriticalCount > 0 {
		t.Error("false positive: legitimate query flagged as critical")
	}
}

func TestScan_NotEqualOperator(t *testing.T) {
	scanner := NewScanner()

	// WHERE 1!=1 is not a tautology (it's always false)
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.LiteralValue{Value: "1", Type: "INTEGER"},
			Operator: "!=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}

	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}
	result := scanner.Scan(tree)

	// Should not flag != as tautology
	for _, f := range result.Findings {
		if f.Pattern == PatternTautology {
			t.Error("false positive: 1!=1 should not be flagged as tautology")
		}
	}
}

func BenchmarkScan_SimpleQuery(b *testing.B) {
	scanner := NewScanner()
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		Where: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "id"},
			Operator: "=",
			Right:    &ast.LiteralValue{Value: "1", Type: "INTEGER"},
		},
	}
	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

func BenchmarkScan_ComplexQuery(b *testing.B) {
	scanner := NewScanner()
	selectStmt := &ast.SelectStatement{
		Columns: []ast.Expression{
			&ast.Identifier{Name: "id"},
			&ast.Identifier{Name: "name"},
			&ast.FunctionCall{Name: "COUNT", Arguments: []ast.Expression{&ast.Identifier{Name: "*"}}},
		},
		Where: &ast.BinaryExpression{
			Left: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "status"},
				Operator: "=",
				Right:    &ast.LiteralValue{Value: "active", Type: "STRING"},
			},
			Operator: "AND",
			Right: &ast.BinaryExpression{
				Left:     &ast.Identifier{Name: "age"},
				Operator: ">",
				Right:    &ast.LiteralValue{Value: "18", Type: "INTEGER"},
			},
		},
		Having: &ast.BinaryExpression{
			Left:     &ast.Identifier{Name: "COUNT(*)"},
			Operator: ">",
			Right:    &ast.LiteralValue{Value: "5", Type: "INTEGER"},
		},
	}
	tree := &ast.AST{Statements: []ast.Statement{selectStmt}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tree)
	}
}

func BenchmarkScanSQL(b *testing.B) {
	scanner := NewScanner()
	sql := "SELECT * FROM users WHERE id = 1 AND SLEEP(5) -- comment"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanSQL(sql)
	}
}

func TestIsSystemTable(t *testing.T) {
	scanner := NewScanner()

	// Test cases for system table detection
	tests := []struct {
		tableName string
		isSystem  bool
		desc      string
	}{
		// Exact matches
		{"information_schema", true, "exact information_schema"},
		{"INFORMATION_SCHEMA", true, "case-insensitive information_schema"},
		{"pg_catalog", true, "exact pg_catalog"},
		{"sys", true, "exact sys"},

		// Prefix matches
		{"information_schema.tables", true, "information_schema prefix"},
		{"mysql.user", true, "mysql prefix"},
		{"pg_class", true, "pg_ prefix"},
		{"sys.tables", true, "sys. prefix"},
		{"sqlite_master", true, "sqlite_ prefix"},
		{"master.dbo.sysobjects", true, "SQL Server master.dbo prefix"},

		// False positives that should NOT match
		{"users", false, "regular table"},
		{"mysystem", false, "table starting with 'my' should not match mysql"},
		{"system_logs", false, "table containing 'system' should not match"},
		{"postgresql_data", false, "table containing 'postgresql' should not match"},
		{"syslog", false, "table starting with 'sys' (no dot) should not match"},
		{"customer_info", false, "table with 'info' should not match information_schema"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			result := scanner.isSystemTable(tc.tableName)
			if result != tc.isSystem {
				t.Errorf("isSystemTable(%q) = %v, want %v", tc.tableName, result, tc.isSystem)
			}
		})
	}
}

func TestShouldInclude_UnknownSeverity(t *testing.T) {
	scanner := NewScanner()

	// Unknown severity should always be included (fail-safe)
	if !scanner.shouldInclude(Severity("UNKNOWN")) {
		t.Error("unknown severity should be included (fail-safe behavior)")
	}

	// Valid severities should still work correctly
	scanner.MinSeverity = SeverityHigh
	if scanner.shouldInclude(SeverityLow) {
		t.Error("LOW should not be included when MinSeverity is HIGH")
	}
	if !scanner.shouldInclude(SeverityCritical) {
		t.Error("CRITICAL should be included when MinSeverity is HIGH")
	}
}
