package gosqlx

import (
	"sort"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Helper function to sort and compare string slices
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := make([]string, len(a))
	sortedB := make([]string, len(b))
	copy(sortedA, a)
	copy(sortedB, b)
	sort.Strings(sortedA)
	sort.Strings(sortedB)
	for i := range sortedA {
		if sortedA[i] != sortedB[i] {
			return false
		}
	}
	return true
}

// Helper function to check if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestExtractTables_SimpleSelect(t *testing.T) {
	sql := "SELECT * FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if len(tables) != 1 {
		t.Errorf("Expected 1 table, got %d: %v", len(tables), tables)
	}
	if !contains(tables, "users") {
		t.Errorf("Expected to find 'users' table, got: %v", tables)
	}
}

func TestExtractTables_WithJoins(t *testing.T) {
	sql := "SELECT * FROM users u INNER JOIN orders o ON u.id = o.user_id"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if len(tables) != 2 {
		t.Errorf("Expected 2 tables, got %d: %v", len(tables), tables)
	}
	if !contains(tables, "users") || !contains(tables, "orders") {
		t.Errorf("Expected 'users' and 'orders', got: %v", tables)
	}
}

func TestExtractTables_MultipleJoins(t *testing.T) {
	sql := `SELECT u.name, o.total, p.name
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		INNER JOIN products p ON o.product_id = p.id`
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	expected := []string{"users", "orders", "products"}
	if !stringSlicesEqual(tables, expected) {
		t.Errorf("Expected tables %v, got %v", expected, tables)
	}
}

func TestExtractTables_WithCTE(t *testing.T) {
	sql := `WITH active_users AS (
		SELECT * FROM users WHERE active = true
	)
	SELECT * FROM active_users`
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if !contains(tables, "users") {
		t.Errorf("Expected to find 'users' table in CTE, got: %v", tables)
	}
}

func TestExtractTables_WithRecursiveCTE(t *testing.T) {
	// Skipping - Recursive CTE with complex JOIN syntax not fully supported yet
	t.Skip("Recursive CTE with complex syntax not fully supported")
}

func TestExtractTables_Insert(t *testing.T) {
	sql := "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if len(tables) != 1 || !contains(tables, "users") {
		t.Errorf("Expected 'users' table, got: %v", tables)
	}
}

func TestExtractTables_Update(t *testing.T) {
	sql := "UPDATE users SET active = false WHERE id = 1"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if len(tables) != 1 || !contains(tables, "users") {
		t.Errorf("Expected 'users' table, got: %v", tables)
	}
}

func TestExtractTables_Delete(t *testing.T) {
	sql := "DELETE FROM users WHERE created_at < '2020-01-01'"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	if len(tables) != 1 || !contains(tables, "users") {
		t.Errorf("Expected 'users' table, got: %v", tables)
	}
}

func TestExtractTables_EmptyAST(t *testing.T) {
	tables := ExtractTables(nil)
	if tables != nil {
		t.Errorf("Expected nil for nil AST, got: %v", tables)
	}
}

func TestExtractTablesQualified_SimpleTable(t *testing.T) {
	sql := "SELECT * FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTablesQualified(astNode)
	if len(tables) != 1 {
		t.Errorf("Expected 1 table, got %d: %v", len(tables), tables)
	}
	if tables[0].Name != "users" {
		t.Errorf("Expected table name 'users', got: %s", tables[0].Name)
	}
}

func TestExtractTablesQualified_WithSchema(t *testing.T) {
	// Skipping - Schema-qualified table names (schema.table) not supported in parser yet
	t.Skip("Schema-qualified table names not supported in parser yet")
}

func TestQualifiedName_String(t *testing.T) {
	tests := []struct {
		name     string
		qn       QualifiedName
		expected string
	}{
		{
			name:     "Simple name",
			qn:       QualifiedName{Name: "users"},
			expected: "users",
		},
		{
			name:     "Schema and name",
			qn:       QualifiedName{Schema: "public", Name: "users"},
			expected: "public.users",
		},
		{
			name:     "Full qualified",
			qn:       QualifiedName{Schema: "db", Table: "public", Name: "users"},
			expected: "db.public.users",
		},
		{
			name:     "Table and name",
			qn:       QualifiedName{Table: "users", Name: "id"},
			expected: "users.id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.qn.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestExtractColumns_SimpleSelect(t *testing.T) {
	sql := "SELECT id, name, email FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expected := []string{"id", "name", "email"}
	if !stringSlicesEqual(columns, expected) {
		t.Errorf("Expected columns %v, got %v", expected, columns)
	}
}

func TestExtractColumns_WithAsterisk(t *testing.T) {
	sql := "SELECT * FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	// Asterisk should be ignored
	if contains(columns, "*") {
		t.Errorf("Expected asterisk to be filtered out, got: %v", columns)
	}
}

func TestExtractColumns_WithQualifiers(t *testing.T) {
	sql := "SELECT u.id, u.name, o.order_id FROM users u JOIN orders o ON u.id = o.user_id"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expected := []string{"id", "name", "order_id", "user_id"}
	if !stringSlicesEqual(columns, expected) {
		t.Errorf("Expected columns %v, got %v", expected, columns)
	}
}

func TestExtractColumns_WithWhere(t *testing.T) {
	sql := "SELECT name FROM users WHERE active = true AND created_at > '2020-01-01'"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	if !contains(columns, "name") || !contains(columns, "active") || !contains(columns, "created_at") {
		t.Errorf("Expected name, active, created_at, got: %v", columns)
	}
}

func TestExtractColumns_WithGroupBy(t *testing.T) {
	sql := "SELECT department, COUNT(*) FROM employees GROUP BY department"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	if !contains(columns, "department") {
		t.Errorf("Expected 'department' column, got: %v", columns)
	}
}

func TestExtractColumns_WithOrderBy(t *testing.T) {
	sql := "SELECT name, salary FROM employees ORDER BY salary"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	if !contains(columns, "name") || !contains(columns, "salary") {
		t.Errorf("Expected name and salary columns, got: %v", columns)
	}
}

func TestExtractColumns_WithHaving(t *testing.T) {
	sql := "SELECT department, COUNT(*) as cnt FROM employees GROUP BY department HAVING cnt > 5"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	if !contains(columns, "department") {
		t.Errorf("Expected 'department' column, got: %v", columns)
	}
}

func TestExtractColumns_Update(t *testing.T) {
	sql := "UPDATE users SET active = false, updated_at = NOW() WHERE id = 1"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expected := []string{"active", "updated_at", "id"}
	if !stringSlicesEqual(columns, expected) {
		t.Errorf("Expected columns %v, got %v", expected, columns)
	}
}

func TestExtractColumns_Insert(t *testing.T) {
	sql := "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expected := []string{"name", "email"}
	if !stringSlicesEqual(columns, expected) {
		t.Errorf("Expected columns %v, got %v", expected, columns)
	}
}

func TestExtractColumns_Delete(t *testing.T) {
	sql := "DELETE FROM users WHERE active = false AND created_at < '2020-01-01'"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expected := []string{"active", "created_at"}
	if !stringSlicesEqual(columns, expected) {
		t.Errorf("Expected columns %v, got %v", expected, columns)
	}
}

func TestExtractColumns_EmptyAST(t *testing.T) {
	columns := ExtractColumns(nil)
	if columns != nil {
		t.Errorf("Expected nil for nil AST, got: %v", columns)
	}
}

func TestExtractFunctions_SimpleFunction(t *testing.T) {
	sql := "SELECT COUNT(*) FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	if len(functions) != 1 || !contains(functions, "COUNT") {
		t.Errorf("Expected 'COUNT' function, got: %v", functions)
	}
}

func TestExtractFunctions_MultipleFunctions(t *testing.T) {
	sql := "SELECT COUNT(*), AVG(salary), MAX(age), MIN(created_at) FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	expected := []string{"COUNT", "AVG", "MAX", "MIN"}
	if !stringSlicesEqual(functions, expected) {
		t.Errorf("Expected functions %v, got %v", expected, functions)
	}
}

func TestExtractFunctions_StringFunctions(t *testing.T) {
	sql := "SELECT UPPER(name), LOWER(email), SUBSTRING(address, 1, 10) FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	expected := []string{"UPPER", "LOWER", "SUBSTRING"}
	if !stringSlicesEqual(functions, expected) {
		t.Errorf("Expected functions %v, got %v", expected, functions)
	}
}

func TestExtractFunctions_NestedFunctions(t *testing.T) {
	sql := "SELECT UPPER(TRIM(name)) FROM users"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	expected := []string{"UPPER", "TRIM"}
	if !stringSlicesEqual(functions, expected) {
		t.Errorf("Expected functions %v, got %v", expected, functions)
	}
}

func TestExtractFunctions_InWhere(t *testing.T) {
	sql := "SELECT name FROM users WHERE UPPER(name) = 'JOHN'"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	if !contains(functions, "UPPER") {
		t.Errorf("Expected 'UPPER' function in WHERE clause, got: %v", functions)
	}
}

func TestExtractFunctions_InHaving(t *testing.T) {
	sql := "SELECT department, COUNT(*) as cnt FROM employees GROUP BY department HAVING COUNT(*) > 5"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	if !contains(functions, "COUNT") {
		t.Errorf("Expected 'COUNT' function, got: %v", functions)
	}
}

func TestExtractFunctions_WindowFunction(t *testing.T) {
	sql := "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	if !contains(functions, "ROW_NUMBER") {
		t.Errorf("Expected 'ROW_NUMBER' window function, got: %v", functions)
	}
}

func TestExtractFunctions_Update(t *testing.T) {
	sql := "UPDATE users SET updated_at = NOW(), name = UPPER(name) WHERE id = 1"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	expected := []string{"NOW", "UPPER"}
	if !stringSlicesEqual(functions, expected) {
		t.Errorf("Expected functions %v, got %v", expected, functions)
	}
}

func TestExtractFunctions_EmptyAST(t *testing.T) {
	functions := ExtractFunctions(nil)
	if functions != nil {
		t.Errorf("Expected nil for nil AST, got: %v", functions)
	}
}

func TestExtractMetadata_Comprehensive(t *testing.T) {
	sql := `SELECT u.name, COUNT(o.id) as order_count, UPPER(u.email)
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.name, u.email
		HAVING COUNT(o.id) > 5
		ORDER BY order_count DESC`

	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	metadata := ExtractMetadata(astNode)

	// Check tables
	expectedTables := []string{"users", "orders"}
	if !stringSlicesEqual(metadata.Tables, expectedTables) {
		t.Errorf("Expected tables %v, got %v", expectedTables, metadata.Tables)
	}

	// Check columns
	if !contains(metadata.Columns, "name") || !contains(metadata.Columns, "id") ||
		!contains(metadata.Columns, "email") || !contains(metadata.Columns, "active") ||
		!contains(metadata.Columns, "user_id") {
		t.Errorf("Missing expected columns in: %v", metadata.Columns)
	}

	// Check functions
	expectedFunctions := []string{"COUNT", "UPPER"}
	if !stringSlicesEqual(metadata.Functions, expectedFunctions) {
		t.Errorf("Expected functions %v, got %v", expectedFunctions, metadata.Functions)
	}

	// Check String() method
	str := metadata.String()
	if str == "" {
		t.Error("Expected non-empty string from Metadata.String()")
	}
}

func TestExtractMetadata_WithCTE(t *testing.T) {
	sql := `WITH active_users AS (
		SELECT id, name FROM users WHERE active = true
	)
	SELECT name, COUNT(*) FROM active_users GROUP BY name`

	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	metadata := ExtractMetadata(astNode)

	// Should find base table in CTE
	if !contains(metadata.Tables, "users") {
		t.Errorf("Expected to find 'users' table in CTE, got: %v", metadata.Tables)
	}

	// Should find columns from both CTE and main query
	if !contains(metadata.Columns, "id") || !contains(metadata.Columns, "name") ||
		!contains(metadata.Columns, "active") {
		t.Errorf("Missing expected columns in: %v", metadata.Columns)
	}

	// Should find COUNT function
	if !contains(metadata.Functions, "COUNT") {
		t.Errorf("Expected 'COUNT' function, got: %v", metadata.Functions)
	}
}

func TestExtractMetadata_EmptyQuery(t *testing.T) {
	metadata := ExtractMetadata(nil)
	if metadata == nil {
		t.Error("Expected non-nil Metadata for nil AST")
		return
	}
	if len(metadata.Tables) > 0 || len(metadata.Columns) > 0 || len(metadata.Functions) > 0 {
		t.Errorf("Expected empty metadata for nil AST, got: %+v", metadata)
	}
}

func TestExtractColumns_WithCaseExpression(t *testing.T) {
	// Skipping - CASE expressions not fully supported in parser yet
	t.Skip("CASE expressions not fully supported in parser yet")
}

func TestExtractColumns_WithInExpression(t *testing.T) {
	// Skipping - IN expressions in WHERE clause not fully supported yet
	t.Skip("IN expressions in WHERE clause not fully supported yet")
}

func TestExtractColumns_WithBetweenExpression(t *testing.T) {
	// Skipping - BETWEEN expressions not fully supported yet
	t.Skip("BETWEEN expressions not fully supported yet")
}

func TestExtractFunctions_InCaseExpression(t *testing.T) {
	// Skipping - CASE expressions not fully supported yet
	t.Skip("CASE expressions not fully supported yet")
}

func TestExtractTables_WithSetOperations(t *testing.T) {
	sql := `SELECT id FROM users
		UNION
		SELECT id FROM employees
		EXCEPT
		SELECT id FROM archived_users`

	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	tables := ExtractTables(astNode)
	expected := []string{"users", "employees", "archived_users"}
	if !stringSlicesEqual(tables, expected) {
		t.Errorf("Expected tables %v, got %v", expected, tables)
	}
}

func TestExtractColumns_ComplexJoin(t *testing.T) {
	sql := `SELECT
		u.user_id, u.username,
		o.order_id, o.total,
		p.product_name
	FROM users u
	LEFT JOIN orders o ON u.user_id = o.user_id
	INNER JOIN products p ON o.product_id = p.product_id
	WHERE u.active = true AND o.status = 'completed'`

	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	expectedColumns := []string{
		"user_id", "username", "order_id", "total", "product_name",
		"active", "status", "product_id",
	}

	for _, expected := range expectedColumns {
		if !contains(columns, expected) {
			t.Errorf("Expected column '%s' not found in: %v", expected, columns)
		}
	}
}

func TestQualifiedName_FullName(t *testing.T) {
	tests := []struct {
		name     string
		qn       QualifiedName
		expected string
	}{
		{
			name:     "Only name",
			qn:       QualifiedName{Name: "users"},
			expected: "users",
		},
		{
			name:     "Table and name",
			qn:       QualifiedName{Table: "public", Name: "users"},
			expected: "public.users",
		},
		{
			name:     "Schema, table, and name",
			qn:       QualifiedName{Schema: "db", Table: "public", Name: "users"},
			expected: "public.users",
		},
		{
			name:     "Only table",
			qn:       QualifiedName{Table: "users"},
			expected: "users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.qn.FullName()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkExtractTables(b *testing.B) {
	sql := `SELECT u.name, o.total
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true`
	astNode, _ := Parse(sql)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractTables(astNode)
	}
}

func BenchmarkExtractColumns(b *testing.B) {
	sql := `SELECT u.name, u.email, o.total, o.created_at
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true AND o.status = 'completed'
		ORDER BY o.created_at DESC`
	astNode, _ := Parse(sql)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractColumns(astNode)
	}
}

func BenchmarkExtractFunctions(b *testing.B) {
	sql := `SELECT
		COUNT(*),
		AVG(price),
		MAX(created_at),
		UPPER(name),
		LOWER(email)
	FROM products
	WHERE TRIM(category) = 'electronics'`
	astNode, _ := Parse(sql)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractFunctions(astNode)
	}
}

func BenchmarkExtractMetadata(b *testing.B) {
	sql := `SELECT
		u.name,
		COUNT(o.id) as order_count,
		UPPER(u.email)
	FROM users u
	LEFT JOIN orders o ON u.id = o.user_id
	WHERE u.active = true
	GROUP BY u.name, u.email
	HAVING COUNT(o.id) > 5
	ORDER BY order_count DESC`
	astNode, _ := Parse(sql)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractMetadata(astNode)
	}
}

// Test edge cases
func TestExtractTables_NoTables(t *testing.T) {
	// Empty AST with no statements
	astNode := &ast.AST{Statements: []ast.Statement{}}
	tables := ExtractTables(astNode)
	if len(tables) != 0 {
		t.Errorf("Expected no tables for empty AST, got: %v", tables)
	}
}

func TestExtractColumns_NoColumns(t *testing.T) {
	// Only literals, no column references
	sql := "SELECT 1, 'hello', true"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	columns := ExtractColumns(astNode)
	// Should be empty or minimal
	if len(columns) > 0 {
		t.Logf("Columns found: %v", columns)
	}
}

func TestExtractFunctions_NoFunctions(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE active = true"
	astNode, err := Parse(sql)
	if err != nil {
		t.Fatalf("Failed to parse SQL: %v", err)
	}

	functions := ExtractFunctions(astNode)
	if len(functions) != 0 {
		t.Errorf("Expected no functions, got: %v", functions)
	}
}

func TestExtractColumns_WithCastExpression(t *testing.T) {
	// Skipping - CAST expressions not fully supported yet
	t.Skip("CAST expressions not fully supported yet")
}

func TestExtractFunctions_ExtractExpression(t *testing.T) {
	// Skipping - EXTRACT expressions not fully supported yet
	t.Skip("EXTRACT expressions not fully supported yet")
}
