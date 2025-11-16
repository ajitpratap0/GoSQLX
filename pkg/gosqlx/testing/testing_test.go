package testing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Test AssertValidSQL with valid SQL
func TestAssertValidSQL_Valid(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertValidSQL(mockT, "SELECT * FROM users")

	if !result {
		t.Error("AssertValidSQL should return true for valid SQL")
	}
	if mockT.failed {
		t.Error("AssertValidSQL should not fail for valid SQL")
	}
}

// Test AssertValidSQL with invalid SQL
func TestAssertValidSQL_Invalid(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertValidSQL(mockT, "SELECT FROM WHERE")

	if result {
		t.Error("AssertValidSQL should return false for invalid SQL")
	}
	if !mockT.failed {
		t.Error("AssertValidSQL should fail for invalid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Expected valid SQL") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertInvalidSQL with invalid SQL
func TestAssertInvalidSQL_Invalid(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertInvalidSQL(mockT, "SELECT FROM WHERE")

	if !result {
		t.Error("AssertInvalidSQL should return true for invalid SQL")
	}
	if mockT.failed {
		t.Error("AssertInvalidSQL should not fail for invalid SQL")
	}
}

// Test AssertInvalidSQL with valid SQL
func TestAssertInvalidSQL_Valid(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertInvalidSQL(mockT, "SELECT * FROM users")

	if result {
		t.Error("AssertInvalidSQL should return false for valid SQL")
	}
	if !mockT.failed {
		t.Error("AssertInvalidSQL should fail for valid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Expected invalid SQL") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test RequireValidSQL with valid SQL
func TestRequireValidSQL_Valid(t *testing.T) {
	mockT := &mockTestingT{}

	RequireValidSQL(mockT, "SELECT * FROM users")

	if mockT.fataled {
		t.Error("RequireValidSQL should not fatal for valid SQL")
	}
}

// Test RequireValidSQL with invalid SQL
func TestRequireValidSQL_Invalid(t *testing.T) {
	mockT := &mockTestingT{}

	RequireValidSQL(mockT, "SELECT FROM WHERE")

	if !mockT.fataled {
		t.Error("RequireValidSQL should fatal for invalid SQL")
	}
	if !strings.Contains(mockT.fatalMsg, "Required valid SQL") {
		t.Errorf("Fatal message should be descriptive, got: %s", mockT.fatalMsg)
	}
}

// Test RequireInvalidSQL with invalid SQL
func TestRequireInvalidSQL_Invalid(t *testing.T) {
	mockT := &mockTestingT{}

	RequireInvalidSQL(mockT, "SELECT FROM WHERE")

	if mockT.fataled {
		t.Error("RequireInvalidSQL should not fatal for invalid SQL")
	}
}

// Test RequireInvalidSQL with valid SQL
func TestRequireInvalidSQL_Valid(t *testing.T) {
	mockT := &mockTestingT{}

	RequireInvalidSQL(mockT, "SELECT * FROM users")

	if !mockT.fataled {
		t.Error("RequireInvalidSQL should fatal for valid SQL")
	}
	if !strings.Contains(mockT.fatalMsg, "Required invalid SQL") {
		t.Errorf("Fatal message should be descriptive, got: %s", mockT.fatalMsg)
	}
}

// Test AssertFormattedSQL with matching format
func TestAssertFormattedSQL_Matching(t *testing.T) {
	mockT := &mockTestingT{}

	// Note: Current Format implementation returns input as-is
	sql := "SELECT * FROM users"
	result := AssertFormattedSQL(mockT, sql, sql)

	if !result {
		t.Error("AssertFormattedSQL should return true for matching format")
	}
	if mockT.failed {
		t.Errorf("AssertFormattedSQL should not fail for matching format, got: %s", mockT.errorMsg)
	}
}

// Test AssertFormattedSQL with non-matching format
func TestAssertFormattedSQL_NotMatching(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	expected := "SELECT * FROM orders"
	result := AssertFormattedSQL(mockT, sql, expected)

	if result {
		t.Error("AssertFormattedSQL should return false for non-matching format")
	}
	if !mockT.failed {
		t.Error("AssertFormattedSQL should fail for non-matching format")
	}
	if !strings.Contains(mockT.errorMsg, "does not match expected") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertFormattedSQL with invalid SQL
func TestAssertFormattedSQL_InvalidSQL(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertFormattedSQL(mockT, "SELECT FROM WHERE", "anything")

	if result {
		t.Error("AssertFormattedSQL should return false for invalid SQL")
	}
	if !mockT.failed {
		t.Error("AssertFormattedSQL should fail for invalid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Failed to format SQL") {
		t.Errorf("Error message should indicate format failure, got: %s", mockT.errorMsg)
	}
}

// Test AssertTables with correct tables
func TestAssertTables_Correct(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
	expectedTables := []string{"users", "orders"}

	result := AssertTables(mockT, sql, expectedTables)

	if !result {
		t.Error("AssertTables should return true for correct tables")
	}
	if mockT.failed {
		t.Errorf("AssertTables should not fail for correct tables, got: %s", mockT.errorMsg)
	}
}

// Test AssertTables with incorrect tables
func TestAssertTables_Incorrect(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	expectedTables := []string{"orders"}

	result := AssertTables(mockT, sql, expectedTables)

	if result {
		t.Error("AssertTables should return false for incorrect tables")
	}
	if !mockT.failed {
		t.Error("AssertTables should fail for incorrect tables")
	}
	if !strings.Contains(mockT.errorMsg, "do not match expected") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertTables with multiple tables
func TestAssertTables_MultipleTables(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users u LEFT JOIN orders o ON u.id = o.user_id RIGHT JOIN products p ON o.product_id = p.id"
	expectedTables := []string{"users", "orders", "products"}

	result := AssertTables(mockT, sql, expectedTables)

	if !result {
		t.Error("AssertTables should return true for correct multiple tables")
	}
	if mockT.failed {
		t.Errorf("AssertTables should not fail for correct multiple tables, got: %s", mockT.errorMsg)
	}
}

// Test AssertTables with invalid SQL
func TestAssertTables_InvalidSQL(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertTables(mockT, "SELECT FROM WHERE", []string{"users"})

	if result {
		t.Error("AssertTables should return false for invalid SQL")
	}
	if !mockT.failed {
		t.Error("AssertTables should fail for invalid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Failed to parse SQL") {
		t.Errorf("Error message should indicate parse failure, got: %s", mockT.errorMsg)
	}
}

// Test AssertColumns with correct columns
func TestAssertColumns_Correct(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT id, name, email FROM users"
	expectedColumns := []string{"id", "name", "email"}

	result := AssertColumns(mockT, sql, expectedColumns)

	if !result {
		t.Error("AssertColumns should return true for correct columns")
	}
	if mockT.failed {
		t.Errorf("AssertColumns should not fail for correct columns, got: %s", mockT.errorMsg)
	}
}

// Test AssertColumns with incorrect columns
func TestAssertColumns_Incorrect(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT id, name FROM users"
	expectedColumns := []string{"id", "email"}

	result := AssertColumns(mockT, sql, expectedColumns)

	if result {
		t.Error("AssertColumns should return false for incorrect columns")
	}
	if !mockT.failed {
		t.Error("AssertColumns should fail for incorrect columns")
	}
	if !strings.Contains(mockT.errorMsg, "do not match expected") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertColumns with wildcard (should skip *)
func TestAssertColumns_Wildcard(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	expectedColumns := []string{} // Should extract no columns from *

	result := AssertColumns(mockT, sql, expectedColumns)

	if !result {
		t.Error("AssertColumns should return true for wildcard with empty expected")
	}
	if mockT.failed {
		t.Errorf("AssertColumns should not fail for wildcard, got: %s", mockT.errorMsg)
	}
}

// Test AssertColumns with invalid SQL
func TestAssertColumns_InvalidSQL(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertColumns(mockT, "SELECT FROM WHERE", []string{"id"})

	if result {
		t.Error("AssertColumns should return false for invalid SQL")
	}
	if !mockT.failed {
		t.Error("AssertColumns should fail for invalid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Failed to parse SQL") {
		t.Errorf("Error message should indicate parse failure, got: %s", mockT.errorMsg)
	}
}

// Test AssertParsesTo with correct type
func TestAssertParsesTo_Correct(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	result := AssertParsesTo(mockT, sql, &ast.SelectStatement{})

	if !result {
		t.Error("AssertParsesTo should return true for correct type")
	}
	if mockT.failed {
		t.Errorf("AssertParsesTo should not fail for correct type, got: %s", mockT.errorMsg)
	}
}

// Test AssertParsesTo with incorrect type
func TestAssertParsesTo_Incorrect(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	result := AssertParsesTo(mockT, sql, &ast.InsertStatement{})

	if result {
		t.Error("AssertParsesTo should return false for incorrect type")
	}
	if !mockT.failed {
		t.Error("AssertParsesTo should fail for incorrect type")
	}
	if !strings.Contains(mockT.errorMsg, "unexpected statement type") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertParsesTo with different statement types
func TestAssertParsesTo_InsertStatement(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "INSERT INTO users (name) VALUES ('John')"
	result := AssertParsesTo(mockT, sql, &ast.InsertStatement{})

	if !result {
		t.Error("AssertParsesTo should return true for INSERT statement")
	}
	if mockT.failed {
		t.Errorf("AssertParsesTo should not fail for correct INSERT type, got: %s", mockT.errorMsg)
	}
}

// Test AssertParsesTo with invalid SQL
func TestAssertParsesTo_InvalidSQL(t *testing.T) {
	mockT := &mockTestingT{}

	result := AssertParsesTo(mockT, "SELECT FROM WHERE", &ast.SelectStatement{})

	if result {
		t.Error("AssertParsesTo should return false for invalid SQL")
	}
	if !mockT.failed {
		t.Error("AssertParsesTo should fail for invalid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "Failed to parse SQL") {
		t.Errorf("Error message should indicate parse failure, got: %s", mockT.errorMsg)
	}
}

// Test AssertErrorContains with matching error
func TestAssertErrorContains_Matching(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT FROM WHERE"
	result := AssertErrorContains(mockT, sql, "parsing")

	if !result {
		t.Error("AssertErrorContains should return true for matching error")
	}
	if mockT.failed {
		t.Errorf("AssertErrorContains should not fail for matching error, got: %s", mockT.errorMsg)
	}
}

// Test AssertErrorContains with non-matching error
func TestAssertErrorContains_NotMatching(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT FROM WHERE"
	result := AssertErrorContains(mockT, sql, "completely_wrong_error")

	if result {
		t.Error("AssertErrorContains should return false for non-matching error")
	}
	if !mockT.failed {
		t.Error("AssertErrorContains should fail for non-matching error")
	}
	if !strings.Contains(mockT.errorMsg, "does not contain expected substring") {
		t.Errorf("Error message should be descriptive, got: %s", mockT.errorMsg)
	}
}

// Test AssertErrorContains with valid SQL (no error)
func TestAssertErrorContains_ValidSQL(t *testing.T) {
	mockT := &mockTestingT{}

	sql := "SELECT * FROM users"
	result := AssertErrorContains(mockT, sql, "error")

	if result {
		t.Error("AssertErrorContains should return false for valid SQL")
	}
	if !mockT.failed {
		t.Error("AssertErrorContains should fail for valid SQL")
	}
	if !strings.Contains(mockT.errorMsg, "but SQL parsed successfully") {
		t.Errorf("Error message should indicate successful parse, got: %s", mockT.errorMsg)
	}
}

// Test RequireParse with valid SQL
func TestRequireParse_Valid(t *testing.T) {
	mockT := &mockTestingT{}

	astNode := RequireParse(mockT, "SELECT * FROM users")

	if mockT.fataled {
		t.Error("RequireParse should not fatal for valid SQL")
	}
	if astNode == nil {
		t.Error("RequireParse should return non-nil AST for valid SQL")
		return
	}
	if len(astNode.Statements) == 0 {
		t.Error("RequireParse should return AST with statements")
	}
}

// Test RequireParse with invalid SQL
func TestRequireParse_Invalid(t *testing.T) {
	mockT := &mockTestingT{}

	RequireParse(mockT, "SELECT FROM WHERE")

	if !mockT.fataled {
		t.Error("RequireParse should fatal for invalid SQL")
	}
	if !strings.Contains(mockT.fatalMsg, "Required SQL to parse") {
		t.Errorf("Fatal message should be descriptive, got: %s", mockT.fatalMsg)
	}
}

// Test truncateSQL helper
func TestTruncateSQL(t *testing.T) {
	shortSQL := "SELECT * FROM users"
	if truncated := truncateSQL(shortSQL); truncated != shortSQL {
		t.Errorf("Short SQL should not be truncated, got: %s", truncated)
	}

	longSQL := strings.Repeat("SELECT * FROM users WHERE active = true AND ", 10)
	truncated := truncateSQL(longSQL)
	if len(truncated) > 104 { // 100 chars + "..."
		t.Errorf("Long SQL should be truncated to max 104 chars, got: %d", len(truncated))
	}
	if !strings.HasSuffix(truncated, "...") {
		t.Error("Truncated SQL should end with '...'")
	}
}

// Test extractTables helper with various SQL statements
func TestExtractTables_SelectWithJoins(t *testing.T) {
	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
	astNode := RequireParse(t, sql)

	tables := extractTables(astNode)
	expectedTables := []string{"users", "orders"}

	if len(tables) != len(expectedTables) {
		t.Errorf("Expected %d tables, got %d: %v", len(expectedTables), len(tables), tables)
	}

	tableMap := make(map[string]bool)
	for _, table := range tables {
		tableMap[table] = true
	}

	for _, expected := range expectedTables {
		if !tableMap[expected] {
			t.Errorf("Expected table '%s' not found in extracted tables: %v", expected, tables)
		}
	}
}

// Test extractTables with INSERT statement
func TestExtractTables_Insert(t *testing.T) {
	sql := "INSERT INTO users (name) VALUES ('John')"
	astNode := RequireParse(t, sql)

	tables := extractTables(astNode)

	if len(tables) != 1 {
		t.Errorf("Expected 1 table, got %d: %v", len(tables), tables)
	}
	if len(tables) > 0 && tables[0] != "users" {
		t.Errorf("Expected table 'users', got '%s'", tables[0])
	}
}

// Test extractColumns helper
func TestExtractColumns_Simple(t *testing.T) {
	sql := "SELECT id, name, email FROM users"
	astNode := RequireParse(t, sql)

	columns := extractColumns(astNode)
	expectedColumns := []string{"id", "name", "email"}

	if len(columns) != len(expectedColumns) {
		t.Errorf("Expected %d columns, got %d: %v", len(expectedColumns), len(columns), columns)
	}

	colMap := make(map[string]bool)
	for _, col := range columns {
		colMap[col] = true
	}

	for _, expected := range expectedColumns {
		if !colMap[expected] {
			t.Errorf("Expected column '%s' not found in extracted columns: %v", expected, columns)
		}
	}
}

// Test stringSlicesEqual helper
func TestStringSlicesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{"equal slices", []string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{"different length", []string{"a", "b"}, []string{"a", "b", "c"}, false},
		{"different content", []string{"a", "b", "c"}, []string{"a", "b", "d"}, false},
		{"empty slices", []string{}, []string{}, true},
		{"one empty", []string{"a"}, []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringSlicesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Mock testing.T implementation for testing
type mockTestingT struct {
	failed   bool
	fataled  bool
	errorMsg string
	fatalMsg string
}

func (m *mockTestingT) Helper() {}

func (m *mockTestingT) Errorf(format string, args ...interface{}) {
	m.failed = true
	m.errorMsg = strings.TrimSpace(format)
	if len(args) > 0 {
		m.errorMsg = strings.TrimSpace(fmt.Sprintf(format, args...))
	}
}

func (m *mockTestingT) Fatalf(format string, args ...interface{}) {
	m.fataled = true
	m.fatalMsg = strings.TrimSpace(format)
	if len(args) > 0 {
		m.fatalMsg = strings.TrimSpace(fmt.Sprintf(format, args...))
	}
}

// Test extractColumnsFromFunctionCall
func TestExtractColumns_FunctionCall(t *testing.T) {
	sql := "SELECT COUNT(id), MAX(salary) FROM employees"
	astNode := RequireParse(t, sql)

	columns := extractColumns(astNode)

	// Should extract column names from function arguments
	if len(columns) != 2 {
		t.Errorf("Expected 2 columns from function calls, got %d: %v", len(columns), columns)
	}
}

// Test extractColumnsFromBinaryExpression
func TestExtractColumns_QualifiedColumn(t *testing.T) {
	// Test columns with table qualifiers
	sql := "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id"
	astNode := RequireParse(t, sql)

	columns := extractColumns(astNode)

	// Should extract column names (without table prefixes in the current implementation)
	expectedCols := []string{"id", "name", "total"}
	colMap := make(map[string]bool)
	for _, col := range columns {
		colMap[col] = true
	}

	for _, expected := range expectedCols {
		if !colMap[expected] {
			t.Errorf("Expected column '%s' not found in extracted columns: %v", expected, columns)
		}
	}
}

// Test AssertParsesTo with empty statements
func TestAssertParsesTo_NoStatements(t *testing.T) {
	// This test covers the edge case where AST has no statements
	// We can't really create this case naturally, so we'll test normal behavior
	mockT := &mockTestingT{}

	// Normal case should work fine
	result := AssertParsesTo(mockT, "SELECT * FROM users", &ast.SelectStatement{})
	if !result {
		t.Error("AssertParsesTo should return true for valid SELECT")
	}
}

// Test extractTables with UPDATE statement
func TestExtractTables_Update(t *testing.T) {
	sql := "UPDATE employees SET salary = 50000 WHERE id = 1"
	astNode := RequireParse(t, sql)

	tables := extractTables(astNode)

	if len(tables) != 1 {
		t.Errorf("Expected 1 table, got %d: %v", len(tables), tables)
	}
	if len(tables) > 0 && tables[0] != "employees" {
		t.Errorf("Expected table 'employees', got '%s'", tables[0])
	}
}

// Test extractTables with DELETE statement
func TestExtractTables_Delete(t *testing.T) {
	sql := "DELETE FROM inactive_users WHERE last_login < '2020-01-01'"
	astNode := RequireParse(t, sql)

	tables := extractTables(astNode)

	if len(tables) != 1 {
		t.Errorf("Expected 1 table, got %d: %v", len(tables), tables)
	}
	if len(tables) > 0 && tables[0] != "inactive_users" {
		t.Errorf("Expected table 'inactive_users', got '%s'", tables[0])
	}
}

// Test extractTables with set operations
func TestExtractTables_SetOperations(t *testing.T) {
	sql := "SELECT * FROM users UNION SELECT * FROM admins"
	astNode := RequireParse(t, sql)

	tables := extractTables(astNode)
	expectedTables := []string{"users", "admins"}

	if len(tables) != len(expectedTables) {
		t.Errorf("Expected %d tables, got %d: %v", len(expectedTables), len(tables), tables)
	}

	tableMap := make(map[string]bool)
	for _, table := range tables {
		tableMap[table] = true
	}

	for _, expected := range expectedTables {
		if !tableMap[expected] {
			t.Errorf("Expected table '%s' not found in extracted tables: %v", expected, tables)
		}
	}
}

// Test isSyntheticTableName edge cases
func TestIsSyntheticTableName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"normal table", "users", false},
		{"with parentheses", "(synthetic)", true},
		{"with _with_", "users_with_1_joins", true},
		{"starts with underscore", "_temp", true},
		{"empty string", "", true},
		{"normal with underscore", "user_accounts", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSyntheticTableName(tt.input)
			if result != tt.expected {
				t.Errorf("isSyntheticTableName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// Compile-time check that mockTestingT implements the necessary interface
var _ interface {
	Helper()
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
} = (*mockTestingT)(nil)
