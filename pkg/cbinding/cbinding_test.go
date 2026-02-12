package main

import (
	"encoding/json"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ---------------------------------------------------------------------------
// Tests that call the real gosqlx functions
// ---------------------------------------------------------------------------

func TestParseValidSQL(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT id, name FROM users WHERE active = true")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	if _, ok := tree.Statements[0].(*ast.SelectStatement); !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
}

func TestParseInvalidSQL(t *testing.T) {
	_, err := gosqlx.Parse("SELCT * FORM users")
	if err == nil {
		t.Fatal("expected error for invalid SQL, got nil")
	}
}

func TestParseMultipleStatements(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT 1; SELECT 2")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(tree.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(tree.Statements))
	}
	for i, stmt := range tree.Statements {
		if _, ok := stmt.(*ast.SelectStatement); !ok {
			t.Fatalf("statement %d: expected SelectStatement, got %T", i, stmt)
		}
	}
}

func TestValidateValidSQL(t *testing.T) {
	err := gosqlx.Validate("SELECT * FROM users")
	if err != nil {
		t.Fatalf("expected nil error for valid SQL, got: %v", err)
	}
}

func TestValidateInvalidSQL(t *testing.T) {
	err := gosqlx.Validate("NOT VALID SQL AT ALL ???")
	if err == nil {
		t.Fatal("expected error for invalid SQL, got nil")
	}
}

func TestFormatSQL(t *testing.T) {
	opts := gosqlx.DefaultFormatOptions()
	formatted, err := gosqlx.Format("SELECT * FROM users", opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if formatted == "" {
		t.Fatal("expected non-empty formatted SQL")
	}
}

func TestExtractTables(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT * FROM users JOIN orders ON users.id = orders.user_id")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	tables := gosqlx.ExtractTables(tree)
	if len(tables) == 0 {
		t.Fatal("expected at least one table, got none")
	}

	tableSet := make(map[string]bool)
	for _, tbl := range tables {
		tableSet[tbl] = true
	}
	if !tableSet["users"] {
		t.Errorf("expected 'users' in tables, got: %v", tables)
	}
	if !tableSet["orders"] {
		t.Errorf("expected 'orders' in tables, got: %v", tables)
	}
}

func TestExtractColumns(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT name, email FROM users WHERE active = true")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	columns := gosqlx.ExtractColumns(tree)
	if len(columns) == 0 {
		t.Fatal("expected at least one column, got none")
	}

	colSet := make(map[string]bool)
	for _, col := range columns {
		colSet[col] = true
	}
	if !colSet["name"] {
		t.Errorf("expected 'name' in columns, got: %v", columns)
	}
	if !colSet["email"] {
		t.Errorf("expected 'email' in columns, got: %v", columns)
	}
}

func TestExtractFunctions(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT COUNT(*), SUM(amount) FROM orders")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	functions := gosqlx.ExtractFunctions(tree)
	if len(functions) == 0 {
		t.Fatal("expected at least one function, got none")
	}

	funcSet := make(map[string]bool)
	for _, fn := range functions {
		funcSet[fn] = true
	}
	if !funcSet["COUNT"] {
		t.Errorf("expected 'COUNT' in functions, got: %v", functions)
	}
	if !funcSet["SUM"] {
		t.Errorf("expected 'SUM' in functions, got: %v", functions)
	}
}

func TestExtractMetadata(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT u.name, COUNT(*) FROM users u GROUP BY u.name")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	metadata := gosqlx.ExtractMetadata(tree)
	if metadata == nil {
		t.Fatal("expected non-nil metadata")
	}

	// Check tables
	tableSet := make(map[string]bool)
	for _, tbl := range metadata.Tables {
		tableSet[tbl] = true
	}
	if !tableSet["users"] {
		t.Errorf("expected 'users' in tables, got: %v", metadata.Tables)
	}

	// Check columns
	colSet := make(map[string]bool)
	for _, col := range metadata.Columns {
		colSet[col] = true
	}
	if !colSet["name"] {
		t.Errorf("expected 'name' in columns, got: %v", metadata.Columns)
	}

	// Check functions
	funcSet := make(map[string]bool)
	for _, fn := range metadata.Functions {
		funcSet[fn] = true
	}
	if !funcSet["COUNT"] {
		t.Errorf("expected 'COUNT' in functions, got: %v", metadata.Functions)
	}

	// Check qualified columns contain table qualifier
	foundQualified := false
	for _, qc := range metadata.ColumnsQualified {
		if qc.Table == "u" && qc.Name == "name" {
			foundQualified = true
			break
		}
	}
	if !foundQualified {
		t.Errorf("expected qualified column u.name, got: %v", metadata.ColumnsQualified)
	}
}

// ---------------------------------------------------------------------------
// JSON serialization tests for the C binding structs
// ---------------------------------------------------------------------------

func TestParseResultJSON(t *testing.T) {
	result := ParseResult{
		Success:   true,
		StmtCount: 1,
		StmtTypes: []string{"SELECT"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ParseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !decoded.Success {
		t.Error("expected success=true")
	}
	if decoded.StmtCount != 1 {
		t.Errorf("expected statement_count=1, got %d", decoded.StmtCount)
	}
	if len(decoded.StmtTypes) != 1 || decoded.StmtTypes[0] != "SELECT" {
		t.Errorf("expected statement_types=[SELECT], got %v", decoded.StmtTypes)
	}

	// Verify omitempty: error, error_line, error_column should be absent on success
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}
	if _, exists := raw["error"]; exists {
		t.Error("expected 'error' field to be omitted when empty")
	}
	if _, exists := raw["error_line"]; exists {
		t.Error("expected 'error_line' field to be omitted when zero")
	}
	if _, exists := raw["error_column"]; exists {
		t.Error("expected 'error_column' field to be omitted when zero")
	}
}

func TestValidationResultJSON(t *testing.T) {
	// Valid case
	validResult := ValidationResult{Valid: true}
	data, err := json.Marshal(validResult)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ValidationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !decoded.Valid {
		t.Error("expected valid=true")
	}
	if decoded.Error != "" {
		t.Errorf("expected empty error, got: %s", decoded.Error)
	}

	// Invalid case
	invalidResult := ValidationResult{
		Valid:       false,
		Error:       "unexpected token at line 1, column 5",
		ErrorLine:   1,
		ErrorColumn: 5,
	}
	data, err = json.Marshal(invalidResult)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decodedInvalid ValidationResult
	if err := json.Unmarshal(data, &decodedInvalid); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decodedInvalid.Valid {
		t.Error("expected valid=false")
	}
	if decodedInvalid.ErrorLine != 1 {
		t.Errorf("expected error_line=1, got %d", decodedInvalid.ErrorLine)
	}
	if decodedInvalid.ErrorColumn != 5 {
		t.Errorf("expected error_column=5, got %d", decodedInvalid.ErrorColumn)
	}
}

func TestFormatResultJSON(t *testing.T) {
	// Success case
	result := FormatResult{
		Success:   true,
		Formatted: "SELECT\n  *\nFROM\n  users",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded FormatResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !decoded.Success {
		t.Error("expected success=true")
	}
	if decoded.Formatted != "SELECT\n  *\nFROM\n  users" {
		t.Errorf("unexpected formatted output: %s", decoded.Formatted)
	}

	// Error case
	errResult := FormatResult{
		Success: false,
		Error:   "cannot format invalid SQL",
	}
	data, err = json.Marshal(errResult)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decodedErr FormatResult
	if err := json.Unmarshal(data, &decodedErr); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decodedErr.Success {
		t.Error("expected success=false")
	}
	if decodedErr.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestVersionConst(t *testing.T) {
	if VERSION == "" {
		t.Error("VERSION const must not be empty")
	}
	// Basic format check: should contain at least one dot
	hasDot := false
	for _, c := range VERSION {
		if c == '.' {
			hasDot = true
			break
		}
	}
	if !hasDot {
		t.Errorf("VERSION should be in semver format (contain a dot), got: %s", VERSION)
	}
}

// ---------------------------------------------------------------------------
// Tests for helper functions
// ---------------------------------------------------------------------------

func TestExtractErrorPosition(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLine int
		wantCol  int
	}{
		{
			name:     "standard format",
			input:    "unexpected token at line 3, column 15",
			wantLine: 3,
			wantCol:  15,
		},
		{
			name:     "line 1 column 1",
			input:    "error at line 1, column 1",
			wantLine: 1,
			wantCol:  1,
		},
		{
			name:     "no match",
			input:    "some random error",
			wantLine: 0,
			wantCol:  0,
		},
		{
			name:     "empty string",
			input:    "",
			wantLine: 0,
			wantCol:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, col := extractErrorPosition(tt.input)
			if line != tt.wantLine {
				t.Errorf("line: got %d, want %d", line, tt.wantLine)
			}
			if col != tt.wantCol {
				t.Errorf("column: got %d, want %d", col, tt.wantCol)
			}
		})
	}
}

func TestStatementTypeName(t *testing.T) {
	tests := []struct {
		stmt ast.Statement
		want string
	}{
		{&ast.SelectStatement{}, "SELECT"},
		{&ast.InsertStatement{}, "INSERT"},
		{&ast.UpdateStatement{}, "UPDATE"},
		{&ast.DeleteStatement{}, "DELETE"},
		{&ast.CreateTableStatement{}, "CREATE_TABLE"},
		{&ast.CreateViewStatement{}, "CREATE_VIEW"},
		{&ast.CreateIndexStatement{}, "CREATE_INDEX"},
		{&ast.AlterTableStatement{}, "ALTER_TABLE"},
		{&ast.DropStatement{}, "DROP"},
		{&ast.MergeStatement{}, "MERGE"},
		{&ast.TruncateStatement{}, "TRUNCATE"},
	}

	for _, tt := range tests {
		got := statementTypeName(tt.stmt)
		if got != tt.want {
			t.Errorf("statementTypeName(%T) = %q, want %q", tt.stmt, got, tt.want)
		}
	}
}

func TestMetadataResultJSON(t *testing.T) {
	result := MetadataResult{
		Tables: []string{"users"},
		TablesQualified: []QualifiedNameJSON{
			{Schema: "", Table: "", Name: "users"},
		},
		Columns: []string{"name"},
		ColumnsQualified: []QualifiedNameJSON{
			{Schema: "", Table: "u", Name: "name"},
		},
		Functions: []string{"COUNT"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded MetadataResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.Tables) != 1 || decoded.Tables[0] != "users" {
		t.Errorf("expected tables=[users], got %v", decoded.Tables)
	}
	if len(decoded.Columns) != 1 || decoded.Columns[0] != "name" {
		t.Errorf("expected columns=[name], got %v", decoded.Columns)
	}
	if len(decoded.Functions) != 1 || decoded.Functions[0] != "COUNT" {
		t.Errorf("expected functions=[COUNT], got %v", decoded.Functions)
	}
	if len(decoded.TablesQualified) != 1 || decoded.TablesQualified[0].Name != "users" {
		t.Errorf("expected tables_qualified with users, got %v", decoded.TablesQualified)
	}
	if len(decoded.ColumnsQualified) != 1 || decoded.ColumnsQualified[0].Table != "u" || decoded.ColumnsQualified[0].Name != "name" {
		t.Errorf("expected columns_qualified with u.name, got %v", decoded.ColumnsQualified)
	}
}
