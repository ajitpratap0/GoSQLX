package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromDDL_SimpleTable(t *testing.T) {
	ddl := `CREATE TABLE users (id INT, name VARCHAR(100), email VARCHAR(255))`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	table, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected to find table 'users'")
	}

	expectedCols := []string{"email", "id", "name"}
	gotCols := table.ColumnNames()
	if len(gotCols) != len(expectedCols) {
		t.Fatalf("expected %d columns, got %d: %v", len(expectedCols), len(gotCols), gotCols)
	}
	for i, col := range gotCols {
		if col != expectedCols[i] {
			t.Fatalf("expected column %q at index %d, got %q", expectedCols[i], i, col)
		}
	}
}

func TestLoadFromDDL_MultipleTables(t *testing.T) {
	ddl := `
		CREATE TABLE users (id INT, name VARCHAR(100));
		CREATE TABLE orders (id INT, user_id INT, total DECIMAL)
	`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	names := s.TableNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 tables, got %d: %v", len(names), names)
	}

	if _, ok := s.GetTable("users"); !ok {
		t.Fatal("expected to find table 'users'")
	}
	if _, ok := s.GetTable("orders"); !ok {
		t.Fatal("expected to find table 'orders'")
	}
}

func TestLoadFromDDL_WithNotNull(t *testing.T) {
	ddl := `CREATE TABLE users (id INT NOT NULL, name VARCHAR(100), email VARCHAR(255) NOT NULL)`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	table, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected to find table 'users'")
	}

	// id should be NOT NULL
	idCol, ok := table.GetColumn("id")
	if !ok {
		t.Fatal("expected to find column 'id'")
	}
	if idCol.Nullable {
		t.Fatal("expected 'id' to be NOT NULL")
	}

	// name should be nullable (no constraint)
	nameCol, ok := table.GetColumn("name")
	if !ok {
		t.Fatal("expected to find column 'name'")
	}
	if !nameCol.Nullable {
		t.Fatal("expected 'name' to be nullable")
	}

	// email should be NOT NULL
	emailCol, ok := table.GetColumn("email")
	if !ok {
		t.Fatal("expected to find column 'email'")
	}
	if emailCol.Nullable {
		t.Fatal("expected 'email' to be NOT NULL")
	}
}

func TestLoadFromDDL_WithPrimaryKey(t *testing.T) {
	ddl := `CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100))`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	table, ok := s.GetTable("users")
	if !ok {
		t.Fatal("expected to find table 'users'")
	}

	if len(table.PrimaryKey) != 1 || table.PrimaryKey[0] != "id" {
		t.Fatalf("expected primary key [id], got %v", table.PrimaryKey)
	}

	// PK column should be NOT NULL
	idCol, ok := table.GetColumn("id")
	if !ok {
		t.Fatal("expected to find column 'id'")
	}
	if idCol.Nullable {
		t.Fatal("expected PK column 'id' to be NOT NULL")
	}
}

func TestLoadFromDDL_WithIfNotExists(t *testing.T) {
	ddl := `CREATE TABLE IF NOT EXISTS users (id INT, name VARCHAR(100))`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	if _, ok := s.GetTable("users"); !ok {
		t.Fatal("expected to find table 'users' even with IF NOT EXISTS")
	}
}

func TestLoadFromDDL_ColumnDataTypes(t *testing.T) {
	ddl := `CREATE TABLE types_test (
		int_col INT,
		varchar_col VARCHAR(255),
		decimal_col DECIMAL,
		text_col TEXT,
		bool_col BOOLEAN
	)`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	table, ok := s.GetTable("types_test")
	if !ok {
		t.Fatal("expected to find table 'types_test'")
	}

	tests := []struct {
		colName  string
		dataType string
	}{
		{"int_col", "INT"},
		{"varchar_col", "VARCHAR(255)"},
		{"decimal_col", "DECIMAL"},
		{"text_col", "TEXT"},
		{"bool_col", "BOOLEAN"},
	}

	for _, tt := range tests {
		col, ok := table.GetColumn(tt.colName)
		if !ok {
			t.Fatalf("expected to find column %q", tt.colName)
		}
		if col.DataType != tt.dataType {
			t.Fatalf("expected column %q data type %q, got %q", tt.colName, tt.dataType, col.DataType)
		}
	}
}

func TestLoadFromDDL_InvalidSQL(t *testing.T) {
	ddl := `NOT VALID SQL AT ALL`
	_, err := LoadFromDDL(ddl)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestLoadFromDDL_EmptyInput(t *testing.T) {
	// Empty string may either be an error from the parser or produce an empty schema
	s, err := LoadFromDDL("")
	if err != nil {
		// Parser may reject empty input, which is fine
		return
	}
	if len(s.Tables) != 0 {
		t.Fatalf("expected 0 tables for empty input, got %d", len(s.Tables))
	}
}

func TestLoadFromDDLFile(t *testing.T) {
	// Create a temporary DDL file
	dir := t.TempDir()
	path := filepath.Join(dir, "schema.sql")

	ddl := `CREATE TABLE users (id INT, name VARCHAR(100));
CREATE TABLE orders (id INT, user_id INT, total DECIMAL)`

	if err := os.WriteFile(path, []byte(ddl), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	s, err := LoadFromDDLFile(path)
	if err != nil {
		t.Fatalf("LoadFromDDLFile failed: %v", err)
	}

	if len(s.Tables) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(s.Tables))
	}
}

func TestLoadFromDDLFile_NonexistentFile(t *testing.T) {
	_, err := LoadFromDDLFile("/nonexistent/path/schema.sql")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadFromDDL_SchemaName(t *testing.T) {
	ddl := `CREATE TABLE users (id INT)`
	s, err := LoadFromDDL(ddl)
	if err != nil {
		t.Fatalf("LoadFromDDL failed: %v", err)
	}

	if s.Name != "default" {
		t.Fatalf("expected schema name %q, got %q", "default", s.Name)
	}
}
