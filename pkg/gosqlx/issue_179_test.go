// Package gosqlx - issue_179_test.go
// End-to-end tests for GitHub issue #179: Multi-row INSERT VALUES syntax
// Tests the high-level gosqlx API for parsing multi-row INSERT statements

package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestIssue179_BasicMultiRowInsert tests basic multi-row INSERT parsing via gosqlx API
func TestIssue179_BasicMultiRowInsert(t *testing.T) {
	sql := `INSERT INTO users (name, email) VALUES
		('John', 'john@example.com'),
		('Jane', 'jane@example.com'),
		('Bob', 'bob@example.com')`

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if astResult == nil {
		t.Fatal("expected AST, got nil")
	}

	if len(astResult.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}

	insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
	}

	// Verify table name
	if insertStmt.TableName != "users" {
		t.Errorf("expected table name 'users', got %q", insertStmt.TableName)
	}

	// Verify column count
	if len(insertStmt.Columns) != 2 {
		t.Errorf("expected 2 columns, got %d", len(insertStmt.Columns))
	}

	// Verify row count
	if len(insertStmt.Values) != 3 {
		t.Errorf("expected 3 rows, got %d", len(insertStmt.Values))
	}

	// Verify each row has 2 values
	for i, row := range insertStmt.Values {
		if len(row) != 2 {
			t.Errorf("row %d: expected 2 values, got %d", i, len(row))
		}
	}
}

// TestIssue179_Validate tests that Validate accepts multi-row INSERT
func TestIssue179_Validate(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Two rows",
			sql:  "INSERT INTO users (name) VALUES ('Alice'), ('Bob')",
		},
		{
			name: "Three rows with multiple columns",
			sql:  "INSERT INTO products (id, name, price) VALUES (1, 'Widget', 9.99), (2, 'Gadget', 19.99), (3, 'Thing', 29.99)",
		},
		{
			name: "Without column list",
			sql:  "INSERT INTO data VALUES (1, 'a'), (2, 'b'), (3, 'c')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.sql)
			if err != nil {
				t.Errorf("Validate failed: %v", err)
			}
		})
	}
}

// TestIssue179_MultiRowWithReturning tests multi-row INSERT with RETURNING clause
func TestIssue179_MultiRowWithReturning(t *testing.T) {
	sql := `INSERT INTO users (name, email)
		VALUES ('John', 'john@test.com'), ('Jane', 'jane@test.com')
		RETURNING id, created_at`

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
	}

	// Verify multi-row
	if len(insertStmt.Values) != 2 {
		t.Errorf("expected 2 rows, got %d", len(insertStmt.Values))
	}

	// Verify RETURNING clause
	if len(insertStmt.Returning) != 2 {
		t.Errorf("expected 2 RETURNING columns, got %d", len(insertStmt.Returning))
	}
}

// TestIssue179_MultiRowWithOnConflict tests multi-row INSERT with ON CONFLICT (upsert)
func TestIssue179_MultiRowWithOnConflict(t *testing.T) {
	sql := `INSERT INTO users (id, name, email)
		VALUES (1, 'John', 'john@test.com'), (2, 'Jane', 'jane@test.com')
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
	}

	// Verify multi-row
	if len(insertStmt.Values) != 2 {
		t.Errorf("expected 2 rows, got %d", len(insertStmt.Values))
	}

	// Verify ON CONFLICT clause
	if insertStmt.OnConflict == nil {
		t.Error("expected ON CONFLICT clause, got nil")
	}
}

// TestIssue179_LargeMultiRowInsert tests parsing of INSERT with many rows
func TestIssue179_LargeMultiRowInsert(t *testing.T) {
	// Build SQL with 100 rows to test performance and correctness
	sql := "INSERT INTO data (id, value) VALUES "
	for i := 1; i <= 100; i++ {
		if i > 1 {
			sql += ", "
		}
		// Use actual values instead of placeholders
		sql += "(1, 'value')"
	}

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
	}

	// Verify 100 rows
	if len(insertStmt.Values) != 100 {
		t.Errorf("expected 100 rows, got %d", len(insertStmt.Values))
	}

	// Verify each row has 2 values
	for i, row := range insertStmt.Values {
		if len(row) != 2 {
			t.Errorf("row %d: expected 2 values, got %d", i, len(row))
		}
	}
}

// TestIssue179_ComplexExpressions tests multi-row INSERT with complex value expressions
func TestIssue179_ComplexExpressions(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Function calls",
			sql:  "INSERT INTO events (id, created_at) VALUES (UUID(), NOW()), (UUID(), NOW())",
		},
		{
			name: "Arithmetic expressions",
			sql:  "INSERT INTO math (a, b, sum) VALUES (1, 2, 1 + 2), (3, 4, 3 + 4)",
		},
		{
			name: "CASE expressions",
			sql:  "INSERT INTO grades (score, grade) VALUES (95, CASE WHEN 95 >= 90 THEN 'A' END), (85, CASE WHEN 85 >= 90 THEN 'A' END)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astResult, err := Parse(tt.sql)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
			}

			// Verify we have multiple rows
			if len(insertStmt.Values) < 2 {
				t.Errorf("expected at least 2 rows, got %d", len(insertStmt.Values))
			}
		})
	}
}

// TestIssue179_BackwardCompatibility ensures single-row INSERT still works
func TestIssue179_BackwardCompatibility(t *testing.T) {
	sql := "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	insertStmt, ok := astResult.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", astResult.Statements[0])
	}

	// Verify single row (backward compatibility)
	if len(insertStmt.Values) != 1 {
		t.Errorf("expected 1 row, got %d", len(insertStmt.Values))
	}

	// Verify first row has 2 values
	if len(insertStmt.Values[0]) != 2 {
		t.Errorf("expected 2 values in first row, got %d", len(insertStmt.Values[0]))
	}
}
