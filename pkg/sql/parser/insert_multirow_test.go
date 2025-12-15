// Package parser - insert_multirow_test.go
// Comprehensive tests for multi-row INSERT VALUES syntax (GitHub issue #179)

package parser

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParser_InsertMultiRow_Basic tests basic multi-row INSERT statements
func TestParser_InsertMultiRow_Basic(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		expectedRows  int
		expectedCols  int
		expectedTable string
	}{
		{
			name:          "Single row INSERT (backwards compatibility)",
			sql:           "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
			expectedRows:  1,
			expectedCols:  2,
			expectedTable: "users",
		},
		{
			name:          "Two row INSERT",
			sql:           "INSERT INTO users (name, email) VALUES ('John', 'john@example.com'), ('Jane', 'jane@example.com')",
			expectedRows:  2,
			expectedCols:  2,
			expectedTable: "users",
		},
		{
			name:          "Three row INSERT",
			sql:           "INSERT INTO users (name, email) VALUES ('John', 'john@example.com'), ('Jane', 'jane@example.com'), ('Bob', 'bob@example.com')",
			expectedRows:  3,
			expectedCols:  2,
			expectedTable: "users",
		},
		{
			name:          "Many rows INSERT (10 rows)",
			sql:           "INSERT INTO users (id, name) VALUES (1, 'User1'), (2, 'User2'), (3, 'User3'), (4, 'User4'), (5, 'User5'), (6, 'User6'), (7, 'User7'), (8, 'User8'), (9, 'User9'), (10, 'User10')",
			expectedRows:  10,
			expectedCols:  2,
			expectedTable: "users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			result, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || len(result.Statements) == 0 {
				t.Fatal("expected parsed statement, got nil or empty")
			}

			stmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
			}

			// Check table name
			if stmt.TableName != tt.expectedTable {
				t.Errorf("expected table name %q, got %q", tt.expectedTable, stmt.TableName)
			}

			// Check number of rows
			if len(stmt.Values) != tt.expectedRows {
				t.Errorf("expected %d rows, got %d", tt.expectedRows, len(stmt.Values))
			}

			// Check number of columns in each row
			for i, row := range stmt.Values {
				if len(row) != tt.expectedCols {
					t.Errorf("row %d: expected %d columns, got %d", i, tt.expectedCols, len(row))
				}
			}

			// Check that column list matches
			if len(stmt.Columns) != tt.expectedCols {
				t.Errorf("expected %d columns in column list, got %d", tt.expectedCols, len(stmt.Columns))
			}
		})
	}
}

// TestParser_InsertMultiRow_DataTypes tests multi-row INSERT with various data types
func TestParser_InsertMultiRow_DataTypes(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Multi-row with integers",
			sql:  "INSERT INTO products (id, quantity, price) VALUES (1, 100, 999), (2, 200, 1499), (3, 50, 799)",
		},
		{
			name: "Multi-row with floats",
			sql:  "INSERT INTO measurements (sensor_id, temperature, humidity) VALUES (1, 23.5, 65.2), (2, 22.1, 70.5), (3, 24.8, 62.3)",
		},
		{
			name: "Multi-row with strings",
			sql:  "INSERT INTO tags (name, description) VALUES ('urgent', 'High priority item'), ('review', 'Needs review'), ('completed', 'Task completed')",
		},
		{
			name: "Multi-row with booleans",
			sql:  "INSERT INTO flags (name, enabled) VALUES ('feature_a', true), ('feature_b', false), ('feature_c', true)",
		},
		{
			name: "Multi-row with mixed types",
			sql:  "INSERT INTO users (id, name, age, active, score) VALUES (1, 'Alice', 30, true, 95.5), (2, 'Bob', 25, false, 87.3), (3, 'Charlie', 35, true, 92.1)",
		},
		{
			name: "Multi-row with NULL values",
			sql:  "INSERT INTO contacts (name, email, phone) VALUES ('John', 'john@test.com', NULL), ('Jane', NULL, '555-1234'), ('Bob', 'bob@test.com', '555-5678')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			result, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || len(result.Statements) == 0 {
				t.Fatal("expected parsed statement, got nil or empty")
			}

			stmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
			}

			// Verify we have multiple rows
			if len(stmt.Values) < 2 {
				t.Errorf("expected multiple rows, got %d", len(stmt.Values))
			}
		})
	}
}

// TestParser_InsertMultiRow_WithoutColumns tests multi-row INSERT without column list
func TestParser_InsertMultiRow_WithoutColumns(t *testing.T) {
	sql := "INSERT INTO users VALUES (1, 'Alice', 'alice@test.com'), (2, 'Bob', 'bob@test.com'), (3, 'Charlie', 'charlie@test.com')"

	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	result, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}

	// Should have no columns specified
	if len(stmt.Columns) != 0 {
		t.Errorf("expected 0 columns in column list, got %d", len(stmt.Columns))
	}

	// Should have 3 rows
	if len(stmt.Values) != 3 {
		t.Errorf("expected 3 rows, got %d", len(stmt.Values))
	}

	// Each row should have 3 values
	for i, row := range stmt.Values {
		if len(row) != 3 {
			t.Errorf("row %d: expected 3 values, got %d", i, len(row))
		}
	}
}

// TestParser_InsertMultiRow_ComplexExpressions tests multi-row INSERT with complex expressions
func TestParser_InsertMultiRow_ComplexExpressions(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Multi-row with function calls",
			sql:  "INSERT INTO events (id, created_at, updated_at) VALUES (UUID(), NOW(), NOW()), (UUID(), NOW(), NOW())",
		},
		{
			name: "Multi-row with arithmetic expressions",
			sql:  "INSERT INTO calculations (a, b, result) VALUES (10, 5, 10 + 5), (20, 10, 20 + 10), (30, 15, 30 + 15)",
		},
		{
			name: "Multi-row with comparison expressions",
			sql:  "INSERT INTO comparisons (x, y, is_greater) VALUES (5, 3, 5 > 3), (2, 8, 2 > 8), (10, 10, 10 > 10)",
		},
		{
			name: "Multi-row with CASE expressions",
			sql:  "INSERT INTO grades (score, grade) VALUES (95, CASE WHEN 95 >= 90 THEN 'A' ELSE 'B' END), (85, CASE WHEN 85 >= 90 THEN 'A' ELSE 'B' END)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			result, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || len(result.Statements) == 0 {
				t.Fatal("expected parsed statement, got nil or empty")
			}

			stmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
			}

			// Verify we have multiple rows
			if len(stmt.Values) < 2 {
				t.Errorf("expected at least 2 rows, got %d", len(stmt.Values))
			}
		})
	}
}

// TestParser_InsertMultiRow_WithOnConflict tests multi-row INSERT with ON CONFLICT clause
func TestParser_InsertMultiRow_WithOnConflict(t *testing.T) {
	sql := `INSERT INTO users (id, name, email)
            VALUES (1, 'John', 'john@test.com'), (2, 'Jane', 'jane@test.com'), (3, 'Bob', 'bob@test.com')
            ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email`

	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	result, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}

	// Should have 3 rows
	if len(stmt.Values) != 3 {
		t.Errorf("expected 3 rows, got %d", len(stmt.Values))
	}

	// Should have ON CONFLICT clause
	if stmt.OnConflict == nil {
		t.Error("expected ON CONFLICT clause, got nil")
	}
}

// TestParser_InsertMultiRow_WithReturning tests multi-row INSERT with RETURNING clause
func TestParser_InsertMultiRow_WithReturning(t *testing.T) {
	sql := `INSERT INTO users (name, email)
            VALUES ('John', 'john@test.com'), ('Jane', 'jane@test.com'), ('Bob', 'bob@test.com')
            RETURNING id, created_at`

	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	result, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}

	// Should have 3 rows
	if len(stmt.Values) != 3 {
		t.Errorf("expected 3 rows, got %d", len(stmt.Values))
	}

	// Should have RETURNING clause
	if len(stmt.Returning) == 0 {
		t.Error("expected RETURNING clause, got empty")
	}
}

// TestParser_InsertMultiRow_LargeDataset tests multi-row INSERT with many rows
func TestParser_InsertMultiRow_LargeDataset(t *testing.T) {
	// Build SQL with 50 rows
	sql := "INSERT INTO bulk_data (id, value) VALUES "
	for i := 1; i <= 50; i++ {
		if i > 1 {
			sql += ", "
		}
		// Use actual values instead of placeholders
		sql += fmt.Sprintf("(%d, 'value%d')", i, i)
	}

	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	result, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}

	// Should have 50 rows
	if len(stmt.Values) != 50 {
		t.Errorf("expected 50 rows, got %d", len(stmt.Values))
	}

	// Each row should have 2 values
	for i, row := range stmt.Values {
		if len(row) != 2 {
			t.Errorf("row %d: expected 2 values, got %d", i, len(row))
		}
	}
}

// TestParser_InsertMultiRow_EdgeCases tests edge cases for multi-row INSERT
func TestParser_InsertMultiRow_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		shouldErr bool
	}{
		{
			name:      "Single column multi-row",
			sql:       "INSERT INTO counters (count) VALUES (1), (2), (3), (4), (5)",
			shouldErr: false,
		},
		{
			name:      "Many columns single row",
			sql:       "INSERT INTO wide_table (c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) VALUES (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)",
			shouldErr: false,
		},
		{
			name:      "Many columns multi-row",
			sql:       "INSERT INTO wide_table (c1, c2, c3, c4, c5) VALUES (1, 2, 3, 4, 5), (6, 7, 8, 9, 10), (11, 12, 13, 14, 15)",
			shouldErr: false,
		},
		{
			name:      "Whitespace and newlines between rows",
			sql:       "INSERT INTO users (name, email) VALUES\n  ('John', 'john@test.com'),\n  ('Jane', 'jane@test.com'),\n  ('Bob', 'bob@test.com')",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			result, err := p.Parse(tokens)

			if tt.shouldErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil || len(result.Statements) == 0 {
					t.Error("expected parsed statement, got nil or empty")
				}
			}
		})
	}
}

// TestParser_InsertMultiRow_ValueConsistency tests that all rows have consistent value counts
func TestParser_InsertMultiRow_ValueConsistency(t *testing.T) {
	sql := "INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'alice@test.com'), (2, 'Bob', 'bob@test.com'), (3, 'Charlie', 'charlie@test.com')"

	tokens := tokenizeSQL(t, sql)

	p := NewParser()
	defer p.Release()

	result, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
	}

	// All rows should have the same number of values
	expectedValueCount := len(stmt.Columns)
	for i, row := range stmt.Values {
		if len(row) != expectedValueCount {
			t.Errorf("row %d: expected %d values (to match column count), got %d", i, expectedValueCount, len(row))
		}
	}
}

// TestParser_InsertMultiRow_PostgreSQLDialect tests PostgreSQL-specific multi-row features
func TestParser_InsertMultiRow_PostgreSQLDialect(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Multi-row with type casts",
			sql:  "INSERT INTO data (id, value) VALUES (1::integer, 'text'::text), (2::integer, 'more'::text)",
		},
		{
			name: "Multi-row with array values",
			sql:  "INSERT INTO arrays (id, tags) VALUES (1, ARRAY['tag1', 'tag2']), (2, ARRAY['tag3', 'tag4'])",
		},
		{
			name: "Multi-row with JSONB",
			sql:  "INSERT INTO json_data (id, data) VALUES (1, '{\"key\": \"value1\"}'::jsonb), (2, '{\"key\": \"value2\"}'::jsonb)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)

			p := NewParser()
			defer p.Release()

			result, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil || len(result.Statements) == 0 {
				t.Fatal("expected parsed statement, got nil or empty")
			}

			stmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", result.Statements[0])
			}

			// Verify we have multiple rows
			if len(stmt.Values) < 2 {
				t.Errorf("expected at least 2 rows, got %d", len(stmt.Values))
			}
		})
	}
}
