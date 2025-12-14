// Package gosqlx - issue_192_test.go
// End-to-end tests for GitHub issue #192 using the high-level gosqlx API

package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestIssue192_EndToEnd(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectFetch bool
		expectError bool
	}{
		{
			name:        "FETCH FIRST 10 ROWS ONLY",
			sql:         "SELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY",
			expectFetch: true,
			expectError: false,
		},
		{
			name:        "FETCH FIRST 5 ROW ONLY",
			sql:         "SELECT * FROM products FETCH FIRST 5 ROW ONLY",
			expectFetch: true,
			expectError: false,
		},
		{
			name:        "OFFSET with FETCH NEXT",
			sql:         "SELECT * FROM users ORDER BY id OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
			expectFetch: true,
			expectError: false,
		},
		{
			name:        "FETCH with PERCENT",
			sql:         "SELECT * FROM users FETCH FIRST 10 PERCENT ROWS ONLY",
			expectFetch: true,
			expectError: false,
		},
		{
			name:        "FETCH with WITH TIES",
			sql:         "SELECT * FROM products ORDER BY price FETCH FIRST 5 ROWS WITH TIES",
			expectFetch: true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			astResult, err := Parse(tt.sql)

			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectError {
				return
			}

			if astResult == nil {
				t.Fatal("expected AST, got nil")
			}

			if len(astResult.Statements) == 0 {
				t.Fatal("expected at least one statement")
			}

			selectStmt, ok := astResult.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", astResult.Statements[0])
			}

			if tt.expectFetch && selectStmt.Fetch == nil {
				t.Error("expected Fetch clause, got nil")
			}

			if !tt.expectFetch && selectStmt.Fetch != nil {
				t.Error("expected no Fetch clause")
			}
		})
	}
}

func TestIssue192_ValidateAndParse(t *testing.T) {
	sql := "SELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY"

	// Test Validate
	err := Validate(sql)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Test Parse
	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if astResult == nil {
		t.Fatal("expected AST, got nil")
	}

	selectStmt, ok := astResult.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", astResult.Statements[0])
	}

	if selectStmt.Fetch == nil {
		t.Fatal("expected Fetch clause, got nil")
	}

	fetch := selectStmt.Fetch

	if fetch.FetchType != "FIRST" {
		t.Errorf("FetchType = %q, want FIRST", fetch.FetchType)
	}

	if fetch.FetchValue == nil || *fetch.FetchValue != 10 {
		t.Errorf("FetchValue = %v, want 10", fetch.FetchValue)
	}
}

func TestIssue192_ComplexQuery(t *testing.T) {
	sql := `
		SELECT u.id, u.name, COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.id, u.name
		HAVING COUNT(o.id) > 0
		ORDER BY order_count DESC
		OFFSET 10 ROWS
		FETCH FIRST 20 ROWS WITH TIES
	`

	astResult, err := Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if astResult == nil {
		t.Fatal("expected AST, got nil")
	}

	selectStmt, ok := astResult.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", astResult.Statements[0])
	}

	// Check OFFSET
	if selectStmt.Offset == nil {
		t.Fatal("expected Offset, got nil")
	}
	if *selectStmt.Offset != 10 {
		t.Errorf("Offset = %d, want 10", *selectStmt.Offset)
	}

	// Check FETCH
	if selectStmt.Fetch == nil {
		t.Fatal("expected Fetch clause, got nil")
	}

	fetch := selectStmt.Fetch

	if fetch.FetchType != "FIRST" {
		t.Errorf("FetchType = %q, want FIRST", fetch.FetchType)
	}

	if fetch.FetchValue == nil || *fetch.FetchValue != 20 {
		t.Errorf("FetchValue = %v, want 20", fetch.FetchValue)
	}

	if !fetch.WithTies {
		t.Error("WithTies should be true")
	}

	if fetch.IsPercent {
		t.Error("IsPercent should be false")
	}
}
