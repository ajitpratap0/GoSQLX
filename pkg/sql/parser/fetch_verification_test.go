// Package parser - fetch_verification_test.go
// Comprehensive verification test for FETCH FIRST/OFFSET SQL:2008 standard pagination
// This test verifies all requirements from Issue #192

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestFetchVerification_AllRequirements verifies all requirements from Issue #192
func TestFetchVerification_AllRequirements(t *testing.T) {
	tests := []struct {
		name              string
		sql               string
		wantFetchType     string
		wantFetchVal      int64
		wantWithTies      bool
		wantIsPercent     bool
		wantOffset        *int
		wantOrderByCount  int
		shouldHaveOrderBy bool
	}{
		{
			name:              "FETCH FIRST 10 ROWS ONLY",
			sql:               "SELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY",
			wantFetchType:     "FIRST",
			wantFetchVal:      10,
			wantWithTies:      false,
			wantIsPercent:     false,
			wantOrderByCount:  1,
			shouldHaveOrderBy: true,
		},
		{
			name:              "FETCH FIRST 5 ROW ONLY (singular)",
			sql:               "SELECT * FROM products FETCH FIRST 5 ROW ONLY",
			wantFetchType:     "FIRST",
			wantFetchVal:      5,
			wantWithTies:      false,
			wantIsPercent:     false,
			shouldHaveOrderBy: false,
		},
		{
			name:              "OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
			sql:               "SELECT * FROM users ORDER BY id OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
			wantFetchType:     "NEXT",
			wantFetchVal:      10,
			wantWithTies:      false,
			wantIsPercent:     false,
			wantOffset:        intPtr(20),
			wantOrderByCount:  1,
			shouldHaveOrderBy: true,
		},
		{
			name:              "FETCH FIRST 10 PERCENT ROWS ONLY",
			sql:               "SELECT * FROM users FETCH FIRST 10 PERCENT ROWS ONLY",
			wantFetchType:     "FIRST",
			wantFetchVal:      10,
			wantWithTies:      false,
			wantIsPercent:     true,
			shouldHaveOrderBy: false,
		},
		{
			name:              "FETCH FIRST 5 ROWS WITH TIES",
			sql:               "SELECT * FROM products ORDER BY price FETCH FIRST 5 ROWS WITH TIES",
			wantFetchType:     "FIRST",
			wantFetchVal:      5,
			wantWithTies:      true,
			wantIsPercent:     false,
			wantOrderByCount:  1,
			shouldHaveOrderBy: true,
		},
		{
			name:              "FETCH NEXT (alternative to FIRST)",
			sql:               "SELECT * FROM orders FETCH NEXT 15 ROWS ONLY",
			wantFetchType:     "NEXT",
			wantFetchVal:      15,
			wantWithTies:      false,
			wantIsPercent:     false,
			shouldHaveOrderBy: false,
		},
		{
			name:              "PERCENT with WITH TIES",
			sql:               "SELECT * FROM products ORDER BY rating DESC FETCH FIRST 25 PERCENT ROWS WITH TIES",
			wantFetchType:     "FIRST",
			wantFetchVal:      25,
			wantWithTies:      true,
			wantIsPercent:     true,
			wantOrderByCount:  1,
			shouldHaveOrderBy: true,
		},
		{
			name:              "Multiple ORDER BY columns with FETCH",
			sql:               "SELECT * FROM users ORDER BY department, salary DESC FETCH FIRST 10 ROWS ONLY",
			wantFetchType:     "FIRST",
			wantFetchVal:      10,
			wantWithTies:      false,
			wantIsPercent:     false,
			wantOrderByCount:  2,
			shouldHaveOrderBy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := parseSQL(t, tt.sql)

			if stmt == nil || len(stmt.Statements) == 0 {
				t.Fatal("expected statement")
			}

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
			}

			// Verify FETCH clause
			if selectStmt.Fetch == nil {
				t.Fatal("expected Fetch clause, got nil")
			}

			fetch := selectStmt.Fetch

			// Verify FetchType (FIRST or NEXT)
			if fetch.FetchType != tt.wantFetchType {
				t.Errorf("FetchType = %q, want %q", fetch.FetchType, tt.wantFetchType)
			}

			// Verify FetchValue
			if fetch.FetchValue == nil {
				t.Fatal("expected FetchValue, got nil")
			}
			if *fetch.FetchValue != tt.wantFetchVal {
				t.Errorf("FetchValue = %d, want %d", *fetch.FetchValue, tt.wantFetchVal)
			}

			// Verify WithTies
			if fetch.WithTies != tt.wantWithTies {
				t.Errorf("WithTies = %v, want %v", fetch.WithTies, tt.wantWithTies)
			}

			// Verify IsPercent
			if fetch.IsPercent != tt.wantIsPercent {
				t.Errorf("IsPercent = %v, want %v", fetch.IsPercent, tt.wantIsPercent)
			}

			// Verify OFFSET if specified
			if tt.wantOffset != nil {
				if selectStmt.Offset == nil {
					t.Fatalf("expected Offset = %d, got nil", *tt.wantOffset)
				}
				if *selectStmt.Offset != *tt.wantOffset {
					t.Errorf("Offset = %d, want %d", *selectStmt.Offset, *tt.wantOffset)
				}
			}

			// Verify ORDER BY if specified
			if tt.shouldHaveOrderBy {
				if len(selectStmt.OrderBy) == 0 {
					t.Error("expected ORDER BY clause")
				}
				if len(selectStmt.OrderBy) != tt.wantOrderByCount {
					t.Errorf("OrderBy count = %d, want %d", len(selectStmt.OrderBy), tt.wantOrderByCount)
				}
			}
		})
	}
}

// TestFetchVerification_EdgeCases tests edge cases and variations
func TestFetchVerification_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		sql         string
		expectError bool
		description string
	}{
		{
			name:        "FETCH without ORDER BY",
			sql:         "SELECT * FROM products FETCH FIRST 10 ROWS ONLY",
			expectError: false,
			description: "FETCH should work without ORDER BY",
		},
		{
			name:        "FETCH with WHERE",
			sql:         "SELECT * FROM users WHERE id > 100 FETCH FIRST 10 ROWS ONLY",
			expectError: false,
			description: "FETCH should work with WHERE clause",
		},
		{
			name:        "FETCH with GROUP BY",
			sql:         "SELECT department, COUNT(*) FROM users GROUP BY department FETCH FIRST 5 ROWS ONLY",
			expectError: false,
			description: "FETCH should work with GROUP BY",
		},
		{
			name:        "FETCH with HAVING",
			sql:         "SELECT department, COUNT(*) FROM users GROUP BY department HAVING COUNT(*) > 10 FETCH FIRST 5 ROWS ONLY",
			expectError: false,
			description: "FETCH should work with HAVING",
		},
		{
			name:        "OFFSET without FETCH",
			sql:         "SELECT * FROM users OFFSET 10 ROWS",
			expectError: false,
			description: "OFFSET should work standalone",
		},
		{
			name:        "FETCH value = 1 (edge case)",
			sql:         "SELECT * FROM users FETCH FIRST 1 ROW ONLY",
			expectError: false,
			description: "FETCH should work with count = 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := parseSQL(t, tt.sql)

			if tt.expectError {
				if stmt != nil {
					t.Errorf("expected error but parsing succeeded: %s", tt.description)
				}
				return
			}

			if stmt == nil || len(stmt.Statements) == 0 {
				t.Fatalf("parsing failed: %s", tt.description)
			}

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T: %s", stmt.Statements[0], tt.description)
			}

			// Basic validation that the statement was parsed
			if selectStmt == nil {
				t.Fatalf("selectStmt is nil: %s", tt.description)
			}

			t.Logf("✓ %s", tt.description)
		})
	}
}

// TestFetchVerification_TokenTypes verifies all required token types exist
func TestFetchVerification_TokenTypes(t *testing.T) {
	// This test verifies that all required token types for FETCH clause are defined
	// Token types should be defined in pkg/models/token_type.go

	// We'll parse a query that uses all the tokens and verify it works
	sql := "SELECT * FROM users ORDER BY id OFFSET 5 ROWS FETCH FIRST 10 PERCENT ROWS WITH TIES"

	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("failed to parse query with all FETCH tokens")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	// Verify all components are present
	if selectStmt.Offset == nil {
		t.Error("OFFSET token not properly recognized")
	}

	if selectStmt.Fetch == nil {
		t.Fatal("FETCH token not properly recognized")
	}

	fetch := selectStmt.Fetch

	// Verify FIRST/NEXT token
	if fetch.FetchType != "FIRST" {
		t.Errorf("FIRST token not properly recognized, got %q", fetch.FetchType)
	}

	// Verify PERCENT token
	if !fetch.IsPercent {
		t.Error("PERCENT token not properly recognized")
	}

	// Verify WITH TIES tokens
	if !fetch.WithTies {
		t.Error("WITH TIES tokens not properly recognized")
	}

	// Verify ROWS/ROW token (implicitly tested by successful parsing)
	// Verify ONLY token (implicitly tested by WithTies = false would mean ONLY)

	t.Log("✓ All FETCH-related token types are properly defined and recognized")
}

// Helper function
func intPtr(i int) *int {
	return &i
}
