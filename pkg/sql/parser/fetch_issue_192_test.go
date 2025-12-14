// Package parser - fetch_issue_192_test.go
// Tests for GitHub issue #192: Support FETCH FIRST/OFFSET (SQL:2008 standard pagination)
//
// This file tests all the example SQL queries from the issue to ensure full support.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestIssue192_FetchFirstBasic tests basic FETCH FIRST syntax
func TestIssue192_FetchFirstBasic(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		wantFetchType string
		wantFetchVal  int64
		wantWithTies  bool
		wantIsPercent bool
	}{
		{
			name:          "FETCH FIRST 10 ROWS ONLY",
			sql:           "SELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY",
			wantFetchType: "FIRST",
			wantFetchVal:  10,
			wantWithTies:  false,
			wantIsPercent: false,
		},
		{
			name:          "FETCH FIRST 5 ROW ONLY (singular)",
			sql:           "SELECT * FROM products FETCH FIRST 5 ROW ONLY",
			wantFetchType: "FIRST",
			wantFetchVal:  5,
			wantWithTies:  false,
			wantIsPercent: false,
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

			if selectStmt.Fetch == nil {
				t.Fatal("expected Fetch clause, got nil")
			}

			fetch := selectStmt.Fetch

			if fetch.FetchType != tt.wantFetchType {
				t.Errorf("FetchType = %q, want %q", fetch.FetchType, tt.wantFetchType)
			}

			if fetch.FetchValue == nil {
				t.Fatal("expected FetchValue, got nil")
			}

			if *fetch.FetchValue != tt.wantFetchVal {
				t.Errorf("FetchValue = %d, want %d", *fetch.FetchValue, tt.wantFetchVal)
			}

			if fetch.WithTies != tt.wantWithTies {
				t.Errorf("WithTies = %v, want %v", fetch.WithTies, tt.wantWithTies)
			}

			if fetch.IsPercent != tt.wantIsPercent {
				t.Errorf("IsPercent = %v, want %v", fetch.IsPercent, tt.wantIsPercent)
			}
		})
	}
}

// TestIssue192_WithOffset tests FETCH with OFFSET clause
func TestIssue192_WithOffset(t *testing.T) {
	sql := "SELECT * FROM users ORDER BY id OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY"

	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	// Check OFFSET
	if selectStmt.Offset == nil {
		t.Fatal("expected Offset clause, got nil")
	}

	if *selectStmt.Offset != 20 {
		t.Errorf("Offset = %d, want 20", *selectStmt.Offset)
	}

	// Check FETCH
	if selectStmt.Fetch == nil {
		t.Fatal("expected Fetch clause, got nil")
	}

	fetch := selectStmt.Fetch

	if fetch.FetchType != "NEXT" {
		t.Errorf("FetchType = %q, want %q", fetch.FetchType, "NEXT")
	}

	if fetch.FetchValue == nil {
		t.Fatal("expected FetchValue, got nil")
	}

	if *fetch.FetchValue != 10 {
		t.Errorf("FetchValue = %d, want 10", *fetch.FetchValue)
	}

	if fetch.WithTies {
		t.Error("WithTies should be false")
	}

	if fetch.IsPercent {
		t.Error("IsPercent should be false")
	}
}

// TestIssue192_Percentage tests FETCH with PERCENT
func TestIssue192_Percentage(t *testing.T) {
	sql := "SELECT * FROM users FETCH FIRST 10 PERCENT ROWS ONLY"

	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	if selectStmt.Fetch == nil {
		t.Fatal("expected Fetch clause, got nil")
	}

	fetch := selectStmt.Fetch

	if fetch.FetchType != "FIRST" {
		t.Errorf("FetchType = %q, want %q", fetch.FetchType, "FIRST")
	}

	if fetch.FetchValue == nil {
		t.Fatal("expected FetchValue, got nil")
	}

	if *fetch.FetchValue != 10 {
		t.Errorf("FetchValue = %d, want 10", *fetch.FetchValue)
	}

	if !fetch.IsPercent {
		t.Error("IsPercent should be true")
	}

	if fetch.WithTies {
		t.Error("WithTies should be false")
	}
}

// TestIssue192_WithTies tests FETCH with WITH TIES
func TestIssue192_WithTies(t *testing.T) {
	sql := "SELECT * FROM products ORDER BY price FETCH FIRST 5 ROWS WITH TIES"

	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	if selectStmt.Fetch == nil {
		t.Fatal("expected Fetch clause, got nil")
	}

	fetch := selectStmt.Fetch

	if fetch.FetchType != "FIRST" {
		t.Errorf("FetchType = %q, want %q", fetch.FetchType, "FIRST")
	}

	if fetch.FetchValue == nil {
		t.Fatal("expected FetchValue, got nil")
	}

	if *fetch.FetchValue != 5 {
		t.Errorf("FetchValue = %d, want 5", *fetch.FetchValue)
	}

	if !fetch.WithTies {
		t.Error("WithTies should be true")
	}

	if fetch.IsPercent {
		t.Error("IsPercent should be false")
	}
}

// TestIssue192_AllExamples tests all examples from the issue
func TestIssue192_AllExamples(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "Basic FETCH FIRST",
			sql:  "SELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY",
		},
		{
			name: "Basic FETCH FIRST singular ROW",
			sql:  "SELECT * FROM products FETCH FIRST 5 ROW ONLY",
		},
		{
			name: "With OFFSET",
			sql:  "SELECT * FROM users ORDER BY id OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
		},
		{
			name: "Percentage",
			sql:  "SELECT * FROM users FETCH FIRST 10 PERCENT ROWS ONLY",
		},
		{
			name: "WITH TIES",
			sql:  "SELECT * FROM products ORDER BY price FETCH FIRST 5 ROWS WITH TIES",
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

			if selectStmt.Fetch == nil {
				t.Error("expected Fetch clause")
			}
		})
	}
}
