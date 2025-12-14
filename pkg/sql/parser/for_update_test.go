// Package parser - for_update_test.go
// Tests for GitHub issue #194: Support SELECT FOR UPDATE/SHARE (row locking)
//
// This file tests all the example SQL queries from the issue to ensure full support.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestForUpdateBasic tests basic FOR UPDATE syntax
func TestForUpdateBasic(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		wantLockType string
		wantNoWait   bool
		wantSkipLock bool
		wantTables   []string
	}{
		{
			name:         "FOR UPDATE",
			sql:          "SELECT * FROM accounts WHERE id = 1 FOR UPDATE",
			wantLockType: "UPDATE",
			wantNoWait:   false,
			wantSkipLock: false,
			wantTables:   nil,
		},
		{
			name:         "FOR SHARE",
			sql:          "SELECT * FROM products WHERE category = 'electronics' FOR SHARE",
			wantLockType: "SHARE",
			wantNoWait:   false,
			wantSkipLock: false,
			wantTables:   nil,
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

			if selectStmt.For == nil {
				t.Fatal("expected For clause, got nil")
			}

			forClause := selectStmt.For

			if forClause.LockType != tt.wantLockType {
				t.Errorf("LockType = %q, want %q", forClause.LockType, tt.wantLockType)
			}

			if forClause.NoWait != tt.wantNoWait {
				t.Errorf("NoWait = %v, want %v", forClause.NoWait, tt.wantNoWait)
			}

			if forClause.SkipLocked != tt.wantSkipLock {
				t.Errorf("SkipLocked = %v, want %v", forClause.SkipLocked, tt.wantSkipLock)
			}

			if len(forClause.Tables) != len(tt.wantTables) {
				t.Errorf("Tables length = %d, want %d", len(forClause.Tables), len(tt.wantTables))
			}
		})
	}
}

// TestForUpdateWithNoWait tests FOR UPDATE with NOWAIT
func TestForUpdateWithNoWait(t *testing.T) {
	sql := "SELECT * FROM inventory WHERE sku = 'ABC' FOR UPDATE NOWAIT"
	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	if selectStmt.For == nil {
		t.Fatal("expected For clause, got nil")
	}

	forClause := selectStmt.For

	if forClause.LockType != "UPDATE" {
		t.Errorf("LockType = %q, want %q", forClause.LockType, "UPDATE")
	}

	if !forClause.NoWait {
		t.Error("expected NoWait = true")
	}

	if forClause.SkipLocked {
		t.Error("expected SkipLocked = false")
	}
}

// TestForUpdateWithSkipLocked tests FOR UPDATE with SKIP LOCKED
func TestForUpdateWithSkipLocked(t *testing.T) {
	sql := "SELECT * FROM jobs WHERE status = 'pending' FOR UPDATE SKIP LOCKED"
	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	if selectStmt.For == nil {
		t.Fatal("expected For clause, got nil")
	}

	forClause := selectStmt.For

	if forClause.LockType != "UPDATE" {
		t.Errorf("LockType = %q, want %q", forClause.LockType, "UPDATE")
	}

	if forClause.NoWait {
		t.Error("expected NoWait = false")
	}

	if !forClause.SkipLocked {
		t.Error("expected SkipLocked = true")
	}
}

// TestForUpdateOfTables tests FOR UPDATE OF table_name
func TestForUpdateOfTables(t *testing.T) {
	tests := []struct {
		name       string
		sql        string
		wantTables []string
	}{
		{
			name:       "FOR UPDATE OF single table",
			sql:        "SELECT * FROM orders o JOIN items i ON o.id = i.order_id FOR UPDATE OF orders",
			wantTables: []string{"orders"},
		},
		{
			name:       "FOR UPDATE OF multiple tables",
			sql:        "SELECT * FROM a JOIN b ON a.id = b.a_id FOR UPDATE OF a, b",
			wantTables: []string{"a", "b"},
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

			if selectStmt.For == nil {
				t.Fatal("expected For clause, got nil")
			}

			forClause := selectStmt.For

			if forClause.LockType != "UPDATE" {
				t.Errorf("LockType = %q, want %q", forClause.LockType, "UPDATE")
			}

			if len(forClause.Tables) != len(tt.wantTables) {
				t.Fatalf("Tables length = %d, want %d", len(forClause.Tables), len(tt.wantTables))
			}

			for i, table := range tt.wantTables {
				if forClause.Tables[i] != table {
					t.Errorf("Tables[%d] = %q, want %q", i, forClause.Tables[i], table)
				}
			}
		})
	}
}

// TestPostgreSQLLockModes tests PostgreSQL-specific lock modes
func TestPostgreSQLLockModes(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		wantLockType string
	}{
		{
			name:         "FOR NO KEY UPDATE",
			sql:          "SELECT * FROM accounts FOR NO KEY UPDATE",
			wantLockType: "NO KEY UPDATE",
		},
		{
			name:         "FOR KEY SHARE",
			sql:          "SELECT * FROM products FOR KEY SHARE",
			wantLockType: "KEY SHARE",
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

			if selectStmt.For == nil {
				t.Fatal("expected For clause, got nil")
			}

			forClause := selectStmt.For

			if forClause.LockType != tt.wantLockType {
				t.Errorf("LockType = %q, want %q", forClause.LockType, tt.wantLockType)
			}
		})
	}
}

// TestNoForClause tests that queries without FOR clause don't have it set
func TestNoForClause(t *testing.T) {
	sql := "SELECT * FROM users WHERE active = true"
	stmt := parseSQL(t, sql)

	if stmt == nil || len(stmt.Statements) == 0 {
		t.Fatal("expected statement")
	}

	selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
	}

	if selectStmt.For != nil {
		t.Error("expected For clause to be nil for query without FOR clause")
	}
}
