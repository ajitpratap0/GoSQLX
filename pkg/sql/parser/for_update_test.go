// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package parser - for_update_test.go
// Tests for GitHub issue #194: Support SELECT FOR UPDATE/SHARE (row locking)
//
// This file tests all the example SQL queries from the issue to ensure full support.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
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

// TestForUpdateAfterLimit tests the PostgreSQL clause order where the
// locking clause precedes LIMIT / OFFSET (SELECT ... ORDER BY x FOR
// UPDATE SKIP LOCKED LIMIT n), the shape libpg_query accepts. The
// standard order LIMIT ... FOR UPDATE is covered above.
func TestForUpdateAfterLimit(t *testing.T) {
	tests := []struct {
		name   string
		sql    string
		limit  int
		offset int
	}{
		{
			name:  "FOR UPDATE then LIMIT",
			sql:   "SELECT id FROM t ORDER BY x FOR UPDATE LIMIT 100",
			limit: 100,
		},
		{
			name:  "FOR UPDATE SKIP LOCKED then LIMIT",
			sql:   "SELECT id FROM jobs ORDER BY priority FOR UPDATE SKIP LOCKED LIMIT 100",
			limit: 100,
		},
		{
			name:  "FOR SHARE NOWAIT then LIMIT",
			sql:   "SELECT id FROM t FOR SHARE NOWAIT LIMIT 1",
			limit: 1,
		},
		{
			name:   "FOR UPDATE OF then LIMIT OFFSET",
			sql:    "SELECT id FROM t FOR UPDATE OF t SKIP LOCKED LIMIT 100 OFFSET 5",
			limit:  100,
			offset: 5,
		},
	}

	// LIMIT ALL is a limit clause with no count: Limit stays nil and
	// Extras.LimitAll is set. Both orders around the locking clause are
	// valid PostgreSQL (libpg_query), and neither may combine with a
	// second limit clause (pinned by the error tests below).
	for _, sql := range []string{
		"SELECT id FROM t LIMIT ALL FOR UPDATE",
		"SELECT id FROM t FOR UPDATE LIMIT ALL",
	} {
		t.Run("LIMIT ALL: "+sql, func(t *testing.T) {
			stmt := parseSQL(t, sql)

			selectStmt, ok := stmt.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", stmt.Statements[0])
			}
			if selectStmt.For == nil {
				t.Fatal("expected For clause, got nil")
			}
			if selectStmt.Limit != nil || selectStmt.Extras == nil || !selectStmt.Extras.LimitAll {
				t.Fatalf("expected LIMIT ALL (Limit nil, LimitAll true), got Limit=%v LimitAll-via-Extras=%v",
					selectStmt.Limit, selectStmt.Extras != nil && selectStmt.Extras.LimitAll)
			}
		})
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

			if selectStmt.Limit == nil {
				t.Fatalf("expected LIMIT %d, got none", tt.limit)
			}

			if *selectStmt.Limit != tt.limit {
				t.Fatalf("LIMIT = %d, want %d", *selectStmt.Limit, tt.limit)
			}

			if tt.offset == 0 {
				if selectStmt.Offset != nil {
					t.Fatalf("unexpected OFFSET %d", *selectStmt.Offset)
				}
				return
			}
			if selectStmt.Offset == nil || *selectStmt.Offset != tt.offset {
				t.Fatalf("OFFSET = %+v, want %d", selectStmt.Offset, tt.offset)
			}
		})
	}
}

// TestForUpdateAfterLimitErrors pins that limit-clause tokens cannot be
// repeated: a second LIMIT before the locking clause, a second LIMIT after
// it, or a duplicate OFFSET / FETCH after it are all rejected, matching
// PostgreSQL's own grammar.
func TestForUpdateAfterLimitErrors(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM t LIMIT 5 LIMIT 10",
		"SELECT id FROM t FOR UPDATE LIMIT 5 LIMIT 10",
		"SELECT id FROM t FOR UPDATE OFFSET 5 OFFSET 3",
		"SELECT id FROM t FOR UPDATE FETCH FIRST 1 ROWS ONLY FETCH FIRST 2 ROWS ONLY",
	} {
		t.Run(sql, func(t *testing.T) {
			_, err := parseSQLMayFail(t, sql)
			if err == nil {
				t.Fatalf("parse(%q): expected error for repeated LIMIT, got none", sql)
			}
		})
	}
}

// TestForUpdateTrailingFetch tests FETCH FIRST after the locking clause:
// it combines with OFFSET in any order but never with LIMIT (libpg_query).
func TestForUpdateTrailingFetch(t *testing.T) {
	tests := []struct {
		name   string
		sql    string
		offset int
	}{
		{
			name: "FETCH only",
			sql:  "SELECT id FROM t FOR UPDATE FETCH FIRST 5 ROWS ONLY",
		},
		{
			name:   "OFFSET then FETCH",
			sql:    "SELECT id FROM t FOR UPDATE OFFSET 5 FETCH FIRST 1 ROWS ONLY",
			offset: 5,
		},
		{
			name:   "FETCH then OFFSET",
			sql:    "SELECT id FROM t FOR UPDATE FETCH FIRST 1 ROWS ONLY OFFSET 5",
			offset: 5,
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

			if selectStmt.Fetch == nil {
				t.Fatal("expected FETCH clause, got none")
			}

			if tt.offset == 0 {
				if selectStmt.Offset != nil {
					t.Fatalf("unexpected OFFSET %d", *selectStmt.Offset)
				}
				return
			}
			if selectStmt.Offset == nil || *selectStmt.Offset != tt.offset {
				t.Fatalf("OFFSET = %+v, want %d", selectStmt.Offset, tt.offset)
			}
		})
	}
}

// TestForUpdateLimitFetchMutuallyExclusive pins that LIMIT and FETCH after
// the locking clause cannot combine, in either order (libpg_query). LIMIT
// ALL counts: it is a limit clause with no count.
func TestForUpdateLimitFetchMutuallyExclusive(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM t FOR UPDATE LIMIT 10 FETCH FIRST 1 ROWS ONLY",
		"SELECT id FROM t FOR UPDATE FETCH FIRST 1 ROWS ONLY LIMIT 10",
		"SELECT id FROM t FOR UPDATE LIMIT ALL FETCH FIRST 1 ROWS ONLY",
	} {
		t.Run(sql, func(t *testing.T) {
			_, err := parseSQLMayFail(t, sql)
			if err == nil {
				t.Fatalf("parse(%q): expected error for LIMIT combined with FETCH, got none", sql)
			}
		})
	}
}

// TestForUpdateTrailingLimitAcrossLockingError pins that a limit-clause
// token on both sides of the locking clause is invalid in any combination,
// including LIMIT ALL (a limit clause with no count, stored without a
// Limit value).
func TestForUpdateTrailingLimitAcrossLockingError(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM t LIMIT 5 FOR UPDATE LIMIT 10",
		"SELECT id FROM t OFFSET 5 FOR UPDATE LIMIT 10",
		"SELECT id FROM t LIMIT 5 FOR UPDATE OFFSET 3",
		"SELECT id FROM t OFFSET 5 FOR UPDATE FETCH FIRST 1 ROWS ONLY",
		"SELECT id FROM t LIMIT ALL FOR UPDATE OFFSET 5",
		"SELECT id FROM t LIMIT ALL FOR UPDATE FETCH FIRST 1 ROWS ONLY",
	} {
		t.Run(sql, func(t *testing.T) {
			_, err := parseSQLMayFail(t, sql)
			if err == nil {
				t.Fatalf("parse(%q): expected error for limit clauses on both sides of FOR, got none", sql)
			}
		})
	}
}

// TestLockingTrailingLimitDialectGate pins the dialect gate: MySQL's
// grammar puts LIMIT before the locking clause, so FOR UPDATE ... LIMIT
// must fail there, while PostgreSQL accepts it.
func TestLockingTrailingLimitDialectGate(t *testing.T) {
	sql := "SELECT id FROM t FOR UPDATE LIMIT 5"

	mysqlTree, err := ParseWithDialect(sql, keywords.DialectMySQL)
	if mysqlTree != nil {
		defer ast.ReleaseAST(mysqlTree)
	}
	if err == nil {
		t.Fatal("parse with MySQL dialect: expected error for FOR UPDATE ... LIMIT, got none")
	}

	pgTree, err := ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("parse with PostgreSQL dialect: unexpected error: %v", err)
	}
	defer ast.ReleaseAST(pgTree)
}
