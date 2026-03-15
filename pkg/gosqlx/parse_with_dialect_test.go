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

// Package gosqlx - tests for the ParseWithDialect top-level wrapper (UX fix).
package gosqlx_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// ---------------------------------------------------------------------------
// UX Fix - ParseWithDialect top-level wrapper
// ---------------------------------------------------------------------------

func TestParseWithDialect_MySQLBasic(t *testing.T) {
	sql := "SELECT * FROM users WHERE active = 1"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect(MySQL) unexpected error: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
}

func TestParseWithDialect_PostgreSQLBasic(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE active = true"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("ParseWithDialect(PostgreSQL) unexpected error: %v", err)
	}
	if tree == nil || len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement")
	}
}

func TestParseWithDialect_MySQLOnDuplicateKeyUpdate(t *testing.T) {
	// This is Bug 2 tested through the top-level wrapper.
	sql := "INSERT INTO users (id, name) VALUES (1, 'Alice') ON DUPLICATE KEY UPDATE name=VALUES(name)"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect MySQL VALUES() helper failed: %v", err)
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil {
		t.Fatal("expected OnDuplicateKey to be populated")
	}
}

func TestParseWithDialect_UnknownDialectReturnsError(t *testing.T) {
	_, err := gosqlx.ParseWithDialect("SELECT 1", "totally-unknown-dialect")
	if err == nil {
		t.Fatal("expected error for unknown dialect, got nil")
	}
	t.Logf("unknown dialect error: %v", err)
}

func TestParseWithDialect_ReturnsValidAST(t *testing.T) {
	sql := "SELECT id, name, email FROM users ORDER BY name ASC LIMIT 10"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectGeneric)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least 1 statement")
	}
}

func TestParseWithDialect_InvalidSQLReturnsError(t *testing.T) {
	_, err := gosqlx.ParseWithDialect("SELECT FROM WHERE", keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected parse error for invalid SQL, got nil")
	}
}

func TestParseWithDialect_SQLiteDialect(t *testing.T) {
	sql := "SELECT name FROM sqlite_master WHERE type='table'"
	_, err := gosqlx.ParseWithDialect(sql, keywords.DialectSQLite)
	if err != nil {
		t.Fatalf("ParseWithDialect(SQLite) unexpected error: %v", err)
	}
}

func TestParseWithDialect_SnowflakeDialect(t *testing.T) {
	sql := "SELECT * FROM users LIMIT 100"
	_, err := gosqlx.ParseWithDialect(sql, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("ParseWithDialect(Snowflake) unexpected error: %v", err)
	}
}

func TestParseWithDialect_SameResultAsParseForGenericSQL(t *testing.T) {
	// For generic SQL, ParseWithDialect should produce the same result as Parse.
	sql := "SELECT id FROM users WHERE active = true"

	treeA, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	treeB, err := gosqlx.ParseWithDialect(sql, keywords.DialectGeneric)
	if err != nil {
		t.Fatalf("ParseWithDialect(Generic) failed: %v", err)
	}

	if len(treeA.Statements) != len(treeB.Statements) {
		t.Errorf("statement count differs: Parse=%d ParseWithDialect=%d",
			len(treeA.Statements), len(treeB.Statements))
	}
}
