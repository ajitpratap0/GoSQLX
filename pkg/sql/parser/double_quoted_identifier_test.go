// Package parser - double_quoted_identifier_test.go
// Tests for double-quoted identifier support in DML and DDL statements.
// Double-quoted identifiers are part of the ANSI SQL standard and are used by
// PostgreSQL, Oracle, SQLite, and other databases.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQLWithQuotedIdentifiers is a helper to tokenize and parse SQL for testing quoted identifiers
// (double-quoted for ANSI SQL/PostgreSQL, backticks for MySQL, etc.)
func parseSQLWithQuotedIdentifiers(t *testing.T, sql string) (*ast.AST, error) {
	t.Helper()

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, err
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	return tree, err
}

// convertTokensWithQuotedIdentifiers converts tokenizer tokens to parser tokens,
// including proper handling of quoted strings (double-quoted, backticks) as identifiers

func TestDoubleQuotedIdentifiers_SELECT(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted column in SELECT",
			sql:  `SELECT "id" FROM users`,
		},
		{
			name: "double-quoted table in SELECT",
			sql:  `SELECT id FROM "users"`,
		},
		{
			name: "double-quoted column and table in SELECT",
			sql:  `SELECT "id", "name" FROM "users"`,
		},
		{
			name: "double-quoted in WHERE clause",
			sql:  `SELECT id FROM users WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_INSERT(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in INSERT",
			sql:  `INSERT INTO "users" (name) VALUES (1)`,
		},
		{
			name: "double-quoted columns in INSERT",
			sql:  `INSERT INTO users ("id", "name") VALUES (1, 2)`,
		},
		{
			name: "double-quoted table and columns in INSERT",
			sql:  `INSERT INTO "users" ("id", "name") VALUES (1, 2)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_UPDATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in UPDATE",
			sql:  `UPDATE "users" SET name = 1`,
		},
		{
			name: "double-quoted column in UPDATE SET",
			sql:  `UPDATE users SET "name" = 1`,
		},
		{
			name: "double-quoted table and column in UPDATE",
			sql:  `UPDATE "users" SET "name" = 1 WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_DELETE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in DELETE",
			sql:  `DELETE FROM "users"`,
		},
		{
			name: "double-quoted table with WHERE in DELETE",
			sql:  `DELETE FROM "users" WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_DROP(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in DROP TABLE",
			sql:  `DROP TABLE "users"`,
		},
		{
			name: "double-quoted table with IF EXISTS in DROP",
			sql:  `DROP TABLE IF EXISTS "users"`,
		},
		{
			name: "double-quoted view in DROP VIEW",
			sql:  `DROP VIEW "user_summary"`,
		},
		{
			name: "double-quoted index in DROP INDEX",
			sql:  `DROP INDEX "idx_users_name"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_CREATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in CREATE TABLE",
			sql:  `CREATE TABLE "users" (id INT)`,
		},
		{
			name: "double-quoted view in CREATE VIEW",
			sql:  `CREATE VIEW "user_summary" AS SELECT id FROM users`,
		},
		{
			name: "double-quoted index in CREATE INDEX",
			sql:  `CREATE INDEX "idx_users_name" ON users (name)`,
		},
		{
			name: "double-quoted table in CREATE INDEX ON",
			sql:  `CREATE INDEX idx_users_name ON "users" (name)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_TRUNCATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in TRUNCATE",
			sql:  `TRUNCATE TABLE "users"`,
		},
		{
			name: "double-quoted table without TABLE keyword",
			sql:  `TRUNCATE "users"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_Mixed tests mixing quoted and unquoted identifiers
func TestDoubleQuotedIdentifiers_Mixed(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "mixed identifiers in SELECT",
			sql:  `SELECT "id", name FROM "users" WHERE status = 1`,
		},
		{
			name: "mixed identifiers in INSERT",
			sql:  `INSERT INTO "users" (id, "name") VALUES (1, 2)`,
		},
		{
			name: "mixed identifiers in UPDATE",
			sql:  `UPDATE "users" SET name = 1, "status" = 2`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_CTE tests double-quoted identifiers in Common Table Expressions
func TestDoubleQuotedIdentifiers_CTE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted CTE name",
			sql:  `WITH "reserved-word" AS (SELECT 1) SELECT * FROM "reserved-word"`,
		},
		{
			name: "double-quoted CTE column",
			sql:  `WITH cte ("column") AS (SELECT 1) SELECT * FROM cte`,
		},
		{
			name: "double-quoted CTE name and columns",
			sql:  `WITH "my-cte" ("col1", "col2") AS (SELECT 1, 2) SELECT * FROM "my-cte"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_MERGE tests double-quoted identifiers in MERGE statements
func TestDoubleQuotedIdentifiers_MERGE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted target table in MERGE",
			sql:  `MERGE INTO "target" t USING source s ON t.id = s.id WHEN MATCHED THEN UPDATE SET name = s.name`,
		},
		{
			name: "double-quoted source table in MERGE",
			sql:  `MERGE INTO target t USING "source" s ON t.id = s.id WHEN MATCHED THEN UPDATE SET name = s.name`,
		},
		{
			name: "double-quoted column in MERGE UPDATE",
			sql:  `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN UPDATE SET "col" = s.val`,
		},
		{
			name: "double-quoted tables in MERGE",
			sql:  `MERGE INTO "target" t USING "source" s ON t.id = s.id WHEN MATCHED THEN UPDATE SET "col" = s.val`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_MaterializedView tests double-quoted identifiers in materialized view statements
func TestDoubleQuotedIdentifiers_MaterializedView(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted view in CREATE MATERIALIZED VIEW",
			sql:  `CREATE MATERIALIZED VIEW "my-view" AS SELECT id FROM users`,
		},
		{
			name: "double-quoted view in REFRESH MATERIALIZED VIEW",
			sql:  `REFRESH MATERIALIZED VIEW "my-view"`,
		},
		{
			name: "double-quoted view in DROP MATERIALIZED VIEW",
			sql:  `DROP MATERIALIZED VIEW "my-view"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_OnConflict tests double-quoted identifiers in ON CONFLICT clauses
func TestDoubleQuotedIdentifiers_OnConflict(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted column in ON CONFLICT",
			sql:  `INSERT INTO users ("id") VALUES (1) ON CONFLICT ("id") DO NOTHING`,
		},
		{
			name: "double-quoted table and column in INSERT with ON CONFLICT",
			sql:  `INSERT INTO "users" ("id") VALUES (1) ON CONFLICT ("id") DO NOTHING`,
		},
		{
			name: "double-quoted in ON CONFLICT DO UPDATE",
			sql:  `INSERT INTO "users" ("id", "name") VALUES (1, 2) ON CONFLICT ("id") DO UPDATE SET "name" = 3`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_EdgeCases tests edge cases for double-quoted identifiers
func TestDoubleQuotedIdentifiers_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "reserved word as identifier",
			sql:  `SELECT "select", "from" FROM users`,
		},
		{
			name: "identifier with hyphen",
			sql:  `SELECT * FROM "my-table"`,
		},
		{
			name: "identifier with space",
			sql:  `SELECT * FROM "table name"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}
