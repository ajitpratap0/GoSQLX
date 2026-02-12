// Package parser - schema_qualified_test.go
// Tests for schema-qualified table name support (schema.table, db.schema.table).
// Fixes GitHub issue #202: E2002 Error when using schema.table_name.
//
// Schema-qualified table names are part of the SQL standard and used by:
//   - PostgreSQL (search_path-based schema qualification)
//   - MySQL (database.table)
//   - SQL Server (schema.table)
//   - Oracle (schema.table)
//   - SQLite (schema.table via ATTACH DATABASE)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestSchemaQualified_SELECT(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		tableName string
	}{
		{
			name:      "schema.table in FROM",
			sql:       "SELECT * FROM public.users",
			tableName: "public.users",
		},
		{
			name:      "db.schema.table in FROM",
			sql:       "SELECT * FROM mydb.public.users",
			tableName: "mydb.public.users",
		},
		{
			name:      "schema.table with alias",
			sql:       "SELECT u.id FROM public.users u",
			tableName: "public.users",
		},
		{
			name:      "schema.table with AS alias",
			sql:       "SELECT u.id FROM public.users AS u",
			tableName: "public.users",
		},
		{
			name:      "schema.table with WHERE",
			sql:       "SELECT * FROM public.users WHERE id = 1",
			tableName: "public.users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
			}
			if len(stmt.From) == 0 {
				t.Fatal("expected at least one FROM table")
			}
			if stmt.From[0].Name != tt.tableName {
				t.Errorf("expected table name %q, got %q", tt.tableName, stmt.From[0].Name)
			}
		})
	}
}

func TestSchemaQualified_JOIN(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		fromTable string
		joinTable string
	}{
		{
			name:      "schema.table in FROM and JOIN",
			sql:       "SELECT * FROM public.users u JOIN public.orders o ON u.id = o.user_id",
			fromTable: "public.users",
			joinTable: "public.orders",
		},
		{
			name:      "schema.table only in JOIN",
			sql:       "SELECT * FROM users u JOIN public.orders o ON u.id = o.user_id",
			fromTable: "users",
			joinTable: "public.orders",
		},
		{
			name:      "schema.table LEFT JOIN",
			sql:       "SELECT * FROM public.users u LEFT JOIN public.orders o ON u.id = o.user_id",
			fromTable: "public.users",
			joinTable: "public.orders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
			}
			if len(stmt.From) == 0 {
				t.Fatal("expected at least one FROM table")
			}
			if stmt.From[0].Name != tt.fromTable {
				t.Errorf("expected FROM table %q, got %q", tt.fromTable, stmt.From[0].Name)
			}
			if len(stmt.Joins) == 0 {
				t.Fatal("expected at least one JOIN")
			}
			if stmt.Joins[0].Right.Name != tt.joinTable {
				t.Errorf("expected JOIN table %q, got %q", tt.joinTable, stmt.Joins[0].Right.Name)
			}
		})
	}
}

func TestSchemaQualified_INSERT(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		tableName string
	}{
		{
			name:      "schema.table in INSERT",
			sql:       "INSERT INTO public.users (name) VALUES ('test')",
			tableName: "public.users",
		},
		{
			name:      "db.schema.table in INSERT",
			sql:       "INSERT INTO mydb.public.users (id) VALUES (1)",
			tableName: "mydb.public.users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			stmt, ok := tree.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("expected InsertStatement, got %T", tree.Statements[0])
			}
			if stmt.TableName != tt.tableName {
				t.Errorf("expected table name %q, got %q", tt.tableName, stmt.TableName)
			}
		})
	}
}

func TestSchemaQualified_UPDATE(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		tableName string
	}{
		{
			name:      "schema.table in UPDATE",
			sql:       "UPDATE public.users SET name = 'test'",
			tableName: "public.users",
		},
		{
			name:      "schema.table in UPDATE with WHERE",
			sql:       "UPDATE myschema.users SET name = 'test' WHERE id = 1",
			tableName: "myschema.users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			stmt, ok := tree.Statements[0].(*ast.UpdateStatement)
			if !ok {
				t.Fatalf("expected UpdateStatement, got %T", tree.Statements[0])
			}
			if stmt.TableName != tt.tableName {
				t.Errorf("expected table name %q, got %q", tt.tableName, stmt.TableName)
			}
		})
	}
}

func TestSchemaQualified_DELETE(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		tableName string
	}{
		{
			name:      "schema.table in DELETE",
			sql:       "DELETE FROM public.users WHERE id = 1",
			tableName: "public.users",
		},
		{
			name:      "db.schema.table in DELETE",
			sql:       "DELETE FROM mydb.public.users WHERE id = 1",
			tableName: "mydb.public.users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			stmt, ok := tree.Statements[0].(*ast.DeleteStatement)
			if !ok {
				t.Fatalf("expected DeleteStatement, got %T", tree.Statements[0])
			}
			if stmt.TableName != tt.tableName {
				t.Errorf("expected table name %q, got %q", tt.tableName, stmt.TableName)
			}
		})
	}
}

func TestSchemaQualified_DDL(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "CREATE TABLE with schema",
			sql:  "CREATE TABLE public.users (id INT)",
		},
		{
			name: "CREATE VIEW with schema",
			sql:  "CREATE VIEW public.user_summary AS SELECT id FROM users",
		},
		{
			name: "CREATE INDEX with schema",
			sql:  "CREATE INDEX public.idx_users_name ON public.users (name)",
		},
		{
			name: "DROP TABLE with schema",
			sql:  "DROP TABLE public.users",
		},
		{
			name: "DROP TABLE IF EXISTS with schema",
			sql:  "DROP TABLE IF EXISTS public.users",
		},
		{
			name: "DROP multiple schema-qualified tables",
			sql:  "DROP TABLE public.users, public.orders",
		},
		{
			name: "CREATE MATERIALIZED VIEW with schema",
			sql:  "CREATE MATERIALIZED VIEW public.user_stats AS SELECT COUNT(*) FROM users",
		},
		{
			name: "REFRESH MATERIALIZED VIEW with schema",
			sql:  "REFRESH MATERIALIZED VIEW public.user_stats",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}

			if len(tree.Statements) == 0 {
				t.Fatal("expected at least one statement")
			}
		})
	}
}

func TestSchemaQualified_DDL_Names(t *testing.T) {
	// Test that DDL statements correctly capture the schema-qualified name
	t.Run("CREATE TABLE name", func(t *testing.T) {
		tokens := tokenizeSQL(t, "CREATE TABLE public.users (id INT)")
		p := NewParser()
		defer p.Release()

		tree, err := p.Parse(tokens)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if stmt.Name != "public.users" {
			t.Errorf("expected table name %q, got %q", "public.users", stmt.Name)
		}
	})

	t.Run("DROP TABLE names", func(t *testing.T) {
		tokens := tokenizeSQL(t, "DROP TABLE public.users, app.orders")
		p := NewParser()
		defer p.Release()

		tree, err := p.Parse(tokens)
		if err != nil {
			t.Fatalf("Failed to parse: %v", err)
		}
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.DropStatement)
		if !ok {
			t.Fatalf("expected DropStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Names) != 2 {
			t.Fatalf("expected 2 names, got %d", len(stmt.Names))
		}
		if stmt.Names[0] != "public.users" {
			t.Errorf("expected first name %q, got %q", "public.users", stmt.Names[0])
		}
		if stmt.Names[1] != "app.orders" {
			t.Errorf("expected second name %q, got %q", "app.orders", stmt.Names[1])
		}
	})
}

func TestSchemaQualified_MixedSimpleAndQualified(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "simple table then schema-qualified JOIN",
			sql:  "SELECT * FROM users u JOIN public.orders o ON u.id = o.user_id",
		},
		{
			name: "schema-qualified table then simple JOIN",
			sql:  "SELECT * FROM public.users u JOIN orders o ON u.id = o.user_id",
		},
		{
			name: "INSERT with qualified table and simple columns",
			sql:  "INSERT INTO public.users (id, name) VALUES (1, 'test')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeSQL(t, tt.sql)
			p := NewParser()
			defer p.Release()

			tree, err := p.Parse(tokens)
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tt.sql, err)
			}
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
		})
	}
}
