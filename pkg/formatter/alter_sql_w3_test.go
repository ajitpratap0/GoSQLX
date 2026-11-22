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

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestAlterStatementSQL checks that AST.SQL() and Statement.SQL() write every
// ALTER statement (they used to write nothing for an *ast.AlterStatement) and
// that the output matches the formatter's compact rendering and re-parses to
// the same text.
func TestAlterStatementSQL(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		{"add column", keywords.DialectPostgreSQL,
			"ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0", "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0"},
		{"several actions", keywords.DialectPostgreSQL,
			"ALTER TABLE IF EXISTS ONLY s.t DROP COLUMN a CASCADE, ALTER COLUMN b SET NOT NULL, RENAME TO u",
			"ALTER TABLE IF EXISTS ONLY s.t DROP COLUMN a CASCADE, ALTER COLUMN b SET NOT NULL, RENAME TO u"},
		{"set data type using", keywords.DialectPostgreSQL,
			"ALTER TABLE t ALTER COLUMN c TYPE BIGINT USING CAST(c AS BIGINT)", "ALTER TABLE t ALTER COLUMN c TYPE BIGINT USING CAST(c AS BIGINT)"},
		{"quoted names", keywords.DialectPostgreSQL,
			`ALTER TABLE "Post" RENAME COLUMN "Old" TO "New"`, `ALTER TABLE "Post" RENAME COLUMN "Old" TO "New"`},
		{"mysql add index", keywords.DialectMySQL,
			"ALTER TABLE t ADD UNIQUE KEY idx (a, b)", "ALTER TABLE t ADD UNIQUE KEY idx (a, b)"},
		{"clickhouse on cluster", keywords.DialectClickHouse,
			"ALTER TABLE t ON CLUSTER c DELETE WHERE x = 1", "ALTER TABLE t ON CLUSTER c DELETE WHERE x = 1"},
		{"alter policy", keywords.DialectGeneric,
			"ALTER POLICY p ON s.t TO a, b USING (x = 1) WITH CHECK (y = 2)", "ALTER POLICY p ON s.t TO a, b USING (x = 1) WITH CHECK (y = 2)"},
		{"alter connector url", keywords.DialectGeneric,
			"ALTER CONNECTOR c SET URL 'it''s'", "ALTER CONNECTOR c SET URL 'it''s'"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.in, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 1 {
				t.Fatalf("got %d statements, want 1", len(tree.Statements))
			}
			alter, ok := tree.Statements[0].(*ast.AlterStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.AlterStatement", tree.Statements[0])
			}
			if got := alter.SQL(); got != tc.want {
				t.Errorf("Statement.SQL() = %q, want %q", got, tc.want)
			}
			if got := tree.SQL(); got != tc.want {
				t.Errorf("AST.SQL() = %q, want %q", got, tc.want)
			}
			style := ast.CompactStyle()
			style.Dialect = string(tc.dialect)
			if got := formatter.FormatStatement(alter, style); got != tc.want {
				t.Errorf("FormatStatement = %q, want %q", got, tc.want)
			}
			// The SQL() text parses back to the same statement.
			again, err := gosqlx.ParseWithDialect(tc.want, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse %q: %v", tc.want, err)
			}
			defer ast.ReleaseAST(again)
			if got := again.SQL(); got != tc.want {
				t.Errorf("re-parsed SQL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAlterStatementSQL_Bare checks that an ALTER statement without an
// operation, and a nil one, never write more than the ALTER keyword.
func TestAlterStatementSQL_Bare(t *testing.T) {
	var nilStmt *ast.AlterStatement
	if got := nilStmt.SQL(); got != "" {
		t.Errorf("nil SQL() = %q, want empty", got)
	}
	role := &ast.AlterStatement{Type: ast.AlterTypeRole, Name: "r"}
	if got := role.SQL(); got != "ALTER" {
		t.Errorf("operation-less SQL() = %q, want ALTER", got)
	}
}

// TestAlterNameQuotes_Recorded checks that the delimiters of names in ALTER
// ROLE / POLICY / CONNECTOR, index names, partition names, INHERITS and index
// names inside constraints are recorded and written back when they carry
// meaning (case, keywords).
func TestAlterNameQuotes_Recorded(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		{"policy", keywords.DialectGeneric,
			`ALTER POLICY "Pol" ON "Sch"."Tbl" TO "Admin", other`, `ALTER POLICY "Pol" ON "Sch"."Tbl" TO "Admin", other`},
		{"policy rename", keywords.DialectGeneric,
			`ALTER POLICY "Pol" ON t RENAME TO "Pol2"`, `ALTER POLICY "Pol" ON t RENAME TO "Pol2"`},
		{"connector", keywords.DialectGeneric,
			`ALTER CONNECTOR "Conn" SET OWNER USER "Bob"`, `ALTER CONNECTOR "Conn" SET OWNER USER "Bob"`},
		{"add index name", keywords.DialectMySQL,
			"ALTER TABLE t ADD INDEX `Select` (a)", "ALTER TABLE t ADD INDEX `Select` (a)"},
		{"drop index name", keywords.DialectMySQL,
			"ALTER TABLE t DROP INDEX `Select`", "ALTER TABLE t DROP INDEX `Select`"},
		{"constraint index name", keywords.DialectMySQL,
			"CREATE TABLE t (a INT, KEY `Select` (a), UNIQUE KEY `Order` (a))",
			"CREATE TABLE t (a INT, KEY `Select` (a), UNIQUE KEY `Order` (a))"},
		{"fulltext index name", keywords.DialectMySQL,
			"CREATE TABLE t (a TEXT, FULLTEXT KEY `Select` (a))", "CREATE TABLE t (a TEXT, FULLTEXT KEY `Select` (a))"},
		{"clickhouse index name", keywords.DialectClickHouse,
			"CREATE TABLE t (a Int32, INDEX `Select` a TYPE minmax GRANULARITY 1) ENGINE = MergeTree ORDER BY a",
			"CREATE TABLE t (a Int32, INDEX `Select` a TYPE minmax GRANULARITY 1) ENGINE=MergeTree ORDER BY a"},
		{"inherits", keywords.DialectPostgreSQL,
			`CREATE TABLE t (a INT) INHERITS ("Parent", "Sch"."Other")`, `CREATE TABLE t (a INT) INHERITS ("Parent", "Sch"."Other")`},
		{"partition name", keywords.DialectMySQL,
			"CREATE TABLE t (a INT) PARTITION BY RANGE (a) (PARTITION `Select` VALUES LESS THAN (10))",
			"CREATE TABLE t (a INT) PARTITION BY RANGE (a) (PARTITION `Select` VALUES LESS THAN (10))"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.in, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			style := ast.CompactStyle()
			style.Dialect = string(tc.dialect)
			got := formatter.FormatStatement(tree.Statements[0], style)
			if got != tc.want {
				t.Errorf("FormatStatement\n got: %s\nwant: %s", got, tc.want)
			}
			if sql := tree.SQL(); sql != tc.want {
				t.Errorf("SQL()\n got: %s\nwant: %s", sql, tc.want)
			}
		})
	}
}

// TestAlterRoleNameQuotes checks that a hand-built ALTER ROLE statement
// writes the delimiters recorded on its names, and only those.
func TestAlterRoleNameQuotes(t *testing.T) {
	q := ast.QuotedName('"')
	tests := []struct {
		name string
		stmt *ast.AlterStatement
		want string
	}{
		{"rename keeps case quotes", &ast.AlterStatement{
			Type: ast.AlterTypeRole, Name: "MyRole", NameQuote: q,
			Operation: &ast.AlterRoleOperation{Type: ast.RenameRole, NewName: "NewRole", NewNameQuote: q},
		}, `ALTER ROLE "MyRole" RENAME TO "NewRole"`},
		{"plain names stay bare", &ast.AlterStatement{
			Type: ast.AlterTypeRole, Name: "myrole",
			Operation: &ast.AlterRoleOperation{Type: ast.RenameRole, NewName: "newrole"},
		}, `ALTER ROLE myrole RENAME TO newrole`},
		{"add member", &ast.AlterStatement{
			Type: ast.AlterTypeRole, Name: "r",
			Operation: &ast.AlterRoleOperation{Type: ast.AddMember, MemberName: "User", MemberNameQuote: q},
		}, `ALTER ROLE r ADD MEMBER "User"`},
	}
	for _, tc := range tests {
		if got := tc.stmt.SQL(); got != tc.want {
			t.Errorf("%s: SQL() = %q, want %q", tc.name, got, tc.want)
		}
		if got := formatter.FormatStatement(tc.stmt, ast.CompactStyle()); got != tc.want {
			t.Errorf("%s: FormatStatement = %q, want %q", tc.name, got, tc.want)
		}
	}
}
