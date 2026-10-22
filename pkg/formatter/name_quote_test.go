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

package formatter

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestNameQuote_FormatKeepsCaseQuotes checks that FormatStatement keeps the
// quotes a name needs for its letter case where the dialect folds unquoted
// names, in the clauses the formatter renders itself (FROM and JOIN tables
// and aliases, CTE names and columns, DML targets, CREATE TABLE / VIEW), and
// drops them where the dialect does not fold.
func TestNameQuote_FormatKeepsCaseQuotes(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		{"pg select", keywords.DialectPostgreSQL,
			`SELECT "C"."name" AS "CName" FROM "companies" AS "C" JOIN "Users" "U" ON "U".cid = "C".id`,
			`SELECT "C".name AS "CName" FROM companies "C" INNER JOIN "Users" "U" ON "U".cid = "C".id`},
		{"pg cte", keywords.DialectPostgreSQL,
			`WITH "Cte"("Total") AS (SELECT 1) SELECT "Total" FROM "Cte"`,
			`WITH "Cte" ("Total") AS (SELECT 1) SELECT "Total" FROM "Cte"`},
		{"pg update", keywords.DialectPostgreSQL,
			`UPDATE "MyTable" AS "T" SET "ColA" = 1 WHERE "T"."ColB" = 2`,
			`UPDATE "MyTable" "T" SET "ColA" = 1 WHERE "T"."ColB" = 2`},
		{"pg delete", keywords.DialectPostgreSQL, `DELETE FROM "MyTable" WHERE "Id" = 1`, `DELETE FROM "MyTable" WHERE "Id" = 1`},
		{"pg insert", keywords.DialectPostgreSQL, `INSERT INTO "MyTable" ("ColA") VALUES (1)`, `INSERT INTO "MyTable" ("ColA") VALUES (1)`},
		{"pg merge", keywords.DialectPostgreSQL,
			`MERGE INTO t AS "Tgt" USING s AS "Src" ON "Tgt".id = "Src".id WHEN MATCHED THEN UPDATE SET "Val" = 1 WHEN NOT MATCHED THEN INSERT ("Id") VALUES (1)`,
			`MERGE INTO t "Tgt" USING s "Src" ON "Tgt".id = "Src".id WHEN MATCHED THEN UPDATE SET "Val" = 1 WHEN NOT MATCHED THEN INSERT ("Id") VALUES (1)`},
		{"pg create table", keywords.DialectPostgreSQL, `CREATE TABLE "MyTable" ("ColA" INT)`, `CREATE TABLE "MyTable" ("ColA" INT)`},
		{"pg create view", keywords.DialectPostgreSQL, `CREATE VIEW "V" ("A") AS SELECT 1`, `CREATE VIEW "V" ("A") AS SELECT 1`},
		{"oracle lower case", keywords.DialectOracle, `SELECT "ID", "id" FROM "T" "t"`, `SELECT ID, "id" FROM T "t"`},
		{"mysql case not needed", keywords.DialectMySQL, "SELECT `Id` FROM `Users` AS `U`", "SELECT Id FROM Users U"},
		{"mysql reserved alias", keywords.DialectMySQL, "SELECT 1 AS `exists` FROM `order` AS `group`", "SELECT 1 AS `exists` FROM `order` `group`"},
		{"sqlserver reserved", keywords.DialectSQLServer, "SELECT [Group] FROM [order] [Key]", "SELECT [Group] FROM [order] [Key]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := parser.ParseWithDialect(tc.in, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			style := ast.CompactStyle()
			style.Dialect = string(tc.dialect)
			got := FormatStatement(tree.Statements[0], style)
			if got != tc.want {
				t.Fatalf("FormatStatement mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestNameQuote_FormatDialectDelimiter checks that a name needing delimiters
// because of its content, with no delimiter recorded (a hand-built AST), is
// written with backticks when the target dialect is MySQL or MariaDB, which
// read "..." as a string, and with ANSI double quotes otherwise.
func TestNameQuote_FormatDialectDelimiter(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "a"}},
		From:    []ast.TableReference{{Name: "my db.order", Alias: "select"}},
	}
	tests := []struct {
		dialect string
		want    string
	}{
		{"mysql", "SELECT a FROM `my db`.`order` `select`"},
		{"MariaDB", "SELECT a FROM `my db`.`order` `select`"},
		{"postgresql", `SELECT a FROM "my db"."order" "select"`},
		{"", `SELECT a FROM "my db"."order" "select"`},
	}
	for _, tc := range tests {
		style := ast.CompactStyle()
		style.Dialect = tc.dialect
		if got := FormatStatement(stmt, style); got != tc.want {
			t.Errorf("dialect %q: got %s, want %s", tc.dialect, got, tc.want)
		}
	}
}

// TestNameQuote_FormatNoAllocForPlainNames checks that the dialect-aware name
// quoting does not allocate for names that need no delimiters.
func TestNameQuote_FormatNoAllocForPlainNames(t *testing.T) {
	q := ast.NameQuoteOf('`')
	if n := testing.AllocsPerRun(100, func() {
		_ = ast.QuoteQualifiedNameWith("db.users", q)
		_ = ast.QuoteTableAliasWith("u", q)
		_ = ast.QuoteNameWith("total", q)
	}); n != 0 {
		t.Errorf("plain names allocate %v times, want 0", n)
	}
}
