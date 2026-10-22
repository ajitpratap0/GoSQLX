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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestNameQuote_SQLKeepsNeededQuotes checks that SQL() keeps the delimiters
// a name needs (letter case in a folding dialect, a keyword, a niladic word
// such as user) in every clause the parser records them for, writes them
// with the source's delimiter, and still drops quotes a name does not need.
// The output must also re-parse to the same SQL().
func TestNameQuote_SQLKeepsNeededQuotes(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		// Letter case in PostgreSQL / generic SQL (fold to lower case).
		{"pg qualified and aliases", keywords.DialectPostgreSQL,
			`SELECT "users"."id", "Company"."name" AS "CompanyName" FROM "users" JOIN "companies" AS "Company" ON "Company"."id" = "users"."company_id"`,
			`SELECT users.id, "Company".name AS "CompanyName" FROM users INNER JOIN companies "Company" ON "Company".id = users.company_id`},
		{"generic mixed case column", "", `SELECT "Mixed" FROM t`, `SELECT "Mixed" FROM t`},
		{"pg upper case table", keywords.DialectPostgreSQL, `SELECT * FROM "USERS"`, `SELECT * FROM "USERS"`},
		{"pg schema qualified table", keywords.DialectPostgreSQL, `SELECT * FROM "Sales"."Orders" o`, `SELECT * FROM "Sales"."Orders" o`},
		{"pg mixed parts", keywords.DialectPostgreSQL, `SELECT "s"."Orders"."Id" FROM "s"."Orders"`, `SELECT s."Orders"."Id" FROM s."Orders"`},
		{"pg qualified star", keywords.DialectPostgreSQL, `SELECT "T".* FROM t AS "T"`, `SELECT "T".* FROM t "T"`},
		{"pg cte name and columns", keywords.DialectPostgreSQL,
			`WITH "Cte"("Total", n) AS (SELECT 1, 2) SELECT "Total" FROM "Cte"`,
			`WITH "Cte" ("Total", n) AS (SELECT 1, 2) SELECT "Total" FROM "Cte"`},
		{"pg derived alias", keywords.DialectPostgreSQL,
			`SELECT s."Total" FROM (SELECT amount AS "Total" FROM t) AS s`,
			`SELECT s."Total" FROM (SELECT amount AS "Total" FROM t) s`},
		{"pg function names", keywords.DialectPostgreSQL,
			`SELECT s."select"(1), "MySchema"."MyFunc"(1), "MyFunc"(2), pg_catalog.now()`,
			`SELECT s."select"(1), "MySchema"."MyFunc"(1), "MyFunc"(2), pg_catalog.now()`},
		{"pg table function and column aliases", keywords.DialectPostgreSQL,
			`SELECT "G"."Elem" FROM unnest(arr) AS "G"("Elem")`,
			`SELECT "G"."Elem" FROM unnest(arr) "G"("Elem")`},
		{"pg join using", keywords.DialectPostgreSQL, `SELECT * FROM a JOIN b USING ("Id", id2)`, `SELECT * FROM a INNER JOIN b USING ("Id", id2)`},
		{"pg insert", keywords.DialectPostgreSQL, `INSERT INTO "MyTable" ("ColA", colb) VALUES (1, 2)`, `INSERT INTO "MyTable" ("ColA", colb) VALUES (1, 2)`},
		{"pg on conflict target", keywords.DialectPostgreSQL,
			`INSERT INTO t (a) VALUES (1) ON CONFLICT ("Key") DO NOTHING`,
			`INSERT INTO t (a) VALUES (1) ON CONFLICT ("Key") DO NOTHING`},
		{"pg update", keywords.DialectPostgreSQL,
			`UPDATE "MyTable" AS "T" SET "ColA" = 1, "T"."ColB" = 2 WHERE "T"."ColC" = 3`,
			`UPDATE "MyTable" "T" SET "ColA" = 1, "T"."ColB" = 2 WHERE "T"."ColC" = 3`},
		{"pg delete", keywords.DialectPostgreSQL, `DELETE FROM "MyTable" AS "T" WHERE "T".id = 1`, `DELETE FROM "MyTable" "T" WHERE "T".id = 1`},
		{"pg merge", keywords.DialectPostgreSQL,
			`MERGE INTO "T" AS "Tgt" USING "S" "Src" ON "Tgt".id = "Src".id WHEN MATCHED THEN UPDATE SET "Val" = "Src"."Val" WHEN NOT MATCHED THEN INSERT ("Id", b) VALUES (1, 2)`,
			`MERGE INTO "T" "Tgt" USING "S" "Src" ON "Tgt".id = "Src".id WHEN MATCHED THEN UPDATE SET "Val" = "Src"."Val" WHEN NOT MATCHED THEN INSERT ("Id", b) VALUES (1, 2)`},
		{"pg create table", keywords.DialectPostgreSQL, `CREATE TABLE "MyTable" ("ColA" int, "order" text, b int)`, `CREATE TABLE "MyTable" ("ColA" int, "order" text, b int)`},
		{"pg create view", keywords.DialectPostgreSQL, `CREATE VIEW "V" ("A", b) AS SELECT 1, 2`, `CREATE VIEW "V" ("A", b) AS SELECT 1, 2`},
		// Keywords and niladic words keep their quotes in every dialect.
		{"pg keyword names", keywords.DialectPostgreSQL,
			`SELECT 1 AS "select", 2 AS "order", "user", "group" FROM "table"`,
			`SELECT 1 AS "select", 2 AS "order", "user", "group" FROM "table"`},
		{"pg lower case quotes dropped", keywords.DialectPostgreSQL, `SELECT "a"."b" AS "c" FROM "t" AS "a"`, `SELECT a.b AS c FROM t a`},
		// Oracle and Snowflake fold to upper case.
		{"oracle mixed and lower case", keywords.DialectOracle,
			`SELECT "ID", "NAME", "CreatedAt", "lower" FROM "AppUsers" WHERE "ID" = :1`,
			`SELECT ID, NAME, "CreatedAt", "lower" FROM "AppUsers" WHERE ID = :1`},
		{"snowflake lower case alias", keywords.DialectSnowflake, `SELECT a AS "total", b AS "TOTAL" FROM t`, `SELECT a AS "total", b AS TOTAL FROM t`},
		{"oracle quoted prior", keywords.DialectOracle,
			`SELECT id FROM t CONNECT BY PRIOR id = parent_id AND "PRIOR" = 1`,
			`SELECT id FROM t CONNECT BY PRIOR id = parent_id AND "PRIOR" = 1`},
		// Oracle bare names with '#' stay bare.
		{"oracle bare hash", keywords.DialectOracle, `SELECT s.serial#, emp# AS no# FROM v$session s`, `SELECT s.serial#, emp# AS no# FROM v$session s`},
		{"oracle quoted hash", keywords.DialectOracle, `SELECT "a#b" FROM t`, `SELECT "a#b" FROM t`},
		// Dialects that do not fold drop quotes needed only for case, and
		// keep the source delimiter for the quotes they need.
		{"mysql backtick alias", keywords.DialectMySQL,
			"SELECT EXISTS(SELECT * FROM `users` WHERE `email` = 'a') AS `exists`",
			"SELECT EXISTS (SELECT * FROM users WHERE email = 'a') AS `exists`"},
		{"mysql backtick keywords", keywords.DialectMySQL,
			"SELECT 1 AS `select`, `Company`.`x` FROM `order` `group`, `Company`",
			"SELECT 1 AS `select`, Company.x FROM `order` `group`, Company"},
		{"mysql insert reserved column", keywords.DialectMySQL, "INSERT INTO t (`select`) VALUES (1)", "INSERT INTO t (`select`) VALUES (1)"},
		{"sqlserver brackets", keywords.DialectSQLServer,
			"SELECT [a b], [Group], [Name] FROM [dbo].[My Table] AS [t]",
			"SELECT [a b], [Group], Name FROM dbo.[My Table] t"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.in, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			again, err := ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			defer ast.ReleaseAST(again)
			if again.SQL() != got {
				t.Fatalf("re-parse changed SQL()\nfirst:  %s\nsecond: %s", got, again.SQL())
			}
		})
	}
}

// TestNameQuote_RecordedOnAST checks the NameQuote values the parser stores.
func TestNameQuote_RecordedOnAST(t *testing.T) {
	tree, err := ParseWithDialect(`SELECT "S"."T"."Col" AS "A", x."y" FROM "S"."Tbl" AS "B"`, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	ae, ok := sel.Columns[0].(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected *ast.AliasedExpression, got %T", sel.Columns[0])
	}
	if !ae.AliasQuote.Part(0) || ae.AliasQuote.Style() != '"' {
		t.Errorf("AliasQuote = %08b, want part 0 with '\"'", ae.AliasQuote)
	}
	id, ok := ae.Expr.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier, got %T", ae.Expr)
	}
	for i := 0; i < 3; i++ {
		if !id.Quotes.Part(i) {
			t.Errorf("identifier part %d not recorded (Quotes = %08b)", i, id.Quotes)
		}
	}
	plain, ok := sel.Columns[1].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[1])
	}
	if plain.Quotes != 0 {
		t.Errorf("x.\"y\" Quotes = %08b, want 0 (lower-case quotes are not needed)", plain.Quotes)
	}
	ref := sel.From[0]
	if ref.NameQuote.Part(0) != true || ref.NameQuote.Part(1) != true {
		t.Errorf("table NameQuote = %08b, want parts 0 and 1", ref.NameQuote)
	}
	if !ref.AliasQuote.Part(0) {
		t.Errorf("table AliasQuote = %08b, want part 0", ref.AliasQuote)
	}
}

// TestNameQuote_PoolReuse checks that quote marks do not leak through the
// object pools into a later parse of unquoted names.
func TestNameQuote_PoolReuse(t *testing.T) {
	quoted := `SELECT "A"."B" AS "C", "F"(1) FROM "T" AS "U" JOIN "V" "W" ON "U".x = "W".x`
	plain := `SELECT A.B AS C, F(1) FROM T AS U JOIN V W ON U.x = W.x`
	want := `SELECT A.B AS C, F(1) FROM T U INNER JOIN V W ON U.x = W.x`
	for i := 0; i < 50; i++ {
		tree, err := ParseWithDialect(quoted, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("parse quoted: %v", err)
		}
		ast.ReleaseAST(tree)
		tree, err = ParseWithDialect(plain, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("parse plain: %v", err)
		}
		got := tree.SQL()
		ast.ReleaseAST(tree)
		if got != want {
			t.Fatalf("iteration %d: SQL() = %s, want %s", i, got, want)
		}
	}
}
