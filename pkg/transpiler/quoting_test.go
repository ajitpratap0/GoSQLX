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

package transpiler_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// TestTranspile_IdentifierDelimiters checks that quoted names are written
// with the target dialect's delimiters, not the source's: MySQL backticks
// and SQL Server brackets are invalid in PostgreSQL, and ANSI double quotes
// are strings in MySQL.
func TestTranspile_IdentifierDelimiters(t *testing.T) {
	tests := []struct {
		name     string
		from, to keywords.SQLDialect
		in       string
		want     string
	}{
		{"mysql to pg column", keywords.DialectMySQL, keywords.DialectPostgreSQL,
			"SELECT `my col` FROM t", `SELECT "my col" FROM t`},
		{"sqlserver to pg", keywords.DialectSQLServer, keywords.DialectPostgreSQL,
			"SELECT [Group], [a b] FROM t", `SELECT "Group", "a b" FROM t`},
		{"mysql to sqlserver reserved", keywords.DialectMySQL, keywords.DialectSQLServer,
			"SELECT `order` FROM t", "SELECT [order] FROM t"},
		{"mysql to pg aliases and tables", keywords.DialectMySQL, keywords.DialectPostgreSQL,
			"SELECT `a b` AS `my alias` FROM `my table` AS `x y` JOIN `u v` ON `x y`.id = `u v`.id",
			`SELECT "a b" AS "my alias" FROM "my table" "x y" INNER JOIN "u v" ON "x y".id = "u v".id`},
		{"pg to mysql case and reserved", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`SELECT "Total", "a b" AS "select" FROM "MyTable" AS "T" WHERE "T"."order" = 1`,
			"SELECT `Total`, `a b` AS `select` FROM `MyTable` `T` WHERE `T`.`order` = 1"},
		{"pg to mysql cte", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`WITH "Cte"("A b") AS (SELECT 1) SELECT "A b" FROM "Cte"`,
			"WITH `Cte` (`A b`) AS (SELECT 1) SELECT `A b` FROM `Cte`"},
		{"pg to mysql insert", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`INSERT INTO "MyTable" ("ColA", "order") VALUES (1, 2)`,
			"INSERT INTO `MyTable` (`ColA`, `order`) VALUES (1, 2)"},
		{"pg to mysql update", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`UPDATE "MyTable" AS "T" SET "ColA" = 1 WHERE "T"."ColB" = 2`,
			"UPDATE `MyTable` `T` SET `ColA` = 1 WHERE `T`.`ColB` = 2"},
		{"pg to mysql delete", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`DELETE FROM "MyTable" WHERE "order" = 1`, "DELETE FROM `MyTable` WHERE `order` = 1"},
		{"pg to mysql functions", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`SELECT s."select"(1), "MyFunc"(2)`, "SELECT s.`select`(1), `MyFunc`(2)"},
		{"pg to mysql create table", keywords.DialectPostgreSQL, keywords.DialectMySQL,
			`CREATE TABLE "MyTable" ("ColA" INT)`, "CREATE TABLE `MyTable` (`ColA` INT)"},
		{"sqlserver to mysql qualified", keywords.DialectSQLServer, keywords.DialectMySQL,
			"SELECT [a b] FROM [dbo].[My Table]", "SELECT `a b` FROM dbo.`My Table`"},
		{"oracle hash to pg", keywords.DialectOracle, keywords.DialectPostgreSQL,
			"SELECT s.serial#, emp# FROM v$session s", `SELECT s."serial#", "emp#" FROM v$session s`},
		{"oracle hash kept in oracle", keywords.DialectOracle, keywords.DialectOracle,
			"SELECT s.serial#, emp# FROM v$session s", "SELECT s.serial#, emp# FROM v$session s"},
		{"same dialect keeps source delimiters", keywords.DialectMySQL, keywords.DialectMySQL,
			"SELECT `a b` FROM t", "SELECT `a b` FROM t"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transpiler.Transpile(tc.in, tc.from, tc.to)
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Transpile mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			tree, err := parser.ParseWithDialect(got, tc.to)
			if err != nil {
				t.Fatalf("output does not parse as %s: %v\n%s", tc.to, err, got)
			}
			ast.ReleaseAST(tree)
		})
	}
}
