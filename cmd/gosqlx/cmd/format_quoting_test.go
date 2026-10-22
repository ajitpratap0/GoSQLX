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

package cmd

import "testing"

// TestFormatSQL_KeepsNeededQuotes checks that the CLI formats input whose
// quoted names need their quotes (letter case, keywords, MySQL backtick
// aliases) and keeps those quotes, where it used to refuse because the
// renderer wrote them bare or in the wrong delimiters.
func TestFormatSQL_KeepsNeededQuotes(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
		want    string
	}{
		{name: "select mixed case", in: `SELECT "Mixed" FROM t`, want: `SELECT "Mixed" FROM t`},
		{name: "select mixed case table", in: `SELECT a FROM "Mixed"`, want: `SELECT a FROM "Mixed"`},
		{name: "qualified mixed case alias", in: `SELECT "C"."name" AS "CName" FROM "companies" AS "C"`,
			want: `SELECT "C".name AS "CName" FROM companies "C"`},
		{name: "keyword table name", dialect: "postgresql", in: `SELECT 1 FROM "table"`, want: `SELECT 1 FROM "table"`},
		{name: "user column", dialect: "postgresql", in: `SELECT "user" FROM t`, want: `SELECT "user" FROM t`},
		{name: "oracle lowercase quoted", dialect: "oracle", in: `SELECT "abc" FROM t`, want: `SELECT "abc" FROM t`},
		{name: "oracle mixed case", dialect: "oracle", in: `SELECT "ID", "CreatedAt" FROM "AppUsers"`,
			want: `SELECT ID, "CreatedAt" FROM "AppUsers"`},
		{name: "oracle bare hash", dialect: "oracle", in: `SELECT s.serial#, emp# FROM v$session s`,
			want: `SELECT s.serial#, emp# FROM v$session s`},
		{name: "create table quoted", in: `CREATE TABLE "Mixed" ("order" INT)`, want: `CREATE TABLE "Mixed" ("order" INT)`},
		{name: "alter add mixed case column", in: `ALTER TABLE t ADD COLUMN "Mixed" INT`, want: `ALTER TABLE t ADD COLUMN "Mixed" INT`},
		{name: "mysql backtick reserved alias", dialect: "mysql", in: "SELECT EXISTS(SELECT 1) AS `exists`",
			want: "SELECT EXISTS (SELECT 1) AS `exists`"},
		{name: "mysql backtick keyword column", dialect: "mysql", in: "ALTER TABLE `Users` ADD COLUMN `select` INT",
			want: "ALTER TABLE Users ADD COLUMN `select` INT"},
		{name: "mysql backtick table alias", dialect: "mysql", in: "SELECT `o`.`id` FROM `order` AS `o`",
			want: "SELECT o.id FROM `order` o"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := formatWith(tc.in, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
			if err != nil {
				t.Fatalf("formatSQL(%q): %v", tc.in, err)
			}
			if out != tc.want {
				t.Fatalf("formatSQL(%q) = %q, want %q", tc.in, out, tc.want)
			}
		})
	}
}
