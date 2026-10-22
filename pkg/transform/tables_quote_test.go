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

package transform

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestTableTransforms_DropReplacedNameQuotes checks that a name a transform
// replaces is written as the caller gave it: the delimiters recorded for the
// old name (or old alias) must not carry over, or a renamed "Users" would
// become a case-sensitive "Accounts" and a new alias U would not match a
// still-quoted "U" qualifier.
func TestTableTransforms_DropReplacedNameQuotes(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		rule Rule
		want string
	}{
		{
			name: "replace quoted table and qualifiers",
			sql:  `SELECT "Users".id, "Users"."Name" FROM "Users" WHERE "Users".x = 1`,
			rule: ReplaceTable("Users", "Accounts"),
			want: `SELECT Accounts.id, Accounts."Name" FROM Accounts WHERE Accounts.x = 1`,
		},
		{
			name: "alias replaces quoted alias",
			sql:  `SELECT * FROM t AS "X"`,
			rule: AddTableAlias("t", "Y"),
			want: `SELECT * FROM t Y`,
		},
		{
			name: "update replace",
			sql:  `UPDATE "Users" SET a = 1 WHERE "Users".b = 2`,
			rule: ReplaceTable("Users", "Accounts"),
			want: `UPDATE Accounts SET a = 1 WHERE Accounts.b = 2`,
		},
		{
			name: "update alias rewrites quoted qualifier",
			sql:  `UPDATE "Users" SET a = 1 WHERE "Users".b = 2`,
			rule: AddTableAlias("Users", "U"),
			want: `UPDATE "Users" U SET a = 1 WHERE U.b = 2`,
		},
		{
			name: "delete replace",
			sql:  `DELETE FROM "Users" WHERE "Users".b = 2`,
			rule: ReplaceTable("Users", "Accounts"),
			want: `DELETE FROM Accounts WHERE Accounts.b = 2`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseSQLWithDialect(tc.sql, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			stmt := tree.Statements[0]
			if err := Apply(stmt, tc.rule); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := FormatSQL(stmt); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}
