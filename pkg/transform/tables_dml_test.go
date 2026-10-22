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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// applyDialect parses sql in dialect d, applies rule and returns the
// formatted statement.
func applyDialect(t *testing.T, d keywords.SQLDialect, sql string, rule Rule) (string, error) {
	t.Helper()
	tree, err := ParseSQLWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, d, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q: got %d statements, want 1", sql, len(tree.Statements))
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, rule); err != nil {
		return "", err
	}
	return FormatSQLWithDialect(stmt, d), nil
}

// ReplaceTable renames the table in every place a multi-table UPDATE or
// DELETE names it, so no reference to the old name is left behind.
func TestReplaceTable_MultiTableDML(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"mysql delete targets from", keywords.DialectMySQL,
			"DELETE orders FROM orders JOIN c ON c.id = orders.cid WHERE orders.x = 1",
			"DELETE orders_v2 FROM orders_v2 INNER JOIN c ON c.id = orders_v2.cid WHERE orders_v2.x = 1"},
		{"mysql delete using with two targets", keywords.DialectMySQL,
			"DELETE FROM orders, c USING orders JOIN c ON c.id = orders.cid",
			"DELETE FROM orders_v2, c USING orders_v2 INNER JOIN c ON c.id = orders_v2.cid"},
		{"mysql delete second target", keywords.DialectMySQL,
			"DELETE c, orders FROM c JOIN orders ON c.id = orders.cid",
			"DELETE c, orders_v2 FROM c INNER JOIN orders_v2 ON c.id = orders_v2.cid"},
		{"mysql update join", keywords.DialectMySQL,
			"UPDATE orders JOIN c ON c.id = orders.cid SET orders.a = 1 WHERE orders.b = 2",
			"UPDATE orders_v2 INNER JOIN c ON c.id = orders_v2.cid SET orders_v2.a = 1 WHERE orders_v2.b = 2"},
		{"mysql update join renames the joined table", keywords.DialectMySQL,
			"UPDATE c JOIN orders ON c.id = orders.cid SET c.a = orders.a",
			"UPDATE c INNER JOIN orders_v2 ON c.id = orders_v2.cid SET c.a = orders_v2.a"},
		{"mysql update comma targets", keywords.DialectMySQL,
			"UPDATE orders, c SET orders.a = c.a WHERE orders.id = c.id",
			"UPDATE orders_v2, c SET orders_v2.a = c.a WHERE orders_v2.id = c.id"},
		{"mysql update order by", keywords.DialectMySQL,
			"UPDATE orders SET a = 1 WHERE orders.id = 3 ORDER BY orders.id LIMIT 2",
			"UPDATE orders_v2 SET a = 1 WHERE orders_v2.id = 3 ORDER BY orders_v2.id LIMIT 2"},
		{"postgres delete using", keywords.DialectPostgreSQL,
			"DELETE FROM c USING orders WHERE c.id = orders.cid",
			"DELETE FROM c USING orders_v2 WHERE c.id = orders_v2.cid"},
		{"postgres update from returning", keywords.DialectPostgreSQL,
			"UPDATE c SET a = orders.a FROM orders WHERE c.id = orders.cid RETURNING orders.a",
			"UPDATE c SET a = orders_v2.a FROM orders_v2 WHERE c.id = orders_v2.cid RETURNING orders_v2.a"},
		{"sqlserver delete output from alias", keywords.DialectSQLServer,
			"DELETE o OUTPUT deleted.id FROM orders o JOIN c ON c.id = o.cid",
			"DELETE o OUTPUT deleted.id FROM orders_v2 o INNER JOIN c ON c.id = o.cid"},
		{"unrelated table untouched", keywords.DialectMySQL,
			"DELETE c FROM c JOIN d ON d.id = c.did",
			"DELETE c FROM c INNER JOIN d ON d.id = c.did"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyDialect(t, tc.dialect, tc.sql, ReplaceTable("orders", "orders_v2"))
			if err != nil {
				t.Fatalf("ReplaceTable: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// AddTableAlias aliases the table wherever a multi-table UPDATE or DELETE
// names it, points the qualifiers at the alias and renames DELETE targets.
func TestAddTableAlias_MultiTableDML(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"mysql delete targets from", keywords.DialectMySQL,
			"DELETE orders FROM orders JOIN c ON c.id = orders.cid WHERE orders.x = 1",
			"DELETE o FROM orders o INNER JOIN c ON c.id = o.cid WHERE o.x = 1"},
		{"mysql delete using with two targets", keywords.DialectMySQL,
			"DELETE FROM orders, c USING orders JOIN c ON c.id = orders.cid",
			"DELETE FROM o, c USING orders o INNER JOIN c ON c.id = o.cid"},
		{"mysql delete from replaces an earlier alias", keywords.DialectMySQL,
			"DELETE x FROM orders x JOIN c ON c.id = x.cid",
			"DELETE o FROM orders o INNER JOIN c ON c.id = o.cid"},
		{"mysql update join", keywords.DialectMySQL,
			"UPDATE orders JOIN c ON c.id = orders.cid SET orders.a = 1 WHERE orders.b = 2",
			"UPDATE orders o INNER JOIN c ON c.id = o.cid SET o.a = 1 WHERE o.b = 2"},
		{"mysql update joined table", keywords.DialectMySQL,
			"UPDATE c JOIN orders ON c.id = orders.cid SET c.a = orders.a",
			"UPDATE c INNER JOIN orders o ON c.id = o.cid SET c.a = o.a"},
		{"mysql update comma targets", keywords.DialectMySQL,
			"UPDATE orders, c SET orders.a = c.a WHERE orders.id = c.id",
			"UPDATE orders o, c SET o.a = c.a WHERE o.id = c.id"},
		{"mysql single table qualifiers", keywords.DialectMySQL,
			"UPDATE orders SET a = 1 WHERE orders.id = 3 ORDER BY orders.id LIMIT 2",
			"UPDATE orders o SET a = 1 WHERE o.id = 3 ORDER BY o.id LIMIT 2"},
		{"postgres delete using", keywords.DialectPostgreSQL,
			"DELETE FROM c USING orders WHERE c.id = orders.cid",
			"DELETE FROM c USING orders o WHERE c.id = o.cid"},
		{"postgres update from returning", keywords.DialectPostgreSQL,
			"UPDATE c SET a = orders.a FROM orders WHERE c.id = orders.cid RETURNING orders.a",
			"UPDATE c SET a = o.a FROM orders o WHERE c.id = o.cid RETURNING o.a"},
		{"single table without qualifiers", keywords.DialectPostgreSQL,
			"DELETE FROM orders WHERE id = 1",
			"DELETE FROM orders o WHERE id = 1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyDialect(t, tc.dialect, tc.sql, AddTableAlias("orders", "o"))
			if err != nil {
				t.Fatalf("AddTableAlias: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// A table that appears twice cannot take one alias: the transform fails
// instead of emitting SQL that names both instances the same.
func TestAddTableAlias_AmbiguousDML(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"update self join", keywords.DialectMySQL,
			"UPDATE orders JOIN orders p ON p.id = orders.parent SET orders.a = 1"},
		{"delete using self reference", keywords.DialectPostgreSQL,
			"DELETE FROM orders USING orders o2 WHERE orders.parent = o2.id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := applyDialect(t, tc.dialect, tc.sql, AddTableAlias("orders", "o"))
			if err == nil || !strings.Contains(err.Error(), "appears 2 times") {
				t.Errorf("err = %v, want an ambiguity error", err)
			}
		})
	}
}
