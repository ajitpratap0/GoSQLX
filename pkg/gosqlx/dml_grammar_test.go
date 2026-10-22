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

package gosqlx

import (
	"reflect"
	"sort"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// dmlRoundTripCases are the DML grammar forms of UPDATE / DELETE / INSERT /
// REPLACE / MERGE: each must parse in its dialect, format to want with
// FormatAST and with the statement's own SQL(), and re-parse to the same
// text. want differs from sql only by normalization (AS dropped before a
// table alias, INNER added to a plain JOIN, INTO added where optional).
var dmlRoundTripCases = []struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	want    string // "" means want == sql
}{
	// UPDATE / DELETE row limit (the LIMIT used to be parsed and dropped).
	{"update limit", keywords.DialectMySQL, "UPDATE t SET a = 1 WHERE b = 2 LIMIT 5", ""},
	{"delete limit", keywords.DialectMySQL, "DELETE FROM t WHERE b = 2 LIMIT 5", ""},
	{"delete limit mariadb", keywords.DialectMariaDB, "DELETE FROM t WHERE b = 2 LIMIT 5", ""},
	{"delete order limit", keywords.DialectMySQL, "DELETE FROM t ORDER BY id LIMIT 5", ""},
	{"update order limit", keywords.DialectMySQL, "UPDATE t SET a = 1 WHERE b = 2 ORDER BY id DESC LIMIT 5", ""},
	{"sqlite delete order limit", keywords.DialectSQLite, "DELETE FROM t WHERE a = 1 ORDER BY id LIMIT 3", ""},

	// Target aliases.
	{"update as alias", keywords.DialectPostgreSQL, "UPDATE t AS x SET a = 1", "UPDATE t x SET a = 1"},
	{"update bare alias", keywords.DialectOracle, "UPDATE t x SET a = 1", ""},
	{"update alias sqlite from", keywords.DialectSQLite, "UPDATE orders AS o SET status = 'vip' FROM customers AS c WHERE c.id = o.customer_id",
		"UPDATE orders o SET status = 'vip' FROM customers c WHERE c.id = o.customer_id"},
	{"delete bare alias", keywords.DialectPostgreSQL, "DELETE FROM t x WHERE x.a = 1", ""},
	{"delete as alias", keywords.DialectPostgreSQL, "DELETE FROM t AS x WHERE x.a = 1", "DELETE FROM t x WHERE x.a = 1"},
	{"update only", keywords.DialectPostgreSQL, "UPDATE ONLY t SET x = 1 WHERE d > 0", ""},
	{"delete only", keywords.DialectPostgreSQL, "DELETE FROM ONLY t WHERE a = 1", ""},

	// DELETE ... USING and multi-table forms.
	{"delete using", keywords.DialectPostgreSQL, "DELETE FROM a USING b WHERE a.id = b.id RETURNING a.id", ""},
	{"delete using snowflake", keywords.DialectSnowflake, "DELETE FROM a USING b WHERE a.id = b.id", ""},
	{"mysql delete using join", keywords.DialectMySQL, "DELETE FROM a, b USING a INNER JOIN b ON a.id = b.a_id WHERE a.flag = 0", ""},
	{"mysql delete targets from", keywords.DialectMySQL, "DELETE o FROM o JOIN c ON c.id = o.cid", "DELETE o FROM o INNER JOIN c ON c.id = o.cid"},
	{"mysql delete two targets", keywords.DialectMySQL, "DELETE a, b FROM p a LEFT JOIN m b ON b.pid = a.id WHERE a.k = 'r'", ""},
	{"sqlserver delete target from", keywords.DialectSQLServer, "DELETE o FROM dbo.Orders o LEFT JOIN dbo.Customers c ON c.Id = o.CustomerId WHERE c.Id IS NULL", ""},
	{"oracle delete without from", keywords.DialectOracle, "DELETE employees WHERE employee_id = 999", "DELETE FROM employees WHERE employee_id = 999"},
	{"oracle delete derived", keywords.DialectOracle, "DELETE FROM (SELECT * FROM e WHERE d = 10) WHERE s < 1000", ""},

	// Multi-table UPDATE.
	{"mysql update join", keywords.DialectMySQL, "UPDATE t JOIN u ON t.id = u.id SET t.a = 1", "UPDATE t INNER JOIN u ON t.id = u.id SET t.a = 1"},
	{"mysql update comma", keywords.DialectMySQL, "UPDATE t, u SET t.a = u.b WHERE t.id = u.id", ""},
	{"mysql update join derived", keywords.DialectMySQL, "UPDATE c INNER JOIN (SELECT id, MAX(x) AS m FROM o GROUP BY id) s ON s.id = c.id SET c.m = s.m", ""},
	{"sqlserver update from join", keywords.DialectSQLServer, "UPDATE t SET t.a = s.a FROM dbo.Orders t INNER JOIN dbo.S s ON s.id = t.id WHERE t.b = 1", ""},
	{"postgres update from join", keywords.DialectPostgreSQL, "UPDATE t SET a = s.b FROM s INNER JOIN u ON s.id = u.id WHERE t.id = s.id", ""},
	{"oracle update derived", keywords.DialectOracle, "UPDATE (SELECT e.s AS o, n.s AS n FROM e INNER JOIN n ON e.id = n.id) SET o = n", ""},

	// Modifiers.
	{"insert ignore", keywords.DialectMySQL, "INSERT IGNORE INTO t (a) VALUES (1)", ""},
	{"insert low priority ignore", keywords.DialectMySQL, "INSERT LOW_PRIORITY IGNORE INTO t (a) VALUES (1)", ""},
	{"update modifiers", keywords.DialectMySQL, "UPDATE LOW_PRIORITY IGNORE t SET x = 1", ""},
	{"delete modifiers", keywords.DialectMariaDB, "DELETE LOW_PRIORITY QUICK IGNORE FROM logs WHERE ts < 5", ""},
	{"table named like modifier", keywords.DialectMySQL, "UPDATE ignore SET a = 1", ""},
	{"sqlite insert or replace", keywords.DialectSQLite, "INSERT OR REPLACE INTO t (a) VALUES (1)", ""},
	{"sqlite insert or rollback", keywords.DialectSQLite, "INSERT OR ROLLBACK INTO t (a) VALUES (1)", ""},
	{"sqlite update or ignore", keywords.DialectSQLite, "UPDATE OR IGNORE t SET a = 1 WHERE id = 3", ""},
	{"snowflake insert overwrite", keywords.DialectSnowflake, "INSERT OVERWRITE INTO d SELECT * FROM s", ""},
	{"sqlserver update top", keywords.DialectSQLServer, "UPDATE TOP (500) dbo.Queue SET Status = 1 WHERE Status = 0", ""},
	{"sqlserver delete top percent", keywords.DialectSQLServer, "DELETE TOP (10) PERCENT FROM t", ""},
	{"sqlserver insert without into", keywords.DialectSQLServer, "INSERT t (a) VALUES (1)", "INSERT INTO t (a) VALUES (1)"},

	// SET list targets and values.
	{"set tuple", keywords.DialectPostgreSQL, "UPDATE t SET (a, b) = (1, 2) WHERE id = 5", ""},
	{"set tuple subquery", keywords.DialectOracle, "UPDATE t SET (a, b) = (SELECT x, y FROM u WHERE u.id = t.id) WHERE id = 6", ""},
	{"set qualified target", keywords.DialectSQLServer, "UPDATE o SET o.a = 1 FROM dbo.Orders AS o", "UPDATE o SET o.a = 1 FROM dbo.Orders o"},
	{"set default", keywords.DialectPostgreSQL, "UPDATE t SET a = DEFAULT, b = 2", ""},
	{"set keyword column", keywords.DialectSQLite, "UPDATE OR REPLACE s SET key = 'k2' WHERE id = 1", ""},
	{"values default", keywords.DialectPostgreSQL, "INSERT INTO t (a, b) VALUES (DEFAULT, 1), (2, DEFAULT)", ""},
	{"values empty mysql", keywords.DialectMySQL, "INSERT INTO t () VALUES ()", "INSERT INTO t VALUES ()"},
	{"keyword insert columns", keywords.DialectSQLite, "INSERT INTO settings (key, value) VALUES ('a', '1')", ""},

	// INSERT variants.
	{"mysql row alias", keywords.DialectMySQL, "INSERT INTO t (a) VALUES (1) AS n ON DUPLICATE KEY UPDATE a = n.a", ""},
	{"mysql row alias columns", keywords.DialectMySQL, "INSERT INTO t (a) VALUES (1) AS n (x) ON DUPLICATE KEY UPDATE a = n.x", ""},
	{"on conflict where", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) WHERE b > 0 DO NOTHING", ""},
	{"on conflict expression", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) ON CONFLICT (lower(a)) DO NOTHING", ""},
	{"on conflict keyword column", keywords.DialectSQLite, "INSERT INTO s (key) VALUES ('p') ON CONFLICT (key) DO UPDATE SET key = excluded.key WHERE s.key <> 'x'", ""},
	{"overriding system value", keywords.DialectPostgreSQL, "INSERT INTO t (id, name) OVERRIDING SYSTEM VALUE VALUES (1, 'x')", ""},
	{"overriding user value", keywords.DialectPostgreSQL, "INSERT INTO t (id) OVERRIDING USER VALUE SELECT 1", ""},
	{"returning alias", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) RETURNING a AS x, (xmax = 0) AS inserted", ""},
	{"delete returning alias", keywords.DialectPostgreSQL, "DELETE FROM t x WHERE x.c < 1 RETURNING x.id AS deleted_id", ""},
	{"oracle returning into", keywords.DialectOracle, "INSERT INTO t (a) VALUES (1) RETURNING a INTO :x", ""},
	{"oracle update returning into", keywords.DialectOracle, "UPDATE t SET b = b - :amt WHERE id = :id RETURNING b INTO :nb", ""},
	{"oracle delete returning into", keywords.DialectOracle, "DELETE FROM t WHERE d < SYSDATE RETURNING COUNT(*) INTO :cnt", ""},
	{"oracle insert all", keywords.DialectOracle, "INSERT ALL INTO a (x) VALUES (1) INTO b (x) VALUES (2) SELECT 1 FROM dual", ""},
	{"oracle insert all when", keywords.DialectOracle, "INSERT ALL WHEN r = 'E' THEN INTO e VALUES (id, amt) WHEN r = 'W' THEN INTO w VALUES (id, amt) ELSE INTO o VALUES (id, amt) SELECT id, r, amt FROM s", ""},
	{"oracle insert first", keywords.DialectOracle, "INSERT FIRST WHEN amt > 10 THEN INTO big VALUES (id, amt) ELSE INTO small VALUES (id, amt) SELECT id, amt FROM s", ""},
	{"clickhouse insert settings", keywords.DialectClickHouse, "INSERT INTO t (a, b) SETTINGS async_insert = 1, wait_for_async_insert = 0 VALUES (1, 'x')", ""},
	{"clickhouse insert settings format", keywords.DialectClickHouse, "INSERT INTO t SETTINGS async_insert = 1 FORMAT CSV", ""},
	{"clickhouse insert function", keywords.DialectClickHouse, "INSERT INTO FUNCTION s3('https://b.s3.amazonaws.com/o.parquet', 'Parquet') SELECT * FROM events", ""},
	{"clickhouse insert format", keywords.DialectClickHouse, "INSERT INTO t (a) FORMAT JSONEachRow", ""},
	{"clickhouse values format", keywords.DialectClickHouse, "INSERT INTO t VALUES (1) FORMAT Values", ""},

	// REPLACE.
	{"replace select", keywords.DialectMySQL, "REPLACE INTO t (a) SELECT a FROM u", ""},
	{"replace set", keywords.DialectMySQL, "REPLACE t SET a = 1, b = 'x'", "REPLACE INTO t SET a = 1, b = 'x'"},
	{"replace returning", keywords.DialectMariaDB, "REPLACE INTO s (k, v) VALUES ('a', '1') RETURNING k, v", ""},
	{"replace keyword columns", keywords.DialectSQLite, "REPLACE INTO settings (key, value) VALUES ('lang', 'en')", ""},

	// OUTPUT.
	{"delete output", keywords.DialectSQLServer, "DELETE FROM t OUTPUT DELETED.id WHERE a = 1", ""},
	{"delete output into", keywords.DialectSQLServer, "DELETE FROM dbo.O OUTPUT DELETED.Id, DELETED.T INTO dbo.A (Id, T) WHERE c < '2020-01-01'", ""},
	{"update output alias", keywords.DialectSQLServer, "UPDATE dbo.O SET S = 'x' OUTPUT DELETED.S AS OldS, INSERTED.S AS NewS WHERE Id = 1", ""},
	{"insert output into variable", keywords.DialectSQLServer, "INSERT INTO dbo.Log (Msg) OUTPUT INSERTED.Id INTO @Ids (Id) VALUES ('x')", ""},
	{"delete output then from", keywords.DialectSQLServer, "DELETE FROM t OUTPUT deleted.* FROM t JOIN u ON u.id = t.id", "DELETE t OUTPUT deleted.* FROM t INNER JOIN u ON u.id = t.id"},

	// MERGE.
	{"merge derived source", keywords.DialectSnowflake, "MERGE INTO t USING (SELECT k FROM s2) s ON t.k = s.k WHEN NOT MATCHED THEN INSERT (k) VALUES (s.k)", ""},
	{"merge derived source as", keywords.DialectSQLServer, "MERGE INTO dbo.I AS t USING (SELECT Sku, SUM(Qty) AS Qty FROM dbo.R GROUP BY Sku) AS s ON t.Sku = s.Sku WHEN MATCHED THEN UPDATE SET t.OnHand = t.OnHand + s.Qty",
		"MERGE INTO dbo.I t USING (SELECT Sku, SUM(Qty) AS Qty FROM dbo.R GROUP BY Sku) s ON t.Sku = s.Sku WHEN MATCHED THEN UPDATE SET t.OnHand = t.OnHand + s.Qty"},
	{"merge do nothing returning", keywords.DialectPostgreSQL, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DO NOTHING WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id) RETURNING merge_action(), t.*", ""},
	{"merge by target", keywords.DialectSQLServer, "MERGE INTO dbo.T tgt USING dbo.S src ON tgt.Id = src.Id WHEN NOT MATCHED BY TARGET THEN INSERT (Id) VALUES (src.Id) WHEN NOT MATCHED BY SOURCE THEN DELETE", ""},
	{"merge oracle delete where", keywords.DialectOracle, "MERGE INTO t USING s ON (t.a = s.a) WHEN MATCHED THEN UPDATE SET b = s.b DELETE WHERE (s.c = 1)", ""},
	{"merge oracle update and insert where", keywords.DialectOracle, "MERGE INTO e USING u ON (e.id = u.id) WHEN MATCHED THEN UPDATE SET e.s = u.s WHERE e.s <> u.s WHEN NOT MATCHED THEN INSERT (id, s) VALUES (u.id, u.s) WHERE u.s > 0", ""},
	{"merge output", keywords.DialectSQLServer, "MERGE INTO t x USING u y ON x.id = y.id WHEN MATCHED THEN UPDATE SET a = 1 OUTPUT $action, INSERTED.id", ""},
}

func TestDMLGrammarRoundTrip(t *testing.T) {
	for _, tc := range dmlRoundTripCases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.sql
			}
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
			}
			if got := FormatAST(tree, WithIndent(0)); got != want {
				t.Errorf("FormatAST:\n got: %s\nwant: %s", got, want)
			}
			sqler, ok := tree.Statements[0].(interface{ SQL() string })
			if !ok {
				t.Fatalf("%T has no SQL()", tree.Statements[0])
			}
			if got := sqler.SQL(); got != want {
				t.Errorf("SQL():\n got: %s\nwant: %s", got, want)
			}
			// The readable (one clause per line) form must re-parse to itself.
			readable := FormatAST(tree)
			tree2, err := ParseWithDialect(readable, tc.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", readable, err)
			}
			defer ast.ReleaseAST(tree2)
			if got := FormatAST(tree2); got != readable {
				t.Errorf("not idempotent:\n got: %s\nwant: %s", got, readable)
			}
			if got := FormatAST(tree2, WithIndent(0)); got != want {
				t.Errorf("reparsed compact form:\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestDMLGrammarDialectGates checks that dialect-specific DML syntax is
// rejected outside its dialects instead of being misread.
func TestDMLGrammarDialectGates(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"order by on delete in postgres", keywords.DialectPostgreSQL, "DELETE FROM t ORDER BY id"},
		{"mysql modifier in postgres", keywords.DialectPostgreSQL, "INSERT IGNORE INTO t (a) VALUES (1)"},
		{"sqlite conflict modifier in mysql", keywords.DialectMySQL, "INSERT OR REPLACE INTO t (a) VALUES (1)"},
		{"multi-table update in postgres", keywords.DialectPostgreSQL, "UPDATE t JOIN u ON t.id = u.id SET a = 1"},
		{"delete without from in postgres", keywords.DialectPostgreSQL, "DELETE t WHERE a = 1"},
		{"insert without into in postgres", keywords.DialectPostgreSQL, "INSERT t (a) VALUES (1)"},
		{"multi-table delete without from", keywords.DialectMySQL, "DELETE a, b WHERE a.id = 1"},
		{"insert all outside oracle", keywords.DialectPostgreSQL, "INSERT ALL INTO a VALUES (1) SELECT 1"},
		{"insert first needs when", keywords.DialectOracle, "INSERT FIRST INTO a VALUES (1) SELECT 1 FROM dual"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("expected an error for %q in %s", tc.sql, tc.dialect)
			}
		})
	}
}

// TestDMLGrammarExtractTables checks that ExtractTables sees the tables of
// multi-table UPDATE and DELETE statements.
func TestDMLGrammarExtractTables(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []string
	}{
		{"update join", keywords.DialectMySQL, "UPDATE a JOIN b ON a.id = b.id SET a.x = b.x", []string{"a", "b"}},
		{"update comma", keywords.DialectMySQL, "UPDATE a, b SET a.x = b.x WHERE a.id = b.id", []string{"a", "b"}},
		{"delete targets from", keywords.DialectMySQL, "DELETE o FROM orders o JOIN users u ON u.id = o.uid", []string{"orders", "users"}},
		{"delete using join", keywords.DialectMySQL, "DELETE FROM a USING a JOIN b ON a.id = b.id", []string{"a", "b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			got := ExtractTables(tree)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractTables = %v, want %v", got, tc.want)
			}
		})
	}
}
