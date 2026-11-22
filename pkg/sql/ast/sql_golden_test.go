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

package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// goldenParseCase pins the exact SQL() output for a parsed statement. The
// want strings were captured from the strings.Builder/fmt.Sprintf based
// serializer before it was rewritten to render through one pooled buffer
// (issue #558), so any byte-level drift in SQL() fails here.
//
// Inputs that the parser rejects (and therefore cannot be pinned through
// parsing) are covered by goldenNodes instead: UPDATE ... FROM, DELETE ...
// USING, POSITION(... IN ...), SUBSTRING(... FROM ... FOR ...), SIMILAR TO,
// custom OPERATOR(...) and postfix factorial.
type goldenParseCase struct {
	name    string
	dialect keywords.SQLDialect // empty means gosqlx.Parse (default dialect)
	sql     string
	want    string
	stable  bool // re-parsing want reproduces want byte-for-byte
}

var goldenParseCases = []goldenParseCase{
	{"rt/simple select", "", "SELECT * FROM users", "SELECT * FROM users", true},
	{"rt/select columns", "", "SELECT id, name FROM users", "SELECT id, name FROM users", true},
	{"rt/select where", "", "SELECT id FROM users WHERE active = TRUE", "SELECT id FROM users WHERE active = TRUE", true},
	{"rt/select and", "", "SELECT id FROM users WHERE active = TRUE AND age > 18", "SELECT id FROM users WHERE active = TRUE AND age > 18", true},
	{"rt/select or", "", "SELECT id FROM users WHERE a = 1 OR b = 2", "SELECT id FROM users WHERE a = 1 OR b = 2", true},
	{"rt/select distinct", "", "SELECT DISTINCT status FROM orders", "SELECT DISTINCT status FROM orders", true},
	{"rt/select limit offset", "", "SELECT * FROM users LIMIT 10 OFFSET 20", "SELECT * FROM users LIMIT 10 OFFSET 20", true},
	{"rt/select order by", "", "SELECT * FROM users ORDER BY name", "SELECT * FROM users ORDER BY name", true},
	{"rt/select order by desc", "", "SELECT * FROM users ORDER BY name DESC", "SELECT * FROM users ORDER BY name DESC", true},
	{"rt/select group by having", "", "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5", "SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5", true},
	{"rt/select alias", "", "SELECT COUNT(*) AS total FROM users", "SELECT COUNT(*) AS total FROM users", true},
	{"rt/insert values", "", "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')", "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')", true},
	{"rt/insert multi row", "", "INSERT INTO users (name) VALUES ('Alice'), ('Bob')", "INSERT INTO users (name) VALUES ('Alice'), ('Bob')", true},
	{"rt/update simple", "", "UPDATE users SET name = 'Bob' WHERE id = 1", "UPDATE users SET name = 'Bob' WHERE id = 1", true},
	{"rt/delete simple", "", "DELETE FROM users WHERE id = 1", "DELETE FROM users WHERE id = 1", true},
	{"rt/select in list", "", "SELECT * FROM users WHERE id IN (1, 2, 3)", "SELECT * FROM users WHERE id IN (1, 2, 3)", true},
	{"rt/select between", "", "SELECT * FROM users WHERE age BETWEEN 18 AND 65", "SELECT * FROM users WHERE age BETWEEN 18 AND 65", true},
	{"rt/select is null", "", "SELECT * FROM users WHERE email IS NULL", "SELECT * FROM users WHERE email IS NULL", true},
	{"rt/select is not null", "", "SELECT * FROM users WHERE email IS NOT NULL", "SELECT * FROM users WHERE email IS NOT NULL", true},
	{"rt/select like", "", "SELECT * FROM users WHERE name LIKE '%alice%'", "SELECT * FROM users WHERE name LIKE '%alice%'", true},
	{"rt/select subquery", "", "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)", "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)", true},
	{"rt/select exists", "", "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)", "SELECT * FROM users WHERE EXISTS (SELECT 1 FROM orders WHERE orders.user_id = users.id)", true},
	{"rt/select case", "", "SELECT CASE WHEN x > 0 THEN 'pos' ELSE 'neg' END FROM t", "SELECT CASE WHEN x > 0 THEN 'pos' ELSE 'neg' END FROM t", true},
	{"rt/select cast", "", "SELECT CAST(price AS INTEGER) FROM products", "SELECT CAST(price AS INTEGER) FROM products", true},
	{"rt/left join", "", "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id", "SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id", true},
	{"rt/inner join", "", "SELECT * FROM a INNER JOIN b ON a.id = b.a_id", "SELECT * FROM a INNER JOIN b ON a.id = b.a_id", true},
	{"rt/create table", "", "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)", "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL)", true},
	{"rt/drop table", "", "DROP TABLE IF EXISTS users CASCADE", "DROP TABLE IF EXISTS users CASCADE", true},
	{"rt/union", "", "SELECT id FROM a UNION SELECT id FROM b", "SELECT id FROM a UNION SELECT id FROM b", true},
	{"rt/union all", "", "SELECT id FROM a UNION ALL SELECT id FROM b", "SELECT id FROM a UNION ALL SELECT id FROM b", true},
	{"idem/select with where", "", "SELECT id, name FROM users WHERE active = TRUE", "SELECT id, name FROM users WHERE active = TRUE", true},
	{"idem/select with join", "", "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id", "SELECT u.name FROM users u LEFT JOIN orders o ON u.id = o.user_id", true},
	{"idem/select with order limit offset", "", "SELECT * FROM products ORDER BY price DESC LIMIT 10 OFFSET 5", "SELECT * FROM products ORDER BY price DESC LIMIT 10 OFFSET 5", true},
	{"idem/select with group by having", "", "SELECT dept, COUNT(*) FROM employees GROUP BY dept HAVING COUNT(*) > 5", "SELECT dept, COUNT(*) FROM employees GROUP BY dept HAVING COUNT(*) > 5", true},
	{"idem/insert multi-row", "", "INSERT INTO t (a) VALUES ('x'), ('y')", "INSERT INTO t (a) VALUES ('x'), ('y')", true},
	{"idem/CTE", "", "WITH cte AS (SELECT * FROM t) SELECT * FROM cte", "WITH cte AS (SELECT * FROM t) SELECT * FROM cte", true},
	{"idem/between", "", "SELECT * FROM t WHERE x BETWEEN 1 AND 10", "SELECT * FROM t WHERE x BETWEEN 1 AND 10", true},
	{"idem/in list", "", "SELECT * FROM t WHERE status IN ('a', 'b')", "SELECT * FROM t WHERE status IN ('a', 'b')", true},
	{"idem/cast", "", "SELECT CAST(price AS INTEGER) FROM t", "SELECT CAST(price AS INTEGER) FROM t", true},
	{"idem/exists subquery", "", "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u)", "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u)", true},
	{"idem/window function", "", "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM t", "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM t", true},
	{"idem/insert on conflict", "", "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING", "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO NOTHING", true},
	{"bench/7line", "", "SELECT u.id, u.name, COUNT(o.id) AS order_count\nFROM users u\nLEFT JOIN orders o ON u.id = o.user_id\nWHERE u.active = TRUE AND u.created_at > '2024-01-01'\nGROUP BY u.id, u.name\nHAVING COUNT(o.id) > 5\nORDER BY order_count DESC LIMIT 100", "SELECT u.id, u.name, COUNT(o.id) AS order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = TRUE AND u.created_at > '2024-01-01' GROUP BY u.id, u.name HAVING COUNT(o.id) > 5 ORDER BY order_count DESC LIMIT 100", true},
	{"bench/15line", "", "WITH recent AS (\n    SELECT user_id, SUM(total) AS spend\n    FROM orders\n    WHERE status IN ('paid', 'shipped') AND created_at BETWEEN '2024-01-01' AND '2024-12-31'\n    GROUP BY user_id\n)\nSELECT u.id, u.email,\n       CASE WHEN r.spend > 1000 THEN 'vip' ELSE 'standard' END AS tier,\n       ROW_NUMBER() OVER (PARTITION BY u.country ORDER BY r.spend DESC) AS rnk,\n       CAST(r.spend AS INTEGER) AS spend_int\nFROM users u\nINNER JOIN recent r ON u.id = r.user_id\nWHERE u.email LIKE '%@example.com' AND u.deleted_at IS NULL AND NOT u.banned\nORDER BY rnk, u.id\nLIMIT 50 OFFSET 10", "WITH recent AS (SELECT user_id, SUM(total) AS spend FROM orders WHERE status IN ('paid', 'shipped') AND created_at BETWEEN '2024-01-01' AND '2024-12-31' GROUP BY user_id) SELECT u.id, u.email, CASE WHEN r.spend > 1000 THEN 'vip' ELSE 'standard' END AS tier, ROW_NUMBER() OVER (PARTITION BY u.country ORDER BY r.spend DESC) AS rnk, CAST(r.spend AS INTEGER) AS spend_int FROM users u INNER JOIN recent r ON u.id = r.user_id WHERE u.email LIKE '%@example.com' AND u.deleted_at IS NULL AND NOT u.banned ORDER BY rnk, u.id LIMIT 50 OFFSET 10", true},
	{"extra/not like", "", "SELECT * FROM t WHERE name NOT LIKE 'a%'", "SELECT * FROM t WHERE name NOT LIKE 'a%'", true},
	{"extra/not like lowercase", "", "SELECT * FROM t WHERE name not like 'a%'", "SELECT * FROM t WHERE name NOT LIKE 'a%'", true},
	{"extra/not ilike", "", "SELECT * FROM t WHERE name NOT ILIKE 'a%'", "SELECT * FROM t WHERE name NOT ILIKE 'a%'", true},
	{"extra/lowercase bool", "", "SELECT * FROM t WHERE active = true", "SELECT * FROM t WHERE active = true", true},
	{"extra/is not null and not", "", "SELECT * FROM t WHERE x IS NOT NULL AND NOT (a = b)", "SELECT * FROM t WHERE x IS NOT NULL AND NOT (a = b)", true},
	{"extra/extract", "", "SELECT EXTRACT(YEAR FROM d) FROM t", "SELECT EXTRACT(YEAR FROM d) FROM t", true},
	{"extra/interval", "", "SELECT INTERVAL '1 day' FROM t", "SELECT INTERVAL '1 day' FROM t", true},
	{"extra/interval qualifier", "", "SELECT d + INTERVAL '1' DAY, INTERVAL '1-2' YEAR TO MONTH FROM t", "SELECT d + INTERVAL '1' DAY, INTERVAL '1-2' YEAR TO MONTH FROM t", true},
	{"extra/window groups exclude", "", "SELECT sum(x) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM t", "SELECT sum(x) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES) FROM t", true},
	{"extra/window range interval", "", "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW) FROM t", "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW) FROM t", true},
	{"extra/arrays", "", "SELECT ARRAY[1, 2], arr[1], arr[1:3], arr[2:], arr[:5], m[1][2] FROM t", "SELECT ARRAY[1, 2], arr[1], arr[1:3], arr[2:], arr[:5], m[1][2] FROM t", true},
	{"extra/rollup", "", "SELECT a, b FROM t GROUP BY ROLLUP(a, b)", "SELECT a, b FROM t GROUP BY ROLLUP(a, b)", true},
	{"extra/grouping sets", "", "SELECT a, b FROM t GROUP BY GROUPING SETS((a, b), (a), ())", "SELECT a, b FROM t GROUP BY GROUPING SETS((a, b), (a), ())", true},
	{"extra/order nulls fetch", "", "SELECT a FROM t ORDER BY a DESC NULLS LAST FETCH FIRST 10 ROWS ONLY", "SELECT a FROM t ORDER BY a DESC NULLS LAST FETCH FIRST 10 ROWS ONLY", true},
	{"extra/for update skip locked", "", "SELECT a FROM t FOR UPDATE SKIP LOCKED", "SELECT a FROM t FOR UPDATE SKIP LOCKED", true},
	{"extra/recursive cte", "", "WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT * FROM r", "WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT * FROM r", true},
	{"extra/distinct on", "", "SELECT DISTINCT ON (a) a, b FROM t", "SELECT DISTINCT ON (a) a, b FROM t", true},
	{"extra/named window", "", "SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)", "SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)", true},
	{"extra/named window refinement", "", "SELECT SUM(x) OVER (w ORDER BY b) FROM t WINDOW w AS (PARTITION BY a)", "SELECT SUM(x) OVER (w ORDER BY b) FROM t WINDOW w AS (PARTITION BY a)", true},
	{"extra/named window parenthesized", "", "SELECT SUM(x) OVER (w) FROM t WINDOW w AS (PARTITION BY a)", "SELECT SUM(x) OVER (w) FROM t WINDOW w AS (PARTITION BY a)", true},
	{"extra/window chain", "", "SELECT SUM(x) OVER w2 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b)", "SELECT SUM(x) OVER w2 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b)", true},
	{"extra/any subquery", "", "SELECT * FROM t WHERE a = ANY (SELECT b FROM u)", "SELECT * FROM t WHERE a = ANY (SELECT b FROM u)", true},
	{"extra/aggregate filter order", "", "SELECT COUNT(DISTINCT a) FILTER (WHERE b > 1), STRING_AGG(c, ',' ORDER BY c) FROM t", "SELECT COUNT(DISTINCT a) FILTER (WHERE b > 1), STRING_AGG(c, ',' ORDER BY c) FROM t", true},
	{"extra/insert on conflict update returning", "", "INSERT INTO t (a, b) VALUES (1, 'x') ON CONFLICT (a) DO UPDATE SET b = 'y' WHERE t.b IS NULL RETURNING a", "INSERT INTO t (a, b) VALUES (1, 'x') ON CONFLICT (a) DO UPDATE SET b = 'y' WHERE t.b IS NULL RETURNING a", true},
	{"extra/update returning", "", "UPDATE t SET a = 1, b = 'x' WHERE id = 2 RETURNING a, b", "UPDATE t SET a = 1, b = 'x' WHERE id = 2 RETURNING a, b", true},
	{"extra/delete returning", "", "DELETE FROM t WHERE id = 1 RETURNING id", "DELETE FROM t WHERE id = 1 RETURNING id", true},
	{"extra/limit only", "", "SELECT a FROM t LIMIT 0", "SELECT a FROM t LIMIT 0", true},
	{"extra/qualified star", "", "SELECT t.*, u.a FROM t, u", "SELECT t.*, u.a FROM t, u", true},
	{"extra/nested functions", "", "SELECT COALESCE(MAX(a), 0), UPPER(LOWER(b)) FROM t", "SELECT COALESCE(MAX(a), 0), UPPER(LOWER(b)) FROM t", true},
	{"extra/float and negative", "", "SELECT 3.14, -2, 1e3 FROM t", "SELECT 3.14, -2, 1e3 FROM t", true},
	{"extra/null literal", "", "SELECT NULL, a FROM t WHERE b = NULL", "SELECT NULL, a FROM t WHERE b = NULL", true},
	{"extra/right full join", "", "SELECT * FROM a RIGHT JOIN b ON a.id = b.id FULL OUTER JOIN c ON b.id = c.id", "SELECT * FROM a RIGHT JOIN b ON a.id = b.id FULL JOIN c ON b.id = c.id", true},
	{"extra/case no else", "", "SELECT CASE WHEN a = 1 THEN 'x' WHEN a = 2 THEN 'y' END FROM t", "SELECT CASE WHEN a = 1 THEN 'x' WHEN a = 2 THEN 'y' END FROM t", true},
	{"extra/window frame range", "", "SELECT SUM(a) OVER (ORDER BY b RANGE UNBOUNDED PRECEDING) FROM t", "SELECT SUM(a) OVER (ORDER BY b RANGE UNBOUNDED PRECEDING) FROM t", true},
	{"extra/order nulls first asc", "", "SELECT a FROM t ORDER BY a ASC NULLS FIRST, b", "SELECT a FROM t ORDER BY a NULLS FIRST, b", true},
	{"extra/placeholder", "", "SELECT * FROM t WHERE id = $1", "SELECT * FROM t WHERE id = $1", true},
	{"extra/scalar subquery and simple case", "", "SELECT (SELECT MAX(x) FROM u) AS m, CASE a WHEN 1 THEN 'one' ELSE 'other' END FROM t", "SELECT (SELECT MAX(x) FROM u) AS m, CASE a WHEN 1 THEN 'one' ELSE 'other' END FROM t", true},
	{"extra/derived and lateral", "", "SELECT * FROM (SELECT a FROM t) AS s CROSS JOIN LATERAL (SELECT 1) AS l", "SELECT * FROM (SELECT a FROM t) s CROSS JOIN LATERAL (SELECT 1) l", true},
	{"extra/except", "", "SELECT a FROM t1 EXCEPT SELECT a FROM t2", "SELECT a FROM t1 EXCEPT SELECT a FROM t2", true},
	{"extra/create table constraints", "", "CREATE TABLE t (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL DEFAULT 'x', FOREIGN KEY (id) REFERENCES u (id) ON DELETE CASCADE)", "CREATE TABLE t (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL DEFAULT 'x', FOREIGN KEY (id) REFERENCES u (id) ON DELETE CASCADE)", true},
	{"extra/string escapes", "", "SELECT 'it''s', 'héllo' FROM t", "SELECT 'it''s', 'héllo' FROM t", true},
	{"extra/quoted identifier", "", "SELECT \"my col\" FROM t", "SELECT \"my col\" FROM t", true},
	{"extra/multi statement", "", "SELECT 1; SELECT 2", "SELECT 1;\nSELECT 2", true},
	{"extra/unary minus and plus", "", "SELECT -a, +b FROM t", "SELECT -a, +b FROM t", true},
	{"extra/not between not in", "", "SELECT * FROM t WHERE a NOT BETWEEN 1 AND 2 AND b NOT IN (1, 2)", "SELECT * FROM t WHERE a NOT BETWEEN 1 AND 2 AND b NOT IN (1, 2)", true},
	{"extra/intersect", "", "SELECT a FROM t1 INTERSECT SELECT a FROM t2", "SELECT a FROM t1 INTERSECT SELECT a FROM t2", true},
	{"extra/insert select", "", "INSERT INTO t (a) SELECT a FROM u", "INSERT INTO t (a) SELECT a FROM u", true},
	{"extra/with insert", "", "WITH c AS (SELECT 1 AS a) INSERT INTO t (a) SELECT a FROM c", "WITH c AS (SELECT 1 AS a) INSERT INTO t (a) SELECT a FROM c", true},
	{"extra/offset fetch", "", "SELECT a FROM t ORDER BY a OFFSET 5 ROWS FETCH NEXT 10 ROWS ONLY", "SELECT a FROM t ORDER BY a OFFSET 5 ROWS FETCH NEXT 10 ROWS ONLY", true},
	{"extra/tuple in", "", "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))", "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3, 4))", true},
	{"extra/cube", "", "SELECT a, b FROM t GROUP BY CUBE(a, b)", "SELECT a, b FROM t GROUP BY CUBE(a, b)", true},
	{"extra/all subquery", "", "SELECT * FROM t WHERE a > ALL (SELECT b FROM u)", "SELECT * FROM t WHERE a > ALL (SELECT b FROM u)", true},
	{"extra/materialized cte", "", "WITH c AS MATERIALIZED (SELECT 1) SELECT * FROM c", "WITH c AS MATERIALIZED (SELECT 1) SELECT * FROM c", true},
	{"extra/cte columns", "", "WITH c (x, y) AS (SELECT 1, 2) SELECT x FROM c", "WITH c (x, y) AS (SELECT 1, 2) SELECT x FROM c", true},
	{"clickhouse/array join", keywords.DialectClickHouse, "SELECT a, x FROM t ARRAY JOIN arr AS x", "SELECT a, x FROM t ARRAY JOIN arr AS x", true},
	{"clickhouse/left array join", keywords.DialectClickHouse, "SELECT a FROM t LEFT ARRAY JOIN arr AS x, arr2 AS y", "SELECT a FROM t LEFT ARRAY JOIN arr AS x, arr2 AS y", true},
	{"clickhouse/final sample prewhere", keywords.DialectClickHouse, "SELECT a FROM t FINAL SAMPLE 1/10 OFFSET 2/10 PREWHERE b = 1 WHERE c = 2", "SELECT a FROM t FINAL SAMPLE 1/10 OFFSET 2/10 PREWHERE b = 1 WHERE c = 2", true},
	{"clickhouse/with fill", keywords.DialectClickHouse, "SELECT d FROM t ORDER BY d WITH FILL FROM 1 TO 10 STEP 1", "SELECT d FROM t ORDER BY d WITH FILL FROM 1 TO 10 STEP 1", true},
	{"clickhouse/parametric aggregate", keywords.DialectClickHouse, "SELECT quantile(0.5)(x) FROM t", "SELECT quantile(0.5)(x) FROM t", true},
	{"clickhouse/scalar cte", keywords.DialectClickHouse, "WITH 10 AS n SELECT n FROM t", "WITH 10 AS n SELECT n FROM t", true},
	{"mariadb/connect by", keywords.DialectMariaDB, "SELECT id FROM t START WITH parent_id IS NULL CONNECT BY NOCYCLE PRIOR id = parent_id", "SELECT id FROM t START WITH parent_id IS NULL CONNECT BY NOCYCLE PRIOR id = parent_id", true},
	{"mariadb/system time", keywords.DialectMariaDB, "SELECT * FROM t FOR SYSTEM_TIME AS OF '2024-01-01'", "SELECT * FROM t FOR SYSTEM_TIME AS OF '2024-01-01'", true},
	{"mariadb/system time between", keywords.DialectMariaDB, "SELECT * FROM t FOR SYSTEM_TIME BETWEEN '2020-01-01' AND '2024-01-01'", "SELECT * FROM t FOR SYSTEM_TIME BETWEEN '2020-01-01' AND '2024-01-01'", true},
	{"postgresql/within group", keywords.DialectPostgreSQL, "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY x) FROM t", "SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY x) FROM t", true},
	{"postgresql/for update of nowait", keywords.DialectPostgreSQL, "SELECT a FROM t FOR UPDATE OF t NOWAIT", "SELECT a FROM t FOR UPDATE OF t NOWAIT", true},
	{"postgresql/array subquery", keywords.DialectPostgreSQL, "SELECT ARRAY(SELECT a FROM t)", "SELECT ARRAY(SELECT a FROM t)", true},
	{"postgresql/ilike lowercase", keywords.DialectPostgreSQL, "SELECT * FROM t WHERE a ilike 'x%' AND b not ilike 'y%'", "SELECT * FROM t WHERE a ilike 'x%' AND b NOT ILIKE 'y%'", true},
	{"postgresql/on conflict constraint", keywords.DialectPostgreSQL, "INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT pk DO NOTHING", "INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT pk DO NOTHING", true},
	{"postgresql/fetch with ties", keywords.DialectPostgreSQL, "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS WITH TIES", "SELECT a FROM t ORDER BY a FETCH FIRST 5 ROWS WITH TIES", true},
	{"postgresql/merge", keywords.DialectPostgreSQL, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = s.a WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a)", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = s.a WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a)", true},
	{"postgresql/create index", keywords.DialectPostgreSQL, "CREATE UNIQUE INDEX IF NOT EXISTS i ON t USING btree (a DESC, b) WHERE c > 0", "CREATE UNIQUE INDEX IF NOT EXISTS i ON t USING btree (a DESC, b) WHERE c > 0", true},
	{"postgresql/create view", keywords.DialectPostgreSQL, "CREATE OR REPLACE VIEW v (a) AS SELECT a FROM t WHERE b IN (SELECT b FROM u)", "CREATE OR REPLACE VIEW v (a) AS SELECT a FROM t WHERE b IN (SELECT b FROM u)", true},
	{"postgresql/reserved composite fields", keywords.DialectPostgreSQL, "SELECT (a).order, (t).select, (f(x)).Group[1].end FROM t", "SELECT (a).order, (t).select, (f(x)).Group[1].end FROM t", true},
	{"default/reserved composite field", "", "SELECT (a).order FROM t", "SELECT (a).order FROM t", true},
	{"postgresql/table function column aliases", keywords.DialectPostgreSQL, "SELECT * FROM unnest(arr) AS g(a, b)", "SELECT * FROM unnest(arr) g(a, b)", true},
	{"postgresql/with ordinality", keywords.DialectPostgreSQL, "SELECT * FROM unnest(arr) WITH ORDINALITY", "SELECT * FROM unnest(arr) WITH ORDINALITY", true},
	{"postgresql/with ordinality alias list", keywords.DialectPostgreSQL, "SELECT * FROM t CROSS JOIN LATERAL unnest(t.arr) WITH ORDINALITY AS u(v, \"order\")", "SELECT * FROM t CROSS JOIN LATERAL unnest(t.arr) WITH ORDINALITY u(v, \"order\")", true},
	{"snowflake/qualify-free select", keywords.DialectSnowflake, "SELECT a FROM t WHERE b = 'x' ORDER BY a LIMIT 5", "SELECT a FROM t WHERE b = 'x' ORDER BY a LIMIT 5", true},
}

func parseGolden(t *testing.T, d keywords.SQLDialect, sql string) *ast.AST {
	t.Helper()
	var (
		tree *ast.AST
		err  error
	)
	if d == "" {
		tree, err = gosqlx.Parse(sql)
	} else {
		tree, err = gosqlx.ParseWithDialect(sql, d)
	}
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	return tree
}

func TestSQL_GoldenCorpus(t *testing.T) {
	for _, tc := range goldenParseCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := parseGolden(t, tc.dialect, tc.sql).SQL()
			if got != tc.want {
				t.Fatalf("SQL() mismatch\n got: %q\nwant: %q", got, tc.want)
			}
			if !tc.stable {
				return
			}
			again := parseGolden(t, tc.dialect, got).SQL()
			if again != tc.want {
				t.Fatalf("re-parse of SQL() output is not stable\n got: %q\nwant: %q", again, tc.want)
			}
		})
	}
}

// goldenNode is a hand-built AST node whose SQL() output is pinned. These
// cover node shapes and field combinations the default-dialect parser does
// not produce (dialect-only clauses, dml.go types, DDL nested in queries,
// literal Value/Type combinations used by other packages).
type goldenNode struct {
	name string
	node interface{ SQL() string }
}

func goldenNodes() []goldenNode {
	id := func(name string) *ast.Identifier { return &ast.Identifier{Name: name} }
	col := func(table, name string) *ast.Identifier { return &ast.Identifier{Table: table, Name: name} }
	str := func(v string) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "string"} }
	num := func(v string) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "int"} }
	intp := func(v int) *int { return &v }
	i64p := func(v int64) *int64 { return &v }
	boolp := func(v bool) *bool { return &v }
	sel := func(cols ...ast.Expression) *ast.SelectStatement {
		return &ast.SelectStatement{Columns: cols, From: []ast.TableReference{{Name: "t"}}}
	}
	eq := func(l, r ast.Expression) *ast.BinaryExpression {
		return &ast.BinaryExpression{Left: l, Operator: "=", Right: r}
	}

	return []goldenNode{
		{"literal/int typed INTEGER", &ast.LiteralValue{Value: 1000, Type: "INTEGER"}},
		{"literal/float", &ast.LiteralValue{Value: 3.5, Type: "float"}},
		{"literal/bool BOOLEAN", &ast.LiteralValue{Value: true, Type: "BOOLEAN"}},
		{"literal/bool lowercase type", &ast.LiteralValue{Value: "true", Type: "bool"}},
		{"literal/empty type", &ast.LiteralValue{Value: "?", Type: ""}},
		{"literal/string escapes", &ast.LiteralValue{Value: "a'b\\c\nd\re\x1af\x00g", Type: "STRING"}},
		{"literal/string invalid utf8", &ast.LiteralValue{Value: "x\xffy", Type: "string"}},
		{"literal/string non-string value", &ast.LiteralValue{Value: 42, Type: "string"}},
		{"literal/nil value", &ast.LiteralValue{Value: nil, Type: "string"}},
		{"literal/null type", &ast.LiteralValue{Value: "x", Type: "NULL"}},
		{"identifier/unsafe both", &ast.Identifier{Table: "my t", Name: "we\"ird"}},
		{"identifier/empty", &ast.Identifier{}},
		{"identifier/unicode", &ast.Identifier{Name: "naïve_列"}},
		{"ident", &ast.Ident{Name: "x"}},
		{"unary/not", &ast.UnaryExpression{Operator: ast.Not, Expr: id("a")}},
		{"unary/factorial", &ast.UnaryExpression{Operator: ast.PGPostfixFactorial, Expr: num("5")}},
		{"unary/minus", &ast.UnaryExpression{Operator: ast.Minus, Expr: id("a")}},
		{"unary/plus", &ast.UnaryExpression{Operator: ast.Plus, Expr: id("a")}},
		{"unary/prior", &ast.UnaryExpression{Operator: ast.Prior, Expr: id("a")}},
		{"binary/custom op", &ast.BinaryExpression{Left: id("a"), Operator: "=", Right: id("b"), CustomOp: &ast.CustomBinaryOperator{Parts: []string{"pg_catalog", "="}}}},
		{"binary/not eq", &ast.BinaryExpression{Left: id("a"), Operator: "=", Right: id("b"), Not: true}},
		{"binary/not similar lowercase", &ast.BinaryExpression{Left: id("a"), Operator: "similar to", Right: str("x"), Not: true}},
		{"binary/is null lowercase", &ast.BinaryExpression{Left: id("a"), Operator: "is null", Not: true}},
		{"binary/nil sides", &ast.BinaryExpression{Operator: "+"}},
		{"aliased", &ast.AliasedExpression{Expr: &ast.FunctionCall{Name: "COUNT", Arguments: []ast.Expression{id("*")}}, Alias: "n"}},
		{"cast", &ast.CastExpression{Expr: id("a"), Type: "VARCHAR(10)"}},
		{"case value", &ast.CaseExpression{Value: id("a"), WhenClauses: []ast.WhenClause{{Condition: num("1"), Result: str("x")}}, ElseClause: str("y")}},
		{"when", &ast.WhenClause{Condition: eq(id("a"), num("1")), Result: str("x")}},
		{"between not", &ast.BetweenExpression{Expr: id("a"), Lower: num("1"), Upper: num("2"), Not: true}},
		{"in subquery not", &ast.InExpression{Expr: id("a"), Subquery: sel(id("b")), Not: true}},
		{"in empty list", &ast.InExpression{Expr: id("a")}},
		{"exists", &ast.ExistsExpression{Subquery: sel(num("1"))}},
		{"subquery", &ast.SubqueryExpression{Subquery: sel(id("b"))}},
		{"any", &ast.AnyExpression{Expr: id("a"), Operator: "<>", Subquery: sel(id("b"))}},
		{"all", &ast.AllExpression{Expr: id("a"), Operator: ">=", Subquery: sel(id("b"))}},
		{"function/full", &ast.FunctionCall{
			Name:        "agg",
			Parameters:  []ast.Expression{num("1"), num("2")},
			Arguments:   []ast.Expression{id("x"), id("y")},
			Distinct:    true,
			OrderBy:     []ast.OrderByExpression{{Expression: id("x"), Ascending: false, NullsFirst: boolp(true)}},
			WithinGroup: []ast.OrderByExpression{{Expression: id("y"), Ascending: true}},
			Filter:      eq(id("z"), num("1")),
			Over: &ast.WindowSpec{
				Name:        "w",
				PartitionBy: []ast.Expression{id("p")},
				OrderBy:     []ast.OrderByExpression{{Expression: id("o"), Ascending: true, NullsFirst: boolp(false)}},
				FrameClause: &ast.WindowFrame{Type: "ROWS", Start: ast.WindowFrameBound{Type: "1 PRECEDING"}, End: &ast.WindowFrameBound{Type: "CURRENT ROW"}},
			},
			NullTreatment: "IGNORE NULLS",
		}},
		{"function/empty over", &ast.FunctionCall{Name: "f", Over: &ast.WindowSpec{}}},
		{"function/over name", &ast.FunctionCall{Name: "f", Over: &ast.WindowSpec{Name: "w"}}},
		{"function/over base", &ast.FunctionCall{Name: "f", Over: &ast.WindowSpec{BaseWindow: "w", OrderBy: []ast.OrderByExpression{{Expression: id("o"), Ascending: true}}}}},
		// The FunctionCall doc example (ast_expressions.go) plus EXCLUDE (#609).
		{"function/over frame exclude", &ast.FunctionCall{
			Name:      "AVG",
			Arguments: []ast.Expression{id("amount")},
			Over: &ast.WindowSpec{
				OrderBy: []ast.OrderByExpression{{Expression: id("date"), Ascending: true}},
				FrameClause: &ast.WindowFrame{
					Type:    "ROWS",
					Start:   ast.WindowFrameBound{Type: "PRECEDING", Value: num("2")},
					End:     &ast.WindowFrameBound{Type: "CURRENT ROW"},
					Exclude: "NO OTHERS",
				},
			},
		}},
		{"extract", &ast.ExtractExpression{Field: "YEAR", Source: id("d")}},
		{"position", &ast.PositionExpression{Substr: str("a"), Str: id("s")}},
		{"substring for", &ast.SubstringExpression{Str: id("s"), Start: num("1"), Length: num("2")}},
		{"substring", &ast.SubstringExpression{Str: id("s"), Start: num("2")}},
		{"interval", &ast.IntervalExpression{Value: "2 hours"}},
		{"interval/qualifier", &ast.IntervalExpression{Value: "1-2", Qualifier: "YEAR TO MONTH"}},
		{"list", &ast.ListExpression{Values: []ast.Expression{num("1"), nil, num("3")}}},
		{"tuple", &ast.TupleExpression{Expressions: []ast.Expression{id("a"), str("b")}}},
		{"tuple empty", &ast.TupleExpression{}},
		{"array subquery", &ast.ArrayConstructorExpression{Subquery: sel(id("a"))}},
		{"array elements", &ast.ArrayConstructorExpression{Elements: []ast.Expression{num("1"), num("2")}}},
		{"array subscript", &ast.ArraySubscriptExpression{Array: id("m"), Indices: []ast.Expression{num("1"), id("j")}}},
		{"array slice open", &ast.ArraySliceExpression{Array: id("a")}},
		{"rollup", &ast.RollupExpression{Expressions: []ast.Expression{id("a"), id("b")}}},
		{"cube", &ast.CubeExpression{Expressions: []ast.Expression{id("a")}}},
		{"grouping sets", &ast.GroupingSetsExpression{Sets: [][]ast.Expression{{id("a"), id("b")}, {}}}},
		{"select/everything", &ast.SelectStatement{
			With:              &ast.WithClause{Recursive: true, CTEs: []*ast.CommonTableExpr{{Name: "c", Columns: []string{"x"}, Statement: sel(num("1")), Materialized: boolp(false)}, {Name: "k", ScalarExpr: num("10")}}},
			DistinctOnColumns: []ast.Expression{id("a")},
			Columns:           []ast.Expression{id("a"), &ast.AliasedExpression{Expr: id("b"), Alias: "bb"}},
			From: []ast.TableReference{
				{Name: "t", Alias: "x", Final: true, TableHints: []string{"NOLOCK"}},
				{Subquery: sel(id("z")), Alias: "s", Lateral: true},
				{Name: "h", ForSystemTime: &ast.ForSystemTimeClause{Type: ast.SystemTimeAll}},
			},
			Joins: []ast.JoinClause{
				{Type: "LEFT", Right: ast.TableReference{Name: "u", Alias: "y"}, Condition: eq(col("x", "id"), col("y", "id"))},
				{Type: "CROSS", Right: ast.TableReference{Name: "v"}},
			},
			ArrayJoin:      &ast.ArrayJoinClause{Left: true, Elements: []ast.ArrayJoinElement{{Expr: id("arr"), Alias: "e"}, {Expr: id("arr2")}}},
			Sample:         &ast.SampleClause{Value: "1", Denominator: "10", Offset: "2", OffsetDenominator: "10"},
			PrewhereClause: eq(id("p"), num("1")),
			Where:          eq(id("w"), num("2")),
			GroupBy:        []ast.Expression{id("a"), &ast.RollupExpression{Expressions: []ast.Expression{id("b")}}},
			Having:         eq(id("h"), num("3")),
			StartWith:      &ast.BinaryExpression{Left: id("parent"), Operator: "IS NULL"},
			ConnectBy:      &ast.ConnectByClause{NoCycle: true, Condition: eq(&ast.UnaryExpression{Operator: ast.Prior, Expr: id("id")}, id("parent"))},
			Windows: []ast.WindowSpec{
				{Name: "w1", PartitionBy: []ast.Expression{id("a")}, FrameClause: &ast.WindowFrame{Type: "RANGE", Start: ast.WindowFrameBound{Type: "UNBOUNDED PRECEDING"}}},
				{Name: "w2", BaseWindow: "w1", OrderBy: []ast.OrderByExpression{{Expression: id("b"), Ascending: true}}},
			},
			OrderBy: []ast.OrderByExpression{
				{Expression: id("a"), Ascending: false, NullsFirst: boolp(false), WithFill: &ast.WithFillClause{From: num("1"), To: num("10"), Step: num("2")}},
				{Expression: id("b"), Ascending: true, WithFill: &ast.WithFillClause{}},
			},
			Limit:  intp(10),
			Offset: intp(-5),
			Fetch:  &ast.FetchClause{OffsetValue: i64p(3), FetchValue: i64p(7), FetchType: "NEXT", IsPercent: true, WithTies: true},
			For:    &ast.ForClause{LockType: "SHARE", Tables: []string{"t", "u"}, NoWait: true, SkipLocked: true},
		}},
		{"select/distinct no from", &ast.SelectStatement{Distinct: true, Columns: []ast.Expression{num("1")}}},
		{"select/fetch minimal", &ast.SelectStatement{Columns: []ast.Expression{id("a")}, Fetch: &ast.FetchClause{FetchType: "FIRST"}}},
		{"select/empty", &ast.SelectStatement{}},
		{"insert/full", &ast.InsertStatement{
			With:       &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", Statement: sel(num("1")), Materialized: boolp(true)}}},
			TableName:  "t",
			Columns:    []ast.Expression{id("a"), id("b")},
			Values:     [][]ast.Expression{{num("1"), str("x")}, {num("2"), &ast.LiteralValue{Type: "null"}}},
			OnConflict: &ast.OnConflict{Target: []ast.Expression{id("a")}, Constraint: "pk", Action: ast.OnConflictAction{DoUpdate: []ast.UpdateExpression{{Column: id("b"), Value: str("y")}, {Column: id("c"), Value: num("1")}}, Where: eq(id("d"), num("0"))}},
			Returning:  []ast.Expression{id("a"), id("b")},
		}},
		{"insert/query", &ast.InsertStatement{TableName: "t", Query: &ast.SetOperation{Left: sel(id("a")), Operator: "UNION", Right: sel(id("b")), All: true}}},
		{"insert/empty", &ast.InsertStatement{}},
		{"update/full", &ast.UpdateStatement{
			With:        &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", Statement: sel(num("1"))}}},
			TableName:   "t",
			Alias:       "x",
			Assignments: []ast.UpdateExpression{{Column: id("a"), Value: num("1")}, {Column: col("x", "b"), Value: str("q")}},
			From:        []ast.TableReference{{Name: "u"}, {Name: "v", Alias: "vv"}},
			Where:       eq(col("x", "id"), col("u", "id")),
			Returning:   []ast.Expression{id("a")},
		}},
		{"update/no assignments", &ast.UpdateStatement{TableName: "t"}},
		{"delete/full", &ast.DeleteStatement{
			With:      &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "c", Statement: sel(num("1"))}}},
			TableName: "t",
			Alias:     "x",
			Using:     []ast.TableReference{{Name: "u"}, {Name: "v"}},
			Where:     eq(col("x", "id"), col("u", "id")),
			Returning: []ast.Expression{id("a"), id("b")},
		}},
		{"with/standalone", &ast.WithClause{CTEs: []*ast.CommonTableExpr{{Name: "a", Statement: sel(num("1"))}, {Name: "b", Statement: sel(num("2"))}}}},
		{"setop/nested", &ast.SetOperation{Left: &ast.SetOperation{Left: sel(id("a")), Operator: "UNION", Right: sel(id("b"))}, Operator: "EXCEPT", Right: sel(id("c")), All: true}},
		{"values", &ast.Values{Rows: [][]ast.Expression{{num("1"), str("a")}, {num("2"), str("b")}}}},
		{"values empty", &ast.Values{}},
		{"nested/ddl in setop", &ast.SetOperation{Left: &ast.CreateViewStatement{Name: "v", Query: sel(id("a"))}, Operator: "UNION", Right: &ast.Select{Columns: []ast.Expression{id("b")}}}},
		{"nested/merge with subquery source", &ast.MergeStatement{
			TargetTable: ast.TableReference{Name: "t"},
			TargetAlias: "x",
			SourceTable: ast.TableReference{Subquery: sel(id("a")), Alias: "s"},
			OnCondition: eq(col("x", "id"), col("s", "id")),
			WhenClauses: []*ast.MergeWhenClause{
				{Type: "MATCHED", Condition: eq(col("x", "a"), num("0")), Action: &ast.MergeAction{ActionType: "DELETE"}},
				{Type: "NOT_MATCHED_BY_SOURCE", Action: &ast.MergeAction{ActionType: "UPDATE", SetClauses: []ast.SetClause{{Column: "a", Value: num("1")}}}},
				{Type: "NOT_MATCHED", Action: &ast.MergeAction{ActionType: "INSERT", Columns: []string{"id"}, Values: []ast.Expression{col("s", "id")}}},
			},
		}},
		{"dml/select", &ast.Select{Distinct: true, Columns: []ast.Expression{id("a")}, From: []ast.TableReference{{Name: "t"}}, Where: eq(id("a"), num("1")), GroupBy: []ast.Expression{id("a")}, Having: eq(id("b"), num("2")), OrderBy: []ast.OrderByExpression{{Expression: id("a")}}, Limit: i64p(5), Offset: i64p(6)}},
		{"dml/insert", &ast.Insert{Table: ast.TableReference{Name: "t"}, Columns: []ast.Expression{id("a")}, Values: [][]ast.Expression{{num("1")}}, ReturningClause: []ast.Expression{id("a")}}},
		{"dml/update", &ast.Update{Table: ast.TableReference{Name: "t"}, Updates: []ast.UpdateExpression{{Column: id("a"), Value: num("1")}}, Where: eq(id("b"), num("2")), ReturningClause: []ast.Expression{id("a")}}},
		{"dml/delete", &ast.Delete{Table: ast.TableReference{Name: "t"}, Where: eq(id("b"), num("2")), ReturningClause: []ast.Expression{id("a")}}},
		{"ast/mixed statements", ast.AST{Statements: []ast.Statement{sel(id("a")), &ast.DropStatement{ObjectType: "TABLE", Names: []string{"t"}}, &ast.Values{Rows: [][]ast.Expression{{num("1")}}}}}},
		{"ast/empty", ast.AST{}},
	}
}

// goldenNodeWant holds the pinned SQL() output for each goldenNodes entry,
// captured from the pre-#558 serializer.
var goldenNodeWant = map[string]string{
	"literal/int typed INTEGER":         "1000",
	"literal/float":                     "3.5",
	"literal/bool BOOLEAN":              "TRUE",
	"literal/bool lowercase type":       "true",
	"literal/empty type":                "?",
	"literal/string escapes":            "'a''b\\\\c\\nd\\re\\Zf\\0g'",
	"literal/string invalid utf8":       "'x�y'",
	"literal/string non-string value":   "'42'",
	"literal/nil value":                 "NULL",
	"literal/null type":                 "NULL",
	"identifier/unsafe both":            "\"my t\".\"we\"\"ird\"",
	"identifier/empty":                  "\"\"",
	"identifier/unicode":                "naïve_列",
	"ident":                             "x",
	"unary/not":                         "NOT a",
	"unary/factorial":                   "5!",
	"unary/minus":                       "-a",
	"unary/plus":                        "+a",
	"unary/prior":                       "PRIOR a",
	"binary/custom op":                  "a OPERATOR(pg_catalog.=) b",
	"binary/not eq":                     "NOT (a = b)",
	"binary/not similar lowercase":      "a NOT SIMILAR TO 'x'",
	"binary/is null lowercase":          "a IS NOT NULL",
	"binary/nil sides":                  " + ",
	"aliased":                           "COUNT(*) AS n",
	"cast":                              "CAST(a AS VARCHAR(10))",
	"case value":                        "CASE a WHEN 1 THEN 'x' ELSE 'y' END",
	"when":                              "WHEN a = 1 THEN 'x'",
	"between not":                       "a NOT BETWEEN 1 AND 2",
	"in subquery not":                   "a NOT IN (SELECT b FROM t)",
	"in empty list":                     "a IN ()",
	"exists":                            "EXISTS (SELECT 1 FROM t)",
	"subquery":                          "(SELECT b FROM t)",
	"any":                               "a <> ANY (SELECT b FROM t)",
	"all":                               "a >= ALL (SELECT b FROM t)",
	"function/full":                     "agg(1, 2)(DISTINCT x, y ORDER BY x DESC NULLS FIRST) IGNORE NULLS WITHIN GROUP (ORDER BY y) FILTER (WHERE z = 1) OVER (w PARTITION BY p ORDER BY o NULLS LAST ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)",
	"function/empty over":               "f() OVER ()",
	"function/over name":                "f() OVER w",
	"function/over base":                "f() OVER (w ORDER BY o)",
	"function/over frame exclude":       "AVG(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW EXCLUDE NO OTHERS)",
	"extract":                           "EXTRACT(YEAR FROM d)",
	"position":                          "POSITION('a' IN s)",
	"substring for":                     "SUBSTRING(s FROM 1 FOR 2)",
	"substring":                         "SUBSTRING(s FROM 2)",
	"interval":                          "INTERVAL '2 hours'",
	"interval/qualifier":                "INTERVAL '1-2' YEAR TO MONTH",
	"list":                              "1, , 3",
	"tuple":                             "(a, 'b')",
	"tuple empty":                       "()",
	"array subquery":                    "ARRAY(SELECT a FROM t)",
	"array elements":                    "ARRAY[1, 2]",
	"array subscript":                   "m[1][j]",
	"array slice open":                  "a[:]",
	"rollup":                            "ROLLUP(a, b)",
	"cube":                              "CUBE(a)",
	"grouping sets":                     "GROUPING SETS((a, b), ())",
	"select/everything":                 "WITH RECURSIVE c (x) AS NOT MATERIALIZED (SELECT 1 FROM t), 10 AS k SELECT DISTINCT ON (a) a, b AS bb FROM t x FINAL WITH (NOLOCK), LATERAL (SELECT z FROM t) s, h FOR SYSTEM_TIME ALL LEFT JOIN u y ON x.id = y.id CROSS JOIN v SAMPLE 1/10 OFFSET 2/10 LEFT ARRAY JOIN arr AS e, arr2 PREWHERE p = 1 WHERE w = 2 GROUP BY a, ROLLUP(b) HAVING h = 3 START WITH parent IS NULL CONNECT BY NOCYCLE PRIOR id = parent WINDOW w1 AS (PARTITION BY a RANGE UNBOUNDED PRECEDING), w2 AS (w1 ORDER BY b) ORDER BY a DESC NULLS LAST WITH FILL FROM 1 TO 10 STEP 2, b WITH FILL LIMIT 10 OFFSET -5 ROWS OFFSET 3 ROWS FETCH NEXT 7 PERCENT ROWS WITH TIES FOR SHARE OF t, u NOWAIT SKIP LOCKED",
	"select/distinct no from":           "SELECT DISTINCT 1",
	"select/fetch minimal":              "SELECT a FETCH FIRST ROW ONLY",
	"select/empty":                      "SELECT ",
	"insert/full":                       "WITH c AS MATERIALIZED (SELECT 1 FROM t) INSERT INTO t (a, b) VALUES (1, 'x'), (2, NULL) ON CONFLICT (a) ON CONSTRAINT pk DO UPDATE SET b = 'y', c = 1 WHERE d = 0 RETURNING a, b",
	"insert/query":                      "INSERT INTO t SELECT a FROM t UNION ALL SELECT b FROM t",
	"insert/empty":                      "INSERT INTO ",
	"update/full":                       "WITH c AS (SELECT 1 FROM t) UPDATE t x SET a = 1, x.b = 'q' FROM u, v vv WHERE x.id = u.id RETURNING a",
	"update/no assignments":             "UPDATE t SET ",
	"delete/full":                       "WITH c AS (SELECT 1 FROM t) DELETE FROM t x USING u, v WHERE x.id = u.id RETURNING a, b",
	"with/standalone":                   "WITH a AS (SELECT 1 FROM t), b AS (SELECT 2 FROM t)",
	"setop/nested":                      "SELECT a FROM t UNION SELECT b FROM t EXCEPT ALL SELECT c FROM t",
	"values":                            "VALUES (1, 'a'), (2, 'b')",
	"values empty":                      "VALUES ",
	"nested/ddl in setop":               "CREATE VIEW v AS SELECT a FROM t UNION SELECT b",
	"nested/merge with subquery source": "MERGE INTO t x USING (SELECT a FROM t) s ON x.id = s.id WHEN MATCHED AND x.a = 0 THEN DELETE WHEN NOT MATCHED BY SOURCE THEN UPDATE SET a = 1 WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)",
	"dml/select":                        "SELECT DISTINCT a FROM t WHERE a = 1 GROUP BY a HAVING b = 2 ORDER BY a DESC LIMIT 5 OFFSET 6",
	"dml/insert":                        "INSERT INTO t (a) VALUES (1) RETURNING a",
	"dml/update":                        "UPDATE t SET a = 1 WHERE b = 2 RETURNING a",
	"dml/delete":                        "DELETE FROM t WHERE b = 2 RETURNING a",
	"ast/mixed statements":              "SELECT a FROM t;\nDROP TABLE t;\nVALUES (1)",
	"ast/empty":                         "",
}

func TestSQL_GoldenNodes(t *testing.T) {
	nodes := goldenNodes()
	if len(nodes) != len(goldenNodeWant) {
		t.Fatalf("goldenNodes has %d entries, goldenNodeWant has %d", len(nodes), len(goldenNodeWant))
	}
	for _, n := range nodes {
		n := n
		t.Run(n.name, func(t *testing.T) {
			want, ok := goldenNodeWant[n.name]
			if !ok {
				t.Fatalf("no pinned output for %q", n.name)
			}
			if got := n.node.SQL(); got != want {
				t.Fatalf("SQL() mismatch\n got: %q\nwant: %q", got, want)
			}
		})
	}
}
