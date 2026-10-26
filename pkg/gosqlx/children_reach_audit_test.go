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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// collectIdents gathers every *Identifier reachable from v through exported
// fields, with the field path that holds it.
func collectIdents(v reflect.Value, path string, seen map[uintptr]bool, out map[*ast.Identifier]string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		if id, ok := v.Interface().(*ast.Identifier); ok {
			if _, dup := out[id]; !dup {
				out[id] = path
			}
			return
		}
		if seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		collectIdents(v.Elem(), path, seen, out)
	case reflect.Interface:
		if !v.IsNil() {
			collectIdents(v.Elem(), path, seen, out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			collectIdents(v.Field(i), path+"."+t.Field(i).Name, seen, out)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			collectIdents(v.Index(i), path, seen, out)
		}
	}
}

func TestInspectReachesEveryIdentifierCorpus(t *testing.T) {
	dirs, _ := os.ReadDir(realworldRoot)
	gaps := map[string]string{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(realworldRoot, d.Name(), "*.sql"))
		for _, f := range files {
			data, _ := os.ReadFile(f)
			for _, s := range SplitStatements(string(data), d.Name()) {
				tree, err := ParseWithDialect(s, keywords.SQLDialect(d.Name()))
				if err != nil {
					continue
				}
				for _, stmt := range tree.Statements {
					all := map[*ast.Identifier]string{}
					collectIdents(reflect.ValueOf(stmt), fmt.Sprintf("%T", stmt), map[uintptr]bool{}, all)
					vis := map[*ast.Identifier]bool{}
					ast.Inspect(stmt, func(n ast.Node) bool {
						if id, ok := n.(*ast.Identifier); ok {
							vis[id] = true
						}
						return true
					})
					for id, p := range all {
						if !vis[id] {
							gaps[p] = s
						}
					}
				}
			}
		}
	}
	var keys []string
	for k := range gaps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("field not reached by ast.Inspect: %s, e.g. %.120s", k, gaps[k])
	}
}

func TestInspectReachesEveryIdentifierCases(t *testing.T) {
	cases := []struct{ d, q string }{
		{"sqlserver", "SELECT * FROM t PIVOT (SUM(mk1) FOR mk2 IN ([a],[b])) AS p"},
		{"sqlserver", "SELECT * FROM t UNPIVOT (mk1 FOR mk2 IN (mk3, mk4)) AS p"},
		{"snowflake", "SELECT * FROM t PIVOT (SUM(mk1) FOR mk2 IN (SELECT mk3 FROM u)) AS p"},
		{"snowflake", "SELECT * FROM t PIVOT (SUM(mk1) FOR mk2 IN (ANY ORDER BY mk3)) AS p"},
		{"snowflake", "SELECT * FROM t PIVOT (SUM(mk1) FOR mk2 IN ('a') DEFAULT ON NULL (mk3)) AS p"},
		{"postgresql", "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = mk1 WHERE mk2 > 1"},
		{"postgresql", "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) WHERE mk3 > 1 DO NOTHING"},
		{"snowflake", "SELECT * FROM t MATCH_RECOGNIZE (PARTITION BY mk1 ORDER BY mk2 MEASURES mk3 AS m ALL ROWS PER MATCH PATTERN (A B+) DEFINE A AS mk4 > 1, B AS mk5 < 2)"},
		{"clickhouse", "SELECT a FROM t ORDER BY a WITH FILL INTERPOLATE (mk1 AS mk2 + 1)"},
		{"clickhouse", "SELECT a FROM t LIMIT 1 BY mk1 SETTINGS x = mk2"},
		{"clickhouse", "SELECT a FROM t PREWHERE mk1 > 1 FINAL SAMPLE 0.1"},
		{"mysql", "SELECT a INTO OUTFILE 'f' FIELDS TERMINATED BY ',' FROM t WHERE mk1 > 1"},
		{"postgresql", "SELECT a FROM t FOR UPDATE OF mk1 SKIP LOCKED"},
		{"snowflake", "SELECT v:mk1[0].b, v[mk2] FROM t"},
		{"snowflake", "SELECT {'a': mk1, 'b': mk2}"},
		{"sqlserver", "DELETE TOP (mk1) FROM t OUTPUT deleted.mk2 WHERE mk3 > 1"},
		{"sqlserver", "UPDATE TOP (mk1) t SET a = 1 OUTPUT inserted.mk2 WHERE mk3 > 1"},
		{"sqlserver", "INSERT TOP (mk1) INTO t (a) OUTPUT inserted.mk2 VALUES (1)"},
		{"mysql", "DELETE FROM t WHERE mk1 > 1 ORDER BY mk2 LIMIT 3"},
		{"mysql", "UPDATE t SET a = 1 WHERE mk1 > 1 ORDER BY mk2 LIMIT 3"},
		{"mysql", "DELETE t1, t2 FROM t1 JOIN t2 ON t1.mk1 = t2.mk2 WHERE mk3 > 1"},
		{"oracle", "DELETE FROM t WHERE mk1 > 1 RETURNING a INTO mk2"},
		{"oracle", "INSERT INTO t (a) VALUES (1) RETURNING a INTO mk1"},
		{"oracle", "INSERT ALL WHEN mk1 > 1 THEN INTO t (a) VALUES (mk2) ELSE INTO u (b) VALUES (mk3) SELECT * FROM d"},
		{"postgresql", "SELECT mk1 LIKE 'x' ESCAPE mk2 FROM t"},
		{"mariadb", "DELETE HISTORY FROM t BEFORE SYSTEM_TIME mk1"},
		{"mysql", "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = mk1"},
		{"mysql", "INSERT INTO t SET a = mk1"},
		{"clickhouse", "INSERT INTO t SETTINGS x = mk1 VALUES (1)"},
		{"clickhouse", "CREATE TABLE t (a Int, INDEX i mk1 TYPE minmax GRANULARITY 1) ENGINE = MergeTree ORDER BY a"},
		{"clickhouse", "CREATE TABLE t (a Int DEFAULT mk1, b Int MATERIALIZED mk2, c Int ALIAS mk3 TTL mk4) ENGINE = MergeTree ORDER BY a"},
		{"clickhouse", "CREATE TABLE t (a Int) ENGINE = MergeTree ORDER BY a COMMENT 'x'"},
		{"postgresql", "CREATE TABLE t (a int, b int GENERATED ALWAYS AS (mk1 + 1) STORED, c int GENERATED ALWAYS AS IDENTITY, CHECK (mk2 > 1), EXCLUDE USING gist (mk3 WITH &&))"},
		{"postgresql", "CREATE TABLE t (a int) PARTITION BY RANGE (mk1)"},
		{"mysql", "CREATE TABLE t (a int) PARTITION BY RANGE (mk1) (PARTITION p0 VALUES LESS THAN (mk2))"},
		{"postgresql", "CREATE INDEX i ON t (mk1, (mk2 + 1)) INCLUDE (c) WHERE mk3 > 1"},
		{"postgresql", "CREATE VIEW v AS SELECT mk1 FROM t"},
		{"postgresql", "CREATE TABLE t AS SELECT mk1 FROM u"},
		{"postgresql", "ALTER TABLE t ADD COLUMN a int DEFAULT mk1"},
		{"postgresql", "ALTER TABLE t ADD CONSTRAINT c CHECK (mk1 > 1)"},
		{"postgresql", "ALTER TABLE t ALTER COLUMN a SET DEFAULT mk1"},
		{"postgresql", "ALTER TABLE t ALTER COLUMN a TYPE int USING mk1::int"},
		{"mysql", "ALTER TABLE t PARTITION BY RANGE (mk1) (PARTITION p VALUES LESS THAN (mk2))"},
		{"mysql", "ALTER TABLE t ADD PARTITION (PARTITION p VALUES LESS THAN (mk1))"},
		{"postgresql", "ALTER TABLE t ATTACH PARTITION p FOR VALUES FROM (mk1) TO (mk2)"},
		{"postgresql", "SELECT mk1 FROM t TABLESAMPLE BERNOULLI (mk2)"},
		{"postgresql", "SELECT * FROM generate_series(1, mk1) WITH ORDINALITY AS g(a, b)"},
		{"postgresql", "SELECT * FROM t, LATERAL (SELECT mk1) s"},
		{"postgresql", "SELECT * FROM ROWS FROM (f(mk1), g(mk2)) AS r"},
		{"postgresql", "SELECT * FROM t WHERE a = ANY(ARRAY[mk1, mk2])"},
		{"postgresql", "SELECT ARRAY[mk1][mk2], mk3[1:mk4] FROM t"},
		{"postgresql", "SELECT mk1 AT TIME ZONE mk2, EXTRACT(year FROM mk3), CAST(mk4 AS int), POSITION(mk5 IN mk6), SUBSTRING(mk7 FROM mk8 FOR mk9), TRIM(BOTH mk10 FROM mk11), OVERLAY(mk12 PLACING mk13 FROM mk14)"},
		{"postgresql", "SELECT COUNT(*) FILTER (WHERE mk1 > 1) OVER (PARTITION BY mk2 ORDER BY mk3 ROWS BETWEEN mk4 PRECEDING AND mk5 FOLLOWING), string_agg(mk6, ',' ORDER BY mk7) FROM t"},
		{"postgresql", "SELECT mk1 FROM t GROUP BY GROUPING SETS ((mk2), ROLLUP(mk3), CUBE(mk4))"},
		{"postgresql", "SELECT * FROM t JOIN u USING (mk1) JOIN v ON mk2 = 1"},
		{"postgresql", "SELECT * FROM t FETCH FIRST mk1 ROWS WITH TIES"},
		{"postgresql", "SELECT mk1 FROM t WINDOW w AS (PARTITION BY mk2)"},
		{"postgresql", "WITH RECURSIVE c AS (SELECT mk1) CYCLE mk2 SET mk3 USING mk4 SELECT * FROM c"},
		{"postgresql", "SELECT CASE mk1 WHEN mk2 THEN mk3 ELSE mk4 END"},
		{"postgresql", "SELECT mk1 IS DISTINCT FROM mk2, mk3 BETWEEN mk4 AND mk5, mk6 IN (mk7, mk8), EXISTS (SELECT mk9)"},
		{"postgresql", "CREATE SEQUENCE s START WITH 1"},
		{"postgresql", "COMMENT ON TABLE t IS 'x'"},
		{"postgresql", "COPY t (a) FROM STDIN"},
		{"postgresql", "CREATE FUNCTION f(a int) RETURNS int AS $$ SELECT mk1 $$ LANGUAGE sql"},
		{"postgresql", "CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW WHEN (mk1 > 1) EXECUTE FUNCTION f()"},
		{"postgresql", "EXPLAIN SELECT mk1 FROM t"},
		{"postgresql", "PREPARE p AS SELECT mk1 FROM t"},
		{"mysql", "SELECT * FROM t PARTITION (p0) WHERE mk1 > 1"},
		{"mysql", "REPLACE INTO t (a) VALUES (mk1)"},
		{"mysql", "SELECT a FROM t FORCE INDEX (i) WHERE mk1 > 1"},
		{"sqlserver", "SELECT * FROM t WITH (NOLOCK) CROSS APPLY f(mk1) AS x"},
		{"sqlserver", "SELECT mk1 FROM t FOR XML PATH('x')"},
		{"sqlserver", "SELECT mk1 FROM t OPTION (MAXDOP mk2)"},
		{"sqlserver", "DECLARE @x int = mk1"},
		{"sqlserver", "IF mk1 > 1 SELECT 1"},
		{"sqlserver", "SELECT mk1 FROM t FOR SYSTEM_TIME AS OF mk2"},
		{"oracle", "SELECT mk1 FROM t START WITH mk2 = 1 CONNECT BY PRIOR mk3 = mk4"},
		{"oracle", "SELECT mk1 FROM t OFFSET mk2 ROWS FETCH NEXT mk3 ROWS ONLY"},
		{"snowflake", "SELECT mk1 FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY mk2) = 1"},
		{"snowflake", "SELECT * FROM t, LATERAL FLATTEN(input => mk1) f"},
		{"snowflake", "CREATE TABLE t CLONE s BEFORE (STATEMENT => mk1)"},
		{"bigquery", "SELECT mk1 FROM t, UNNEST(mk2) AS x"},
		{"clickhouse", "SELECT mk1 FROM t LEFT ARRAY JOIN mk2 AS x, mk3 AS y"},
		{"clickhouse", "CREATE MATERIALIZED VIEW v TO d (a Int) AS SELECT mk1 FROM t"},
		{"clickhouse", "CREATE MATERIALIZED VIEW v ENGINE = MergeTree() ORDER BY mk1 TTL mk2 SETTINGS a = mk3 POPULATE AS SELECT 1"},
		{"clickhouse", "CREATE MATERIALIZED VIEW v ENGINE = ReplicatedMergeTree(mk1, mk2) ORDER BY a AS SELECT 1"},
		{"clickhouse", "CREATE VIEW v AS SELECT mk1"},
		{"oracle", "CREATE MATERIALIZED VIEW v REFRESH FAST AS SELECT mk1 FROM t"},
		{"postgresql", "CREATE TABLE t (a int) WITH (fillfactor = 70)"},
		{"mysql", "CREATE TABLE t (a int) ENGINE=InnoDB"},
		{"mysql", "CREATE TABLE t (a int, KEY k (mk1))"},
		{"postgresql", "CREATE TABLE t (LIKE u INCLUDING ALL)"},
		{"postgresql", "CREATE UNIQUE INDEX CONCURRENTLY i ON t USING btree (mk1 DESC NULLS LAST) WITH (fillfactor = 70)"},
	}
	for _, c := range cases {
		tree, err := ParseWithDialect(c.q, keywords.SQLDialect(c.d))
		if err != nil {
			t.Logf("skipped (unsupported syntax) %s: %.100s: %v", c.d, c.q, err)
			continue
		}
		for _, stmt := range tree.Statements {
			all := map[*ast.Identifier]string{}
			collectIdents(reflect.ValueOf(stmt), fmt.Sprintf("%T", stmt), map[uintptr]bool{}, all)
			vis := map[*ast.Identifier]bool{}
			ast.Inspect(stmt, func(n ast.Node) bool {
				if id, ok := n.(*ast.Identifier); ok {
					vis[id] = true
				}
				return true
			})
			for id, p := range all {
				if !vis[id] {
					t.Errorf("not reached by ast.Inspect: %s %s (%s) in %.100s", c.d, p, id.Name, c.q)
				}
			}
		}
	}
}
