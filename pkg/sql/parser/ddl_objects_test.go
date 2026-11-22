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

package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseOne parses sql in dialect d and returns its single statement.
func parseOne(t *testing.T, d keywords.SQLDialect, sql string) ast.Statement {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, d, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q: %d statements, want 1", sql, len(tree.Statements))
	}
	return tree.Statements[0]
}

// sqlOf returns the SQL() rendering of a statement.
func sqlOf(t *testing.T, s ast.Statement) string {
	t.Helper()
	r, ok := s.(interface{ SQL() string })
	if !ok {
		t.Fatalf("%T has no SQL method", s)
	}
	return r.SQL()
}

// TestDDLObjects_RoundTrip checks that each DDL form parses, renders back
// through SQL() with every word kept, and re-parses to the same rendering.
func TestDDLObjects_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string // SQL() output; empty means the input itself
	}{
		// CREATE TABLE AS query (data loss before: the query was dropped)
		{"ctas", keywords.DialectPostgreSQL, "CREATE TABLE t AS SELECT * FROM u", ""},
		{"ctas with cte", keywords.DialectSnowflake, "CREATE OR REPLACE TABLE t AS WITH x AS (SELECT 1 AS a) SELECT a FROM x", ""},
		{"ctas with data", keywords.DialectPostgreSQL, "CREATE TABLE t WITH (fillfactor=70) AS SELECT 1 AS a WITH NO DATA",
			"CREATE TABLE t WITH (fillfactor = 70) AS SELECT 1 AS a WITH NO DATA"},
		{"ctas union", keywords.DialectMySQL, "CREATE TABLE t AS SELECT a FROM x UNION SELECT a FROM y", ""},
		{"clickhouse engine ctas", keywords.DialectClickHouse, "CREATE TABLE t ENGINE = MergeTree ORDER BY id AS SELECT id FROM u",
			"CREATE TABLE t ENGINE=MergeTree ORDER BY id AS SELECT id FROM u"},
		{"clickhouse as table", keywords.DialectClickHouse, "CREATE TABLE c AS events", ""},
		{"clickhouse as table engine", keywords.DialectClickHouse, "CREATE TABLE d AS l ENGINE = Distributed('c', 'db', 'l', rand())",
			"CREATE TABLE d AS l ENGINE=Distributed('c', 'db', 'l', rand())"},
		// Sources
		{"like", keywords.DialectMySQL, "CREATE TABLE IF NOT EXISTS t LIKE u", ""},
		{"clone", keywords.DialectSnowflake, "CREATE TABLE t2 CLONE t1", ""},
		{"clone before", keywords.DialectSnowflake, "CREATE TABLE b CLONE s BEFORE (STATEMENT => 'x')", ""},
		{"partition of range", keywords.DialectPostgreSQL, "CREATE TABLE m1 PARTITION OF m FOR VALUES FROM ('2024-01-01') TO (MAXVALUE)", ""},
		{"partition of list", keywords.DialectPostgreSQL, "CREATE TABLE r1 PARTITION OF r FOR VALUES IN ('DE', 'FR')", ""},
		{"partition of hash", keywords.DialectPostgreSQL, "CREATE TABLE h0 PARTITION OF h FOR VALUES WITH (MODULUS 4, REMAINDER 0)", ""},
		{"partition of default", keywords.DialectPostgreSQL, "CREATE TABLE d PARTITION OF m DEFAULT", ""},
		// Kinds and OR REPLACE
		{"or replace", keywords.DialectMariaDB, "CREATE OR REPLACE TABLE s (a INT)", ""},
		{"temp", keywords.DialectSQLite, "CREATE TEMP TABLE s (a INT)", ""},
		{"temporary", keywords.DialectPostgreSQL, "CREATE TEMPORARY TABLE s (a INT)", ""},
		{"global temporary", keywords.DialectOracle, "CREATE GLOBAL TEMPORARY TABLE s (a NUMBER) ON COMMIT DELETE ROWS", ""},
		{"unlogged", keywords.DialectPostgreSQL, "CREATE UNLOGGED TABLE s (a INT)", ""},
		{"transient", keywords.DialectSnowflake, "CREATE OR REPLACE TRANSIENT TABLE s AS SELECT 1 AS a", ""},
		{"on cluster", keywords.DialectClickHouse, "CREATE TABLE t ON CLUSTER c (id UInt64) ENGINE = MergeTree ORDER BY id",
			"CREATE TABLE t ON CLUSTER c (id UInt64) ENGINE=MergeTree ORDER BY id"},
		// Table options
		{"mysql options", keywords.DialectMySQL, "CREATE TABLE t (id INT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=100 COMMENT='a table' ROW_FORMAT=DYNAMIC KEY_BLOCK_SIZE=8", ""},
		{"mysql spaced options", keywords.DialectMySQL, "CREATE TABLE t (id INT) DEFAULT CHARACTER SET utf8mb4 COLLATE 'utf8mb4_bin'", ""},
		{"sqlite options", keywords.DialectSQLite, "CREATE TABLE t (k TEXT PRIMARY KEY, v ANY) STRICT, WITHOUT ROWID", ""},
		{"sqlite without rowid", keywords.DialectSQLite, "CREATE TABLE t (k TEXT PRIMARY KEY) WITHOUT ROWID", ""},
		{"postgres options", keywords.DialectPostgreSQL, "CREATE TEMP TABLE t (a INT) INHERITS (p) WITH (fillfactor = 70) ON COMMIT DROP TABLESPACE ts", ""},
		{"oracle options", keywords.DialectOracle, "CREATE TABLE t (a NUMBER) TABLESPACE users PCTFREE 10 NOLOGGING", ""},
		{"snowflake options", keywords.DialectSnowflake, "CREATE OR REPLACE TABLE t (a INT) CLUSTER BY (a, b) COMMENT = 'x' DATA_RETENTION_TIME_IN_DAYS = 1",
			"CREATE OR REPLACE TABLE t (a INT) CLUSTER BY (a, b) COMMENT='x' DATA_RETENTION_TIME_IN_DAYS=1"},
		{"mariadb system versioning", keywords.DialectMariaDB, "CREATE TABLE t (a INT, s TIMESTAMP(6), e TIMESTAMP(6), PERIOD FOR SYSTEM_TIME (s, e)) WITH SYSTEM VERSIONING", ""},
		// ClickHouse engine clauses
		{"clickhouse clauses", keywords.DialectClickHouse,
			"CREATE TABLE e (a UInt8, ts DateTime) ENGINE = MergeTree PARTITION BY toYYYYMM(ts) PRIMARY KEY a ORDER BY (a, ts) SAMPLE BY a SETTINGS index_granularity = 8192 COMMENT 'events'",
			"CREATE TABLE e (a UInt8, ts DateTime) ENGINE=MergeTree PARTITION BY toYYYYMM(ts) PRIMARY KEY a ORDER BY (a, ts) SAMPLE BY a SETTINGS index_granularity = 8192 COMMENT 'events'"},
		{"clickhouse ttl", keywords.DialectClickHouse,
			"CREATE TABLE m (ts DateTime) ENGINE = MergeTree ORDER BY ts TTL ts + INTERVAL 1 MONTH TO VOLUME 'cold', ts + INTERVAL 1 YEAR DELETE WHERE ts > 0",
			"CREATE TABLE m (ts DateTime) ENGINE=MergeTree ORDER BY ts TTL ts + INTERVAL 1 MONTH TO VOLUME 'cold', ts + INTERVAL 1 YEAR DELETE WHERE ts > 0"},
		{"clickhouse ttl group by", keywords.DialectClickHouse,
			"CREATE TABLE g (d Date, k UInt32, x UInt32) ENGINE = MergeTree ORDER BY k TTL d + INTERVAL 1 MONTH GROUP BY k SET x = max(x)",
			"CREATE TABLE g (d Date, k UInt32, x UInt32) ENGINE=MergeTree ORDER BY k TTL d + INTERVAL 1 MONTH GROUP BY k SET x = max(x)"},
		{"clickhouse keyword column", keywords.DialectClickHouse, "CREATE TABLE h (hash UInt64) ENGINE = MergeTree() ORDER BY hash",
			`CREATE TABLE h ("hash" UInt64) ENGINE=MergeTree() ORDER BY hash`},
		// Partitioning
		{"range partitions", keywords.DialectOracle,
			"CREATE TABLE t (a NUMBER) PARTITION BY RANGE (a) (PARTITION p1 VALUES LESS THAN (10), PARTITION pm VALUES LESS THAN (MAXVALUE))", ""},
		{"list partitions", keywords.DialectOracle,
			"CREATE TABLE t (r VARCHAR2(10)) PARTITION BY LIST (r) (PARTITION p1 VALUES ('a', 'b'), PARTITION p2 VALUES (DEFAULT))", ""},
		{"hash partitions", keywords.DialectMySQL, "CREATE TABLE t (id INT) PARTITION BY HASH(id) PARTITIONS 4",
			"CREATE TABLE t (id INT) PARTITION BY HASH (id) PARTITIONS 4"},
		{"linear key", keywords.DialectMySQL, "CREATE TABLE t (id INT) PARTITION BY LINEAR KEY (id) PARTITIONS 2", ""},
		{"interval partitions", keywords.DialectOracle,
			"CREATE TABLE t (d DATE) PARTITION BY RANGE (d) INTERVAL (NUMTOYMINTERVAL(1, 'MONTH')) (PARTITION p0 VALUES LESS THAN (TO_DATE('2020-01-01', 'YYYY-MM-DD')))", ""},
		{"expression partitions after options", keywords.DialectMySQL,
			"CREATE TABLE t (d DATE) ENGINE=InnoDB PARTITION BY RANGE (YEAR(d)) (PARTITION p0 VALUES LESS THAN (2025), PARTITION pm VALUES LESS THAN MAXVALUE)",
			"CREATE TABLE t (d DATE) ENGINE=InnoDB PARTITION BY RANGE (YEAR(d)) (PARTITION p0 VALUES LESS THAN (2025), PARTITION pm VALUES LESS THAN (MAXVALUE))"},
		{"system_time partitions", keywords.DialectMariaDB,
			"CREATE TABLE h (id INT) WITH SYSTEM VERSIONING PARTITION BY SYSTEM_TIME INTERVAL 1 MONTH (PARTITION p0 HISTORY, PARTITION pc CURRENT)", ""},
		// CREATE INDEX
		{"index expression", keywords.DialectPostgreSQL, "CREATE UNIQUE INDEX i ON t (lower(email))", ""},
		{"index paren expression", keywords.DialectPostgreSQL, "CREATE INDEX i ON t ((a + b))", ""},
		{"index full", keywords.DialectPostgreSQL,
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON ONLY t USING btree (a, b DESC NULLS FIRST) INCLUDE (c) WITH (fillfactor = 70) WHERE a > 0", ""},
		{"index opclass", keywords.DialectPostgreSQL, "CREATE INDEX i ON t USING gin (attrs jsonb_path_ops)", ""},
		{"index hash method", keywords.DialectPostgreSQL, "CREATE INDEX i ON t USING hash (token)", ""},
		{"index without name", keywords.DialectPostgreSQL, "CREATE INDEX ON t (a)", ""},
		{"index prefix", keywords.DialectMySQL, "CREATE INDEX i ON users (email(10))", ""},
		{"index collate", keywords.DialectSQLite, "CREATE INDEX i ON t (name COLLATE NOCASE)", ""},
		{"index oracle", keywords.DialectOracle, "CREATE BITMAP INDEX i ON o (d) TABLESPACE ts LOCAL ONLINE", ""},
		{"index sqlserver", keywords.DialectSQLServer,
			"CREATE UNIQUE NONCLUSTERED INDEX ix ON t (a ASC) INCLUDE (b) WHERE a > 1 WITH (FILLFACTOR = 90, ONLINE = ON)", ""},
		{"index fulltext", keywords.DialectMySQL, "CREATE FULLTEXT INDEX ft ON docs (title, body)", ""},
		// Views
		{"view or alter", keywords.DialectSQLServer, "CREATE OR ALTER VIEW v AS SELECT 1 AS a", ""},
		{"view secure", keywords.DialectSnowflake, "CREATE OR REPLACE SECURE VIEW v AS SELECT 1 AS a", ""},
		{"view force", keywords.DialectOracle, "CREATE OR REPLACE FORCE VIEW v AS SELECT a FROM t", ""},
		{"view read only", keywords.DialectOracle, "CREATE VIEW v AS SELECT a FROM t WITH READ ONLY", ""},
		{"view temp", keywords.DialectSQLite, "CREATE TEMP VIEW v AS SELECT 1 AS one", ""},
		{"view with query", keywords.DialectPostgreSQL, "CREATE VIEW v AS WITH c AS (SELECT 1 AS a) SELECT a FROM c", ""},
		{"mv with data", keywords.DialectPostgreSQL, "CREATE MATERIALIZED VIEW mv AS SELECT 1 AS a WITH DATA", ""},
		{"mv to", keywords.DialectClickHouse, "CREATE MATERIALIZED VIEW mv ON CLUSTER c TO d (day Date, n UInt64) AS SELECT day, count() AS n FROM s GROUP BY day", ""},
		{"mv engine", keywords.DialectClickHouse, "CREATE MATERIALIZED VIEW mv ENGINE = SummingMergeTree ORDER BY (d, k) POPULATE AS SELECT d, k FROM e",
			"CREATE MATERIALIZED VIEW mv ENGINE=SummingMergeTree ORDER BY (d, k) POPULATE AS SELECT d, k FROM e"},
		{"mv oracle refresh", keywords.DialectOracle, "CREATE MATERIALIZED VIEW mv BUILD IMMEDIATE REFRESH FAST ON COMMIT AS SELECT a FROM t", ""},
		// DROP / TRUNCATE
		{"drop index on", keywords.DialectMySQL, "DROP INDEX ix ON t", ""},
		{"drop index concurrently", keywords.DialectPostgreSQL, "DROP INDEX CONCURRENTLY IF EXISTS i", ""},
		{"drop cascade constraints", keywords.DialectOracle, "DROP TABLE t CASCADE CONSTRAINTS PURGE", ""},
		{"drop temporary", keywords.DialectMySQL, "DROP TEMPORARY TABLE IF EXISTS t", ""},
		{"drop clickhouse", keywords.DialectClickHouse, "DROP TABLE t ON CLUSTER c SYNC", ""},
		{"truncate drop storage", keywords.DialectOracle, "TRUNCATE TABLE t DROP STORAGE", ""},
		{"truncate reuse storage", keywords.DialectOracle, "TRUNCATE TABLE t REUSE STORAGE", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = tt.sql
			}
			got := sqlOf(t, parseOne(t, tt.dialect, tt.sql))
			if got != want {
				t.Fatalf("SQL()\n got: %s\nwant: %s", got, want)
			}
			if again := sqlOf(t, parseOne(t, tt.dialect, got)); again != got {
				t.Fatalf("not idempotent\nfirst:  %s\nsecond: %s", got, again)
			}
			formatted := gosqlx.FormatAST(&ast.AST{Statements: []ast.Statement{parseOne(t, tt.dialect, tt.sql)}})
			if _, err := gosqlx.ParseWithDialect(formatted, tt.dialect); err != nil {
				t.Fatalf("formatted output does not re-parse: %v\n%s", err, formatted)
			}
		})
	}
}

// TestDDLObjects_CTASKeepsQuery guards the CREATE TABLE ... AS query data
// loss: the query must be on the AST.
func TestDDLObjects_CTASKeepsQuery(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "CREATE TABLE t AS SELECT a FROM u"},
		{keywords.DialectMySQL, "CREATE TABLE IF NOT EXISTS t AS SELECT a FROM u WHERE a IS NOT NULL"},
		{keywords.DialectOracle, "CREATE TABLE t AS SELECT * FROM employees WHERE 1 = 0"},
		{keywords.DialectSnowflake, "CREATE TABLE t AS WITH x AS (SELECT 1 AS a) SELECT a FROM x"},
		{keywords.DialectSQLite, "CREATE TABLE t AS SELECT * FROM a"},
		{keywords.DialectSQLServer, "CREATE TABLE t AS SELECT * FROM a"},
		{keywords.DialectMariaDB, "CREATE TABLE t AS SELECT * FROM a"},
		{keywords.DialectClickHouse, "CREATE TABLE t ENGINE = Memory AS SELECT 1 AS a"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect), func(t *testing.T) {
			ct, ok := parseOne(t, tt.dialect, tt.sql).(*ast.CreateTableStatement)
			if !ok {
				t.Fatalf("want *ast.CreateTableStatement")
			}
			if ct.AsQuery == nil {
				t.Fatalf("AsQuery is nil for %q", tt.sql)
			}
			if ct.HasColumnList() {
				t.Fatalf("HasColumnList() = true for a CTAS without columns")
			}
			if !strings.Contains(sqlOf(t, ct), " AS ") {
				t.Fatalf("SQL() lost the query: %s", sqlOf(t, ct))
			}
		})
	}
}

// TestDDLObjects_ASTFields checks the fields the parser records for the new
// CREATE TABLE, CREATE INDEX and view forms.
func TestDDLObjects_ASTFields(t *testing.T) {
	t.Run("clickhouse engine clauses", func(t *testing.T) {
		ct, ok := parseOne(t, keywords.DialectClickHouse,
			"CREATE TABLE e (a UInt8) ENGINE = MergeTree PARTITION BY a ORDER BY a SETTINGS index_granularity = 1").(*ast.CreateTableStatement)
		if !ok {
			t.Fatal("want *ast.CreateTableStatement")
		}
		if ct.Engine == nil || ct.Engine.OrderBy == nil || ct.Engine.PartitionBy == nil || len(ct.Engine.Settings) != 1 {
			t.Fatalf("engine clauses not recorded: %+v", ct.Engine)
		}
		if len(ct.Options) != 1 || ct.Options[0].Name != "ENGINE" || ct.Options[0].Value != "MergeTree" {
			t.Fatalf("Options = %+v", ct.Options)
		}
	})
	t.Run("sqlite without rowid", func(t *testing.T) {
		ct, ok := parseOne(t, keywords.DialectSQLite, "CREATE TABLE t (a INTEGER PRIMARY KEY) WITHOUT ROWID").(*ast.CreateTableStatement)
		if !ok {
			t.Fatal("want *ast.CreateTableStatement")
		}
		if !ct.WithoutRowID {
			t.Fatal("WithoutRowID not set")
		}
	})
	t.Run("kind and or replace", func(t *testing.T) {
		ct, ok := parseOne(t, keywords.DialectSnowflake, "CREATE OR REPLACE TRANSIENT TABLE t (a INT)").(*ast.CreateTableStatement)
		if !ok {
			t.Fatal("want *ast.CreateTableStatement")
		}
		if !ct.OrReplace || ct.Kind != "TRANSIENT" {
			t.Fatalf("OrReplace = %v, Kind = %q", ct.OrReplace, ct.Kind)
		}
	})
	t.Run("partition by expressions", func(t *testing.T) {
		ct, ok := parseOne(t, keywords.DialectMySQL, "CREATE TABLE t (d DATE) PARTITION BY RANGE (YEAR(d)) (PARTITION p VALUES LESS THAN (2025))").(*ast.CreateTableStatement)
		if !ok {
			t.Fatal("want *ast.CreateTableStatement")
		}
		if ct.PartitionBy == nil || len(ct.PartitionBy.Expressions) != 1 || len(ct.PartitionBy.Columns) != 0 {
			t.Fatalf("PartitionBy = %+v", ct.PartitionBy)
		}
		if len(ct.Partitions) != 1 || ct.Partitions[0].Type != "LESS THAN" {
			t.Fatalf("Partitions = %+v", ct.Partitions)
		}
	})
	t.Run("index element expression", func(t *testing.T) {
		ci, ok := parseOne(t, keywords.DialectPostgreSQL, "CREATE INDEX i ON t (lower(email) DESC, a)").(*ast.CreateIndexStatement)
		if !ok {
			t.Fatal("want *ast.CreateIndexStatement")
		}
		if len(ci.Columns) != 2 || ci.Columns[0].Expr == nil || ci.Columns[0].Direction != "DESC" || ci.Columns[1].Column != "a" {
			t.Fatalf("Columns = %+v", ci.Columns)
		}
	})
	t.Run("materialized view to", func(t *testing.T) {
		mv, ok := parseOne(t, keywords.DialectClickHouse, "CREATE MATERIALIZED VIEW mv TO d AS SELECT 1 AS a").(*ast.CreateMaterializedViewStatement)
		if !ok {
			t.Fatal("want *ast.CreateMaterializedViewStatement")
		}
		if mv.To != "d" || mv.Tablespace != "" {
			t.Fatalf("To = %q, Tablespace = %q", mv.To, mv.Tablespace)
		}
	})
	t.Run("drop index on table", func(t *testing.T) {
		d, ok := parseOne(t, keywords.DialectMySQL, "DROP INDEX ix ON t").(*ast.DropStatement)
		if !ok {
			t.Fatal("want *ast.DropStatement")
		}
		if d.ObjectType != "INDEX" || d.OnTable != "t" {
			t.Fatalf("ObjectType = %q, OnTable = %q", d.ObjectType, d.OnTable)
		}
	})
}

// TestDDLObjects_VerbatimObjects checks that CREATE / DROP of objects
// without a dedicated node are kept verbatim instead of failing or being
// rendered as an UNSUPPORTED comment.
func TestDDLObjects_VerbatimObjects(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		kind    string
	}{
		{keywords.DialectPostgreSQL, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`, "CREATE EXTENSION"},
		{keywords.DialectPostgreSQL, "CREATE TYPE mood AS ENUM ('sad', 'ok')", "CREATE TYPE"},
		{keywords.DialectPostgreSQL, "CREATE OR REPLACE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql", "CREATE FUNCTION"},
		{keywords.DialectPostgreSQL, "CREATE TRIGGER trg BEFORE UPDATE ON t FOR EACH ROW EXECUTE FUNCTION f()", "CREATE TRIGGER"},
		{keywords.DialectMySQL, "CREATE DATABASE IF NOT EXISTS app CHARACTER SET utf8mb4", "CREATE DATABASE"},
		{keywords.DialectMySQL, "CREATE DEFINER = 'root'@'localhost' PROCEDURE p() DELETE FROM s", "CREATE PROCEDURE"},
		{keywords.DialectMySQL, "CREATE ALGORITHM=MERGE SQL SECURITY INVOKER VIEW v AS SELECT 1", "CREATE VIEW"},
		{keywords.DialectClickHouse, "CREATE FUNCTION f AS x -> x + 1", "CREATE FUNCTION"},
		{keywords.DialectSnowflake, "CREATE SCHEMA s", "CREATE SCHEMA"},
		{keywords.DialectSnowflake, "CREATE OR REPLACE MASKING POLICY m AS (v STRING) RETURNS STRING -> v", "CREATE MASKING POLICY"},
		{keywords.DialectSnowflake, "CREATE FILE FORMAT f TYPE = 'CSV'", "CREATE FILE FORMAT"},
		{keywords.DialectOracle, "CREATE PUBLIC SYNONYM e FOR hr.employees", "CREATE SYNONYM"},
		{keywords.DialectOracle, "CREATE SEQUENCE s START WITH 1 NOCACHE", "CREATE SEQUENCE"},
		{keywords.DialectSQLite, "CREATE VIRTUAL TABLE f USING fts5(title, body)", "CREATE VIRTUAL TABLE"},
		{keywords.DialectOracle, "DROP USER u CASCADE", "DROP USER"},
		{keywords.DialectMySQL, "DROP FUNCTION IF EXISTS f", "DROP FUNCTION"},
		{keywords.DialectOracle, "DROP PUBLIC SYNONYM e", "DROP PUBLIC SYNONYM"},
		{keywords.DialectSQLServer, "CREATE OR ALTER PROCEDURE p AS SELECT 1", "CREATE PROCEDURE"},
		{keywords.DialectSnowflake, "DROP SCHEMA s", "DROP SCHEMA"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			u, ok := parseOne(t, tt.dialect, tt.sql).(*ast.UtilityStatement)
			if !ok {
				t.Fatalf("want *ast.UtilityStatement")
			}
			if u.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", u.Kind, tt.kind)
			}
			if u.SQL() != tt.sql {
				t.Fatalf("SQL() = %q, want the input", u.SQL())
			}
			formatted := gosqlx.FormatAST(&ast.AST{Statements: []ast.Statement{u}})
			if strings.Contains(formatted, "UNSUPPORTED") {
				t.Fatalf("formatted as unsupported: %s", formatted)
			}
		})
	}
}

// TestDDLObjects_Errors checks inputs that must still be rejected.
func TestDDLObjects_Errors(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, "CREATE SEQUENCE s"},
		{keywords.DialectPostgreSQL, "CREATE TABLE t ENGINE = x"},
		{keywords.DialectPostgreSQL, "CREATE SECURE TABLE t (a INT)"},
		{keywords.DialectPostgreSQL, "CREATE TABLE t"},
		{keywords.DialectClickHouse, "CREATE TABLE t (a UInt8) ENGINE = MergeTree ORDER BY a ORDER BY a"},
		{keywords.DialectPostgreSQL, "CREATE INDEX i ON t (a NULLS)"},
		{keywords.DialectSnowflake, "CREATE SCHEMA a.b.c.d.e.f"},
		// Modifier words alone do not make a verbatim statement.
		{keywords.DialectPostgreSQL, "CREATE OR FUNCTION f"},
		{keywords.DialectPostgreSQL, "CREATE REPLACE FUNCTION f"},
		{keywords.DialectPostgreSQL, "DROP REPLACE x"},
		{keywords.DialectPostgreSQL, "DROP OR x"},
		{keywords.DialectPostgreSQL, "DROP TEMP x"},
		{keywords.DialectPostgreSQL, "DROP UNIQUE x"},
	}
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			if _, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect); err == nil {
				t.Fatalf("%q parsed, want an error", tt.sql)
			}
		})
	}
}
