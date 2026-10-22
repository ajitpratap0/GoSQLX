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

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// formatAlter parses sql in dialect and renders its only statement with opts.
// ALTER statements other than ALTER TABLE come back as utility statements.
func formatAlter(t *testing.T, sql string, dialect keywords.SQLDialect, opts ast.FormatOptions) string {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, dialect, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q: expected 1 statement, got %d", sql, len(tree.Statements))
	}
	return formatter.FormatStatement(tree.Statements[0], opts)
}

// TestFormatStatement_AlterTableDialects checks that the ALTER TABLE forms of
// each dialect render with their meaning intact (nothing dropped, nothing
// added) and that the rendering re-parses to the same text.
func TestFormatStatement_AlterTableDialects(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordUpper

	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		// PostgreSQL
		{"pg add column if not exists", keywords.DialectPostgreSQL, "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(32)", "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(32)"},
		{"pg only and if exists", keywords.DialectPostgreSQL, "alter table if exists only public.t drop column if exists a cascade", "ALTER TABLE IF EXISTS ONLY public.t DROP COLUMN IF EXISTS a CASCADE"},
		{"pg several actions", keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN a int, ADD COLUMN b int", "ALTER TABLE t ADD COLUMN a int, ADD COLUMN b int"},
		{"pg set default", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a SET DEFAULT 5", "ALTER TABLE t ALTER COLUMN a SET DEFAULT 5"},
		{"pg drop default", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a DROP DEFAULT", "ALTER TABLE t ALTER COLUMN a DROP DEFAULT"},
		{"pg alter without column keyword", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER a SET NOT NULL", "ALTER TABLE t ALTER a SET NOT NULL"},
		{"pg type using", keywords.DialectPostgreSQL, "ALTER TABLE t ALTER COLUMN a TYPE numeric(10,2) USING a::numeric", "ALTER TABLE t ALTER COLUMN a TYPE numeric(10,2) USING CAST(a AS numeric)"},
		{"pg rls", keywords.DialectPostgreSQL, "ALTER TABLE t ENABLE ROW LEVEL SECURITY", "ALTER TABLE t ENABLE ROW LEVEL SECURITY"},
		{"pg owner", keywords.DialectPostgreSQL, "ALTER TABLE t OWNER TO bob", "ALTER TABLE t OWNER TO bob"},
		{"pg bare primary key", keywords.DialectPostgreSQL, "ALTER TABLE t ADD PRIMARY KEY (a)", "ALTER TABLE t ADD PRIMARY KEY (a)"},
		{"pg named check not valid", keywords.DialectPostgreSQL, "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID", "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID"},
		{"pg drop constraint restrict", keywords.DialectPostgreSQL, "ALTER TABLE t DROP CONSTRAINT IF EXISTS c RESTRICT", "ALTER TABLE t DROP CONSTRAINT IF EXISTS c RESTRICT"},
		{"pg rename column without keyword", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME a TO b", "ALTER TABLE t RENAME a TO b"},
		{"pg rename to qualified", keywords.DialectPostgreSQL, "ALTER TABLE t RENAME TO s.u", "ALTER TABLE t RENAME TO s.u"},
		{"pg quoted names", keywords.DialectPostgreSQL, `ALTER TABLE "My Table" ADD COLUMN "Col X" int`, `ALTER TABLE "My Table" ADD COLUMN "Col X" int`},
		{"pg storage parameters", keywords.DialectPostgreSQL, "ALTER TABLE t SET (fillfactor = 70)", "ALTER TABLE t SET (fillfactor = 70)"},
		// MySQL / MariaDB
		{"mysql modify after", keywords.DialectMySQL, "ALTER TABLE t MODIFY COLUMN c INT NOT NULL AFTER b", "ALTER TABLE t MODIFY COLUMN c INT NOT NULL AFTER b"},
		{"mysql change first", keywords.DialectMySQL, "ALTER TABLE t CHANGE a b INT FIRST", "ALTER TABLE t CHANGE a b INT FIRST"},
		{"mysql add index", keywords.DialectMySQL, "ALTER TABLE t ADD UNIQUE INDEX uq (a, b)", "ALTER TABLE t ADD UNIQUE INDEX uq (a, b)"},
		{"mysql drop index", keywords.DialectMySQL, "ALTER TABLE t DROP INDEX ix", "ALTER TABLE t DROP INDEX ix"},
		{"mysql drop primary key", keywords.DialectMySQL, "ALTER TABLE t DROP PRIMARY KEY", "ALTER TABLE t DROP PRIMARY KEY"},
		{"mysql drop foreign key", keywords.DialectMySQL, "ALTER TABLE t DROP FOREIGN KEY fk", "ALTER TABLE t DROP FOREIGN KEY fk"},
		{"mysql drop without column keyword", keywords.DialectMySQL, "ALTER TABLE t DROP c", "ALTER TABLE t DROP c"},
		{"mysql options", keywords.DialectMySQL, "ALTER TABLE t ENGINE=InnoDB, ALGORITHM=INPLACE, LOCK=NONE", "ALTER TABLE t ENGINE=InnoDB, ALGORITHM=INPLACE, LOCK=NONE"},
		{"mysql convert", keywords.DialectMySQL, "ALTER TABLE t CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci", "ALTER TABLE t CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"},
		{"mysql rename without to", keywords.DialectMySQL, "ALTER TABLE t RENAME u", "ALTER TABLE t RENAME TO u"},
		{"mysql parenthesized add", keywords.DialectMySQL, "ALTER TABLE t ADD (a INT, b INT)", "ALTER TABLE t ADD (a INT, b INT)"},
		{"mysql order by", keywords.DialectMySQL, "ALTER TABLE t ORDER BY a, b DESC", "ALTER TABLE t ORDER BY a, b DESC"},
		{"mysql drop partitions", keywords.DialectMySQL, "ALTER TABLE t DROP PARTITION p1, p2", "ALTER TABLE t DROP PARTITION p1, p2"},
		{"mariadb online", keywords.DialectMariaDB, "ALTER ONLINE TABLE t ADD COLUMN c INT", "ALTER ONLINE TABLE t ADD COLUMN c INT"},
		{"mariadb drop index if exists", keywords.DialectMariaDB, "ALTER TABLE t DROP INDEX IF EXISTS ix", "ALTER TABLE t DROP INDEX IF EXISTS ix"},
		{"mariadb add if not exists without column", keywords.DialectMariaDB, "ALTER TABLE t ADD IF NOT EXISTS c INT", "ALTER TABLE t ADD IF NOT EXISTS c INT"},
		{"mariadb system versioning", keywords.DialectMariaDB, "ALTER TABLE t ADD SYSTEM VERSIONING", "ALTER TABLE t ADD SYSTEM VERSIONING"},
		// SQL Server
		{"mssql add without column keyword", keywords.DialectSQLServer, "ALTER TABLE dbo.t ADD c INT NULL", "ALTER TABLE dbo.t ADD c INT NULL"},
		{"mssql add list", keywords.DialectSQLServer, "ALTER TABLE dbo.t ADD a INT NULL, b INT NOT NULL", "ALTER TABLE dbo.t ADD a INT NULL, b INT NOT NULL"},
		{"mssql drop column list", keywords.DialectSQLServer, "ALTER TABLE dbo.t DROP COLUMN a, b", "ALTER TABLE dbo.t DROP COLUMN a, b"},
		{"mssql alter column definition", keywords.DialectSQLServer, "ALTER TABLE dbo.t ALTER COLUMN Name NVARCHAR(400) NOT NULL", "ALTER TABLE dbo.t ALTER COLUMN Name NVARCHAR(400) NOT NULL"},
		{"mssql with nocheck", keywords.DialectSQLServer, "ALTER TABLE dbo.t WITH NOCHECK ADD CONSTRAINT c CHECK (a >= 0)", "ALTER TABLE dbo.t WITH NOCHECK ADD CONSTRAINT c CHECK (a >= 0)"},
		{"mssql nonclustered", keywords.DialectSQLServer, "ALTER TABLE dbo.t ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a, b)", "ALTER TABLE dbo.t ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a, b)"},
		{"mssql nocheck constraint", keywords.DialectSQLServer, "ALTER TABLE dbo.t NOCHECK CONSTRAINT fk", "ALTER TABLE dbo.t NOCHECK CONSTRAINT fk"},
		// Oracle
		{"oracle parenthesized add", keywords.DialectOracle, "ALTER TABLE t ADD (a NUMBER, b VARCHAR2(10))", "ALTER TABLE t ADD (a NUMBER, b VARCHAR2(10))"},
		{"oracle modify list", keywords.DialectOracle, "ALTER TABLE t MODIFY (a VARCHAR2(20) NOT NULL)", "ALTER TABLE t MODIFY (a VARCHAR2(20) NOT NULL)"},
		{"oracle enable novalidate", keywords.DialectOracle, "ALTER TABLE t ENABLE NOVALIDATE CONSTRAINT c", "ALTER TABLE t ENABLE NOVALIDATE CONSTRAINT c"},
		{"oracle add partition", keywords.DialectOracle, "ALTER TABLE t ADD PARTITION p VALUES LESS THAN (TO_DATE('2026-01-01', 'YYYY-MM-DD'))", "ALTER TABLE t ADD PARTITION p VALUES LESS THAN (TO_DATE('2026-01-01', 'YYYY-MM-DD'))"},
		{"oracle move tablespace", keywords.DialectOracle, "ALTER TABLE t MOVE TABLESPACE users2", "ALTER TABLE t MOVE TABLESPACE users2"},
		// Snowflake
		{"snowflake qualified", keywords.DialectSnowflake, "ALTER TABLE a.b.c ADD COLUMN IF NOT EXISTS x INT", "ALTER TABLE a.b.c ADD COLUMN IF NOT EXISTS x INT"},
		{"snowflake swap", keywords.DialectSnowflake, "ALTER TABLE a.b SWAP WITH a.c", "ALTER TABLE a.b SWAP WITH a.c"},
		{"snowflake cluster by", keywords.DialectSnowflake, "ALTER TABLE t CLUSTER BY (a, b)", "ALTER TABLE t CLUSTER BY (a, b)"},
		{"snowflake set properties", keywords.DialectSnowflake, "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 7, COMMENT = 'x'", "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 7, COMMENT = 'x'"},
		{"snowflake set data type", keywords.DialectSnowflake, "ALTER TABLE t ALTER COLUMN a SET DATA TYPE VARCHAR(10)", "ALTER TABLE t ALTER COLUMN a SET DATA TYPE VARCHAR(10)"},
		{"snowflake masking policy", keywords.DialectSnowflake, "ALTER TABLE t MODIFY COLUMN email SET MASKING POLICY email_mask", "ALTER TABLE t MODIFY COLUMN email SET MASKING POLICY email_mask"},
		// ClickHouse
		{"clickhouse on cluster", keywords.DialectClickHouse, "ALTER TABLE db.t ON CLUSTER c ADD COLUMN x UInt8 AFTER y", "ALTER TABLE db.t ON CLUSTER c ADD COLUMN x UInt8 AFTER y"},
		{"clickhouse update", keywords.DialectClickHouse, "ALTER TABLE t UPDATE a = 1, b = 'x' IN PARTITION '202401' WHERE id = 1", "ALTER TABLE t UPDATE a = 1, b = 'x' IN PARTITION '202401' WHERE id = 1"},
		{"clickhouse delete", keywords.DialectClickHouse, "ALTER TABLE t DELETE WHERE ts < now() - INTERVAL 90 DAY", "ALTER TABLE t DELETE WHERE ts < now() - INTERVAL 90 DAY"},
		{"clickhouse modify ttl", keywords.DialectClickHouse, "ALTER TABLE t MODIFY TTL ts + INTERVAL 6 MONTH", "ALTER TABLE t MODIFY TTL ts + INTERVAL 6 MONTH"},
		{"clickhouse add index", keywords.DialectClickHouse, "ALTER TABLE t ADD INDEX i a TYPE bloom_filter GRANULARITY 3", "ALTER TABLE t ADD INDEX i a TYPE bloom_filter GRANULARITY 3"},
		{"clickhouse drop partition id", keywords.DialectClickHouse, "ALTER TABLE t DROP PARTITION ID '20240101'", "ALTER TABLE t DROP PARTITION ID '20240101'"},
		{"clickhouse modify setting", keywords.DialectClickHouse, "ALTER TABLE t MODIFY SETTING a = 1, b = 2", "ALTER TABLE t MODIFY SETTING a = 1, b = 2"},
		// SQLite
		{"sqlite add column", keywords.DialectSQLite, "ALTER TABLE t ADD COLUMN a INT", "ALTER TABLE t ADD COLUMN a INT"},
		{"sqlite drop column", keywords.DialectSQLite, "ALTER TABLE t DROP COLUMN a", "ALTER TABLE t DROP COLUMN a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatAlter(t, tc.in, tc.dialect, opts)
			if got != tc.want {
				t.Errorf("format(%q):\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
			// The rendering must re-parse and render identically.
			if again := formatAlter(t, got, tc.dialect, opts); again != got {
				t.Errorf("render is not stable across re-parse:\nfirst:  %q\nsecond: %q", got, again)
			}
		})
	}
}

// TestFormatStatement_AlterTableLayout checks the readable layout of an ALTER
// TABLE with several actions and the keyword casing of the new forms.
func TestFormatStatement_AlterTableLayout(t *testing.T) {
	const in = "alter table s.t add column if not exists a int, drop column b, alter column c set default 1"
	readable := formatAlter(t, in, keywords.DialectPostgreSQL, ast.ReadableStyle())
	const wantReadable = "ALTER TABLE s.t\nADD COLUMN IF NOT EXISTS a int,\nDROP COLUMN b,\nALTER COLUMN c SET DEFAULT 1;"
	if readable != wantReadable {
		t.Errorf("readable:\n got: %q\nwant: %q", readable, wantReadable)
	}

	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	const wantLower = "alter table s.t add column if not exists a int, drop column b, alter column c set default 1"
	if got := formatAlter(t, in, keywords.DialectPostgreSQL, lower); got != wantLower {
		t.Errorf("lower:\n got: %q\nwant: %q", got, wantLower)
	}

	// The action keywords and the keyword phrase of generic actions follow
	// the casing; the text after a phrase is kept as written.
	const gen = "ALTER TABLE t ENABLE ROW LEVEL SECURITY, OWNER TO Bob"
	if got := formatAlter(t, gen, keywords.DialectPostgreSQL, lower); got != "alter table t enable row level security, owner to Bob" {
		t.Errorf("lower generic: got %q", got)
	}
}

// TestFormatStatement_AlterObjects checks that ALTER <object> statements are
// written back as they were.
func TestFormatStatement_AlterObjects(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "ALTER INDEX idx_users_email RENAME TO idx_users_email_v2"},
		{keywords.DialectSQLServer, "ALTER INDEX ALL ON dbo.Orders REBUILD WITH (ONLINE = ON)"},
		{keywords.DialectOracle, "ALTER SESSION SET NLS_LANGUAGE = 'AMERICAN' NLS_TERRITORY = 'AMERICA'"},
		{keywords.DialectOracle, "ALTER SYSTEM KILL SESSION '123,4567' IMMEDIATE"},
		{keywords.DialectSnowflake, "ALTER WAREHOUSE etl_wh SET WAREHOUSE_SIZE = 'LARGE'"},
		{keywords.DialectSnowflake, "ALTER SESSION SET QUERY_TAG = 'nightly_etl'"},
		{keywords.DialectMySQL, "ALTER DATABASE app CHARACTER SET utf8mb4"},
	}
	for _, tc := range tests {
		t.Run(tc.sql, func(t *testing.T) {
			if got := formatAlter(t, tc.sql, tc.dialect, ast.CompactStyle()); got != tc.sql {
				t.Errorf("got %q, want %q", got, tc.sql)
			}
		})
	}
}

// TestFormatStatement_AlterRolePolicyConnector checks that ALTER ROLE,
// ALTER POLICY and ALTER CONNECTOR no longer render as a bare "ALTER".
func TestFormatStatement_AlterRolePolicyConnector(t *testing.T) {
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordUpper
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		in      string
		want    string
	}{
		{"role rename", keywords.DialectGeneric, "ALTER ROLE r RENAME TO s", "ALTER ROLE r RENAME TO s"},
		{"role add member", keywords.DialectGeneric, "ALTER ROLE r ADD MEMBER m", "ALTER ROLE r ADD MEMBER m"},
		{"role drop member", keywords.DialectGeneric, "ALTER ROLE r DROP MEMBER m", "ALTER ROLE r DROP MEMBER m"},
		{"role set", keywords.DialectGeneric, "ALTER ROLE r SET search_path TO public", "ALTER ROLE r SET search_path TO public"},
		{"role reset all", keywords.DialectGeneric, "ALTER ROLE r RESET ALL", "ALTER ROLE r RESET ALL"},
		{"role options", keywords.DialectGeneric, "ALTER ROLE r WITH SUPERUSER, VALID UNTIL '2030-01-01'", "ALTER ROLE r WITH SUPERUSER, VALID UNTIL '2030-01-01'"},
		{"role password", keywords.DialectGeneric, "ALTER ROLE r WITH LOGIN, PASSWORD 'x'", "ALTER ROLE r WITH LOGIN, PASSWORD 'x'"},
		{"policy rename", keywords.DialectPostgreSQL, "ALTER POLICY p ON s.t RENAME TO q", "ALTER POLICY p ON s.t RENAME TO q"},
		{"policy modify", keywords.DialectPostgreSQL, "ALTER POLICY p ON t TO a, b USING (x > 1) WITH CHECK (y > 1)", "ALTER POLICY p ON t TO a, b USING (x > 1) WITH CHECK (y > 1)"},
		{"connector url", keywords.DialectGeneric, "ALTER CONNECTOR c SET URL 'jdbc:x'", "ALTER CONNECTOR c SET URL 'jdbc:x'"},
		{"connector properties", keywords.DialectGeneric, "ALTER CONNECTOR c SET DCPROPERTIES ('b' = 'it''s', a = '1')", "ALTER CONNECTOR c SET DCPROPERTIES ('a' = '1', 'b' = 'it''s')"},
		{"connector owner", keywords.DialectGeneric, "ALTER CONNECTOR c SET OWNER USER bob", "ALTER CONNECTOR c SET OWNER USER bob"},
		{"connector owner role", keywords.DialectGeneric, "ALTER CONNECTOR c SET OWNER ROLE admins", "ALTER CONNECTOR c SET OWNER ROLE admins"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatAlter(t, tc.in, tc.dialect, opts)
			if got != tc.want {
				t.Errorf("format(%q):\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
			if again := formatAlter(t, got, tc.dialect, opts); again != got {
				t.Errorf("render is not stable across re-parse:\nfirst:  %q\nsecond: %q", got, again)
			}
		})
	}
}
