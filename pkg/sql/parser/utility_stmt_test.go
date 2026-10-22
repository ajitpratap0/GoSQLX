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
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseOne parses sql in dialect d and returns its single statement.
func utilParseOne(t *testing.T, d keywords.SQLDialect, sql string) ast.Statement {
	t.Helper()
	tree, err := ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q (%s): %v", sql, d, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q (%s): got %d statements, want 1", sql, d, len(tree.Statements))
	}
	return tree.Statements[0]
}

// sqlOf returns the SQL() rendering of a statement.
func utilSQLOf(t *testing.T, s ast.Statement) string {
	t.Helper()
	sq, ok := s.(interface{ SQL() string })
	if !ok {
		t.Fatalf("%T has no SQL()", s)
	}
	return sq.SQL()
}

// Transaction control parses into TransactionStatement in every dialect that
// has it, keeps the statement text and records the savepoint.
func TestParser_TransactionStatement(t *testing.T) {
	tests := []struct {
		dialect   keywords.SQLDialect
		sql       string
		action    string
		savepoint string
	}{
		{keywords.DialectPostgreSQL, "BEGIN", "BEGIN", ""},
		{keywords.DialectPostgreSQL, "BEGIN ISOLATION LEVEL SERIALIZABLE", "BEGIN", ""},
		{keywords.DialectPostgreSQL, "BEGIN TRANSACTION READ ONLY", "BEGIN", ""},
		{keywords.DialectPostgreSQL, "COMMIT", "COMMIT", ""},
		{keywords.DialectPostgreSQL, "ROLLBACK", "ROLLBACK", ""},
		{keywords.DialectPostgreSQL, "ROLLBACK TO SAVEPOINT sp1", "ROLLBACK", "sp1"},
		{keywords.DialectPostgreSQL, "SAVEPOINT sp1", "SAVEPOINT", "sp1"},
		{keywords.DialectPostgreSQL, "RELEASE SAVEPOINT sp1", "RELEASE SAVEPOINT", "sp1"},
		{keywords.DialectPostgreSQL, "RELEASE sp1", "RELEASE SAVEPOINT", "sp1"},
		{keywords.DialectPostgreSQL, "END", "END", ""},
		{keywords.DialectPostgreSQL, "ABORT", "ROLLBACK", ""},
		{keywords.DialectMySQL, "START TRANSACTION", "START TRANSACTION", ""},
		{keywords.DialectMariaDB, "START TRANSACTION WITH CONSISTENT SNAPSHOT", "START TRANSACTION", ""},
		{keywords.DialectMySQL, "BEGIN", "BEGIN", ""},
		{keywords.DialectMySQL, "ROLLBACK TO SAVEPOINT sp1", "ROLLBACK", "sp1"},
		{keywords.DialectSQLite, "BEGIN IMMEDIATE", "BEGIN", ""},
		{keywords.DialectSQLite, "BEGIN DEFERRED TRANSACTION", "BEGIN", ""},
		{keywords.DialectSQLite, "END TRANSACTION", "END", ""},
		{keywords.DialectSQLite, "ROLLBACK TRANSACTION TO sp2", "ROLLBACK", "sp2"},
		{keywords.DialectOracle, "COMMIT WORK", "COMMIT", ""},
		{keywords.DialectSnowflake, "BEGIN", "BEGIN", ""},
		{keywords.DialectSQLServer, "BEGIN TRANSACTION", "BEGIN", ""},
		{keywords.DialectSQLServer, "BEGIN TRAN", "BEGIN", ""},
		{keywords.DialectSQLServer, "COMMIT TRANSACTION", "COMMIT", ""},
		{keywords.DialectSQLServer, "SAVE TRANSACTION sp1", "SAVEPOINT", "sp1"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			tx, ok := stmt.(*ast.TransactionStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.TransactionStatement", stmt)
			}
			if tx.Action != tt.action || tx.Savepoint != tt.savepoint {
				t.Errorf("action/savepoint = %q/%q, want %q/%q", tx.Action, tx.Savepoint, tt.action, tt.savepoint)
			}
			if got := utilSQLOf(t, stmt); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}

// BEGIN and END mean different things per dialect: a T-SQL BEGIN TRY or a
// PL/SQL BEGIN opens a block, and END is a transaction statement only in
// PostgreSQL and SQLite.
func TestParser_BeginEndDialectGating(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string // %T, or "error"
	}{
		{keywords.DialectSQLServer, "BEGIN TRY SELECT 1 / 0", "*ast.UtilityStatement"},
		{keywords.DialectSQLServer, "END CATCH", "*ast.UtilityStatement"},
		{keywords.DialectSQLServer, "END", "*ast.UtilityStatement"},
		{keywords.DialectOracle, "BEGIN NULL; END", "error"}, // the block body is split at ';'
		{keywords.DialectOracle, "BEGIN dbms_stats.gather_schema_stats('APP')", "*ast.UtilityStatement"},
		{keywords.DialectPostgreSQL, "END", "*ast.TransactionStatement"},
		{keywords.DialectSQLite, "END", "*ast.TransactionStatement"},
		{keywords.DialectMySQL, "END", "error"},
		{keywords.DialectOracle, "END", "error"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if tt.want == "error" {
				if err == nil && len(tree.Statements) == 1 {
					t.Fatalf("parsed as %T, want an error", tree.Statements[0])
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("got %d statements, want 1", len(tree.Statements))
			}
			if got := fmt.Sprintf("%T", tree.Statements[0]); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// SET keeps its text and records the scope and the variable name.
func TestParser_SetStatement(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		scope   string
		name    string
	}{
		{keywords.DialectPostgreSQL, "SET search_path TO public, analytics", "", "search_path"},
		{keywords.DialectPostgreSQL, "SET LOCAL statement_timeout = '5s'", "LOCAL", "statement_timeout"},
		{keywords.DialectPostgreSQL, "SET SESSION TIME ZONE 'UTC'", "SESSION", "TIME"},
		{keywords.DialectMySQL, "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci", "", "NAMES"},
		{keywords.DialectMySQL, "SET @a = 1, @b := 2", "", "@a"},
		{keywords.DialectMySQL, "SET @@session.sql_mode = 'TRADITIONAL'", "", "@@session.sql_mode"},
		{keywords.DialectMySQL, "SET GLOBAL max_connections = 500", "GLOBAL", "max_connections"},
		{keywords.DialectMySQL, "SET @total = (SELECT COUNT(*) FROM users)", "", "@total"},
		{keywords.DialectMariaDB, "SET STATEMENT max_statement_time = 5 FOR SELECT * FROM orders", "", "STATEMENT"},
		{keywords.DialectSQLServer, "SET NOCOUNT ON", "", "NOCOUNT"},
		{keywords.DialectSQLServer, "SET @i = @i + 1", "", "@i"},
		{keywords.DialectSQLServer, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", "", "TRANSACTION"},
		{keywords.DialectClickHouse, "SET max_threads = 8", "", "max_threads"},
		{keywords.DialectSnowflake, "SET my_var = 10", "", "my_var"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			set, ok := stmt.(*ast.SetStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.SetStatement", stmt)
			}
			if set.Scope != tt.scope || set.Name != tt.name {
				t.Errorf("scope/name = %q/%q, want %q/%q", set.Scope, set.Name, tt.scope, tt.name)
			}
			if got := utilSQLOf(t, stmt); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}

// USE parses in every dialect, with the Snowflake object kinds.
func TestParser_UseStatement(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		kind    string
		name    string
	}{
		{keywords.DialectMySQL, "USE app", "", "app"},
		{keywords.DialectMySQL, "USE `my-app`", "", "my-app"},
		{keywords.DialectSQLServer, "USE [Northwind]", "", "Northwind"},
		{keywords.DialectClickHouse, "USE analytics", "", "analytics"},
		{keywords.DialectSnowflake, "USE WAREHOUSE compute_wh", "WAREHOUSE", "compute_wh"},
		{keywords.DialectSnowflake, "USE SCHEMA analytics.public", "SCHEMA", "analytics.public"},
		{keywords.DialectSnowflake, "USE analytics.public", "", "analytics.public"},
		{keywords.DialectSnowflake, "USE SECONDARY ROLES ALL", "SECONDARY ROLES", "ALL"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			use, ok := stmt.(*ast.UseStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.UseStatement", stmt)
			}
			if use.ObjectKind != tt.kind || use.Name != tt.name {
				t.Errorf("kind/name = %q/%q, want %q/%q", use.ObjectKind, use.Name, tt.kind, tt.name)
			}
			if got := utilSQLOf(t, stmt); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}

// CALL parses its arguments as expressions; forms the expression parser does
// not accept are kept verbatim.
func TestParser_CallStatement(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		name    string
		args    int
		want    string // SQL()
	}{
		{keywords.DialectMySQL, "CALL refresh_stats(2024, 'full')", "refresh_stats", 2, "CALL refresh_stats(2024, 'full')"},
		{keywords.DialectMySQL, "CALL sp_noargs()", "sp_noargs", 0, "CALL sp_noargs()"},
		{keywords.DialectMySQL, "CALL sp_noargs", "sp_noargs", 0, "CALL sp_noargs"},
		{keywords.DialectMariaDB, "CALL sp_touch_user(42)", "sp_touch_user", 1, "CALL sp_touch_user(42)"},
		{keywords.DialectSnowflake, "CALL db.schema.sp_load('2024-01-01')", "db.schema.sp_load", 1, "CALL db.schema.sp_load('2024-01-01')"},
		{keywords.DialectPostgreSQL, "CALL my_proc(1, 'a', NULL)", "my_proc", 3, "CALL my_proc(1, 'a', NULL)"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			call, ok := stmt.(*ast.CallStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.CallStatement", stmt)
			}
			if call.Name != tt.name || len(call.Arguments) != tt.args {
				t.Errorf("name/args = %q/%d, want %q/%d", call.Name, len(call.Arguments), tt.name, tt.args)
			}
			if got := utilSQLOf(t, stmt); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}

	// Named arguments are not expressions; the statement is kept verbatim.
	stmt := utilParseOne(t, keywords.DialectPostgreSQL, "CALL p(a => 1)")
	u, ok := stmt.(*ast.UtilityStatement)
	if !ok {
		t.Fatalf("CALL p(a => 1): got %T, want *ast.UtilityStatement", stmt)
	}
	if u.Kind != "CALL" || u.SQL() != "CALL p(a => 1)" {
		t.Errorf("CALL p(a => 1): kind/SQL = %q/%q", u.Kind, u.SQL())
	}
}

// The long tail of utility statements is kept verbatim: SQL() reproduces the
// statement exactly (comments removed, whitespace collapsed), never as an
// "-- UNSUPPORTED" comment.
func TestParser_UtilityStatementVerbatim(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		kind    string
		want    string // SQL(); "" means the input itself
	}{
		{keywords.DialectPostgreSQL, "GRANT SELECT, INSERT ON users TO app_rw", "GRANT", ""},
		{keywords.DialectPostgreSQL, "REVOKE UPDATE ON orders FROM readonly", "REVOKE", ""},
		{keywords.DialectPostgreSQL, "COMMENT ON TABLE users IS 'it''s users'", "COMMENT", ""},
		{keywords.DialectPostgreSQL, "VACUUM (VERBOSE, ANALYZE) users", "VACUUM", ""},
		{keywords.DialectPostgreSQL, "ANALYZE users", "ANALYZE", ""},
		{keywords.DialectPostgreSQL, "LISTEN channel", "LISTEN", ""},
		{keywords.DialectPostgreSQL, "NOTIFY channel, 'hello'", "NOTIFY", ""},
		{keywords.DialectPostgreSQL, "LOCK TABLE users IN ACCESS EXCLUSIVE MODE", "LOCK", ""},
		{keywords.DialectPostgreSQL, "DO $$ BEGIN RAISE NOTICE 'hi'; END $$", "DO", ""},
		{keywords.DialectPostgreSQL, "PREPARE stmt (int) AS SELECT * FROM users WHERE id = $1", "PREPARE", ""},
		{keywords.DialectPostgreSQL, "EXECUTE stmt(5)", "EXECUTE", ""},
		{keywords.DialectPostgreSQL, "DEALLOCATE stmt", "DEALLOCATE", ""},
		{keywords.DialectPostgreSQL, "RESET ALL", "RESET", ""},
		{keywords.DialectPostgreSQL, "TABLE users", "TABLE", ""},
		{keywords.DialectPostgreSQL, "GRANT  SELECT\n  ON users -- why\n  TO app", "GRANT", "GRANT SELECT ON users TO app"},
		{keywords.DialectMySQL, "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION", "GRANT", ""},
		{keywords.DialectMySQL, "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE users FIELDS TERMINATED BY ',' LINES TERMINATED BY '\\n'", "LOAD", ""},
		{keywords.DialectMySQL, "KILL 123", "KILL", ""},
		{keywords.DialectMySQL, "LOCK TABLES users WRITE, orders READ", "LOCK", ""},
		{keywords.DialectMySQL, "UNLOCK TABLES", "UNLOCK", ""},
		{keywords.DialectMySQL, "FLUSH PRIVILEGES", "FLUSH", ""},
		{keywords.DialectMySQL, "OPTIMIZE TABLE users", "OPTIMIZE", ""},
		{keywords.DialectMySQL, "CHECK TABLE users", "CHECK", ""},
		{keywords.DialectMySQL, "RENAME TABLE a TO b, c TO d", "RENAME", ""},
		{keywords.DialectMySQL, "PREPARE stmt FROM 'SELECT * FROM users WHERE id = ?'", "PREPARE", ""},
		{keywords.DialectMySQL, "EXECUTE stmt USING @id", "EXECUTE", ""},
		{keywords.DialectMySQL, "XA START 'a'", "XA", ""},
		{keywords.DialectMySQL, "TABLE users ORDER BY id LIMIT 5", "TABLE", ""},
		{keywords.DialectMySQL, "SHOW VARIABLES LIKE 'max_%'", "SHOW", ""},
		{keywords.DialectMySQL, "SHOW FULL PROCESSLIST", "SHOW", ""},
		{keywords.DialectMySQL, "SHOW GRANTS FOR 'app'@'%'", "SHOW", ""},
		{keywords.DialectSnowflake, "SHOW TABLES IN SCHEMA analytics.public", "SHOW", ""},
		{keywords.DialectSnowflake, "GRANT SELECT ON FUTURE TABLES IN SCHEMA analytics.public TO ROLE analyst", "GRANT", ""},
		{keywords.DialectSnowflake, "COPY INTO raw_events FROM @my_stage/events/ FILE_FORMAT = (TYPE = 'JSON')", "COPY", ""},
		{keywords.DialectSnowflake, "PUT file:///tmp/data.csv @my_stage AUTO_COMPRESS = TRUE", "PUT", ""},
		{keywords.DialectSnowflake, "LIST @my_stage", "LIST", ""},
		{keywords.DialectSnowflake, "EXECUTE IMMEDIATE 'SELECT 1'", "EXECUTE", ""},
		{keywords.DialectSnowflake, "UNDROP TABLE users", "UNDROP", ""},
		{keywords.DialectClickHouse, "SYSTEM FLUSH LOGS", "SYSTEM", ""},
		{keywords.DialectClickHouse, "OPTIMIZE TABLE events PARTITION 202401 FINAL", "OPTIMIZE", ""},
		{keywords.DialectClickHouse, "KILL QUERY WHERE query_id = 'abc' SYNC", "KILL", ""},
		{keywords.DialectClickHouse, "EXISTS TABLE events", "EXISTS", ""},
		{keywords.DialectClickHouse, "SHOW TABLES FROM system LIKE 'query%'", "SHOW", ""},
		{keywords.DialectClickHouse, "EXCHANGE TABLES a AND b", "EXCHANGE", ""},
		{keywords.DialectSQLite, "ATTACH DATABASE 'archive.db' AS archive", "ATTACH", ""},
		{keywords.DialectSQLite, "DETACH DATABASE archive", "DETACH", ""},
		{keywords.DialectSQLite, "VACUUM INTO 'backup.db'", "VACUUM", ""},
		{keywords.DialectSQLite, "REINDEX", "REINDEX", ""},
		{keywords.DialectSQLite, "VACUUM", "VACUUM", ""},
		{keywords.DialectSQLite, "ANALYZE", "ANALYZE", ""},
		{keywords.DialectSQLServer, "THROW", "THROW", ""},
		{keywords.DialectOracle, "FLASHBACK TABLE orders TO BEFORE DROP", "FLASHBACK", ""},
		{keywords.DialectOracle, "GRANT CREATE SESSION, CREATE TABLE TO app_role", "GRANT", ""},
		{keywords.DialectSQLServer, "DECLARE @i INT = 0", "DECLARE", ""},
		{keywords.DialectSQLServer, "DECLARE @t TABLE (Id INT PRIMARY KEY, Name NVARCHAR(50))", "DECLARE", ""},
		{keywords.DialectSQLServer, "EXEC dbo.p @Id = 42", "EXEC", ""},
		{keywords.DialectSQLServer, "EXEC sp_executesql N'SELECT 1 WHERE x = ''y''', N'@Id INT', @Id = 5", "EXEC", ""},
		{keywords.DialectSQLServer, "IF @i > 0 SELECT 1 ELSE SELECT 0", "IF", ""},
		{keywords.DialectSQLServer, "PRINT N'Done'", "PRINT", ""},
		{keywords.DialectSQLServer, "THROW 50001, N'Custom error', 1", "THROW", ""},
		{keywords.DialectSQLServer, "BULK INSERT dbo.Staging FROM 'C:\\data\\file.csv' WITH (FIRSTROW = 2)", "BULK", ""},
		{keywords.DialectSQLServer, "GRANT SELECT ON dbo.Customers TO [AppUser]", "GRANT", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			u, ok := stmt.(*ast.UtilityStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.UtilityStatement", stmt)
			}
			if u.Kind != tt.kind {
				t.Errorf("Kind = %q, want %q", u.Kind, tt.kind)
			}
			want := tt.want
			if want == "" {
				want = tt.sql
			}
			if got := u.SQL(); got != want {
				t.Errorf("SQL() = %q, want %q", got, want)
			}
			// The rendering re-parses to the same statement.
			again := utilParseOne(t, tt.dialect, u.SQL())
			if got := utilSQLOf(t, again); got != want {
				t.Errorf("re-parsed SQL() = %q, want %q", got, want)
			}
		})
	}
}

// Utility statements are recognized only at a statement boundary. The tail
// of a statement the parser stopped short in must not be split off as a
// second statement that happens to start with a utility keyword.
func TestParser_UtilityStatementBoundary(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, "SELECT * FROM accounts WHERE id = 1 LOCK IN SHARE MODE"},
		{keywords.DialectMySQL, "SELECT 1 SET @a = 1"},
		{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE a = 1 COMMIT"},
		{keywords.DialectSQLServer, "SELECT 1 PRINT 'x'"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			if tree, err := ParseWithDialect(tt.sql, tt.dialect); err == nil {
				t.Fatalf("parsed as %d statements, want an error", len(tree.Statements))
			}
		})
	}

	// After a semicolon a utility statement is fine.
	tree, err := ParseWithDialect("SELECT 1; COMMIT", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("SELECT 1; COMMIT: %v", err)
	}
	if len(tree.Statements) != 2 {
		t.Fatalf("SELECT 1; COMMIT: got %d statements, want 2", len(tree.Statements))
	}
	if _, ok := tree.Statements[1].(*ast.TransactionStatement); !ok {
		t.Errorf("SELECT 1; COMMIT: second statement is %T", tree.Statements[1])
	}
}

// Statements that are not utility statements in a dialect, or that are
// malformed, are still errors.
func TestParser_UtilityStatementErrors(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "IF x > 0 SELECT 1"}, // T-SQL only
		{keywords.DialectPostgreSQL, "PRINT 'x'"},         // T-SQL only
		{keywords.DialectPostgreSQL, "EXISTS TABLE t"},    // ClickHouse only
		{keywords.DialectMySQL, "COMMENT TABLE t"},        // COMMENT needs ON
		{keywords.DialectMySQL, "START t"},                // START needs TRANSACTION
		{keywords.DialectPostgreSQL, "GRANT SELECT ON t TO (u"},
		{keywords.DialectPostgreSQL, "GRANT SELECT ON t) TO u"},
		{keywords.DialectPostgreSQL, "SET"},
		{keywords.DialectMySQL, "USE"},
		{keywords.DialectPostgreSQL, "TABLE"},
		{keywords.DialectPostgreSQL, "GRANT"},
		{keywords.DialectMySQL, "KILL;"},
		{keywords.DialectSQLServer, "EXEC"},
		{keywords.DialectPostgreSQL, "SELEC 1"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			if tree, err := ParseWithDialect(tt.sql, tt.dialect); err == nil {
				t.Fatalf("parsed as %T, want an error", tree.Statements[0])
			}
		})
	}
}

// MariaDB ANALYZE <statement> explains the statement like EXPLAIN ANALYZE.
func TestParser_AnalyzeStatement(t *testing.T) {
	stmt := utilParseOne(t, keywords.DialectMariaDB, "ANALYZE FORMAT=JSON SELECT * FROM t1")
	ex, ok := stmt.(*ast.ExplainStatement)
	if !ok {
		t.Fatalf("got %T, want *ast.ExplainStatement", stmt)
	}
	if ex.Keyword != "ANALYZE" {
		t.Errorf("Keyword = %q, want ANALYZE", ex.Keyword)
	}
	if _, ok := ex.Statement.(*ast.SelectStatement); !ok {
		t.Errorf("explained statement is %T, want *ast.SelectStatement", ex.Statement)
	}
	// ANALYZE TABLE is a maintenance statement.
	stmt = utilParseOne(t, keywords.DialectMariaDB, "ANALYZE TABLE orders")
	if u, ok := stmt.(*ast.UtilityStatement); !ok || u.Kind != "ANALYZE" {
		t.Errorf("ANALYZE TABLE orders: got %#v", stmt)
	}
}

// DESCRIBE keeps the keyword it was written with and its object kind.
func TestParser_DescribeKeywordAndKind(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		keyword string
		kind    string
		table   string
	}{
		{keywords.DialectMySQL, "DESC users", "DESC", "", "users"},
		{keywords.DialectMySQL, "DESCRIBE users", "DESCRIBE", "", "users"},
		{keywords.DialectClickHouse, "DESCRIBE TABLE events", "DESCRIBE", "TABLE", "events"},
		{keywords.DialectSnowflake, "DESC VIEW v_orders", "DESC", "VIEW", "v_orders"},
		{keywords.DialectSnowflake, "DESCRIBE STAGE my_stage", "DESCRIBE", "STAGE", "my_stage"},
		{keywords.DialectMySQL, "DESCRIBE table", "DESCRIBE", "", "table"},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			d, ok := stmt.(*ast.DescribeStatement)
			if !ok {
				t.Fatalf("got %T, want *ast.DescribeStatement", stmt)
			}
			if d.Keyword != tt.keyword || d.ObjectKind != tt.kind || d.TableName != tt.table {
				t.Errorf("keyword/kind/table = %q/%q/%q, want %q/%q/%q",
					d.Keyword, d.ObjectKind, d.TableName, tt.keyword, tt.kind, tt.table)
			}
			if got := d.SQL(); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}

// PRAGMA accepts a schema-qualified name.
func TestParser_PragmaSchemaQualified(t *testing.T) {
	stmt := utilParseOne(t, keywords.DialectSQLite, "PRAGMA main.synchronous = NORMAL")
	pr, ok := stmt.(*ast.PragmaStatement)
	if !ok {
		t.Fatalf("got %T, want *ast.PragmaStatement", stmt)
	}
	if pr.Schema != "main" || pr.Name != "synchronous" || pr.Value != "NORMAL" {
		t.Errorf("schema/name/value = %q/%q/%q", pr.Schema, pr.Name, pr.Value)
	}
	if got := pr.SQL(); got != "PRAGMA main.synchronous = NORMAL" {
		t.Errorf("SQL() = %q", got)
	}
}

// Verbatim text restores each token's delimiters and escapes: string
// literals re-escape backslashes only where the tokenizer decoded them, and
// delimited identifiers keep their own quotes.
func TestParser_UtilityStatementTokenText(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, `SET @p = 'C:\\tmp\\x'`},
		{keywords.DialectMySQL, "GRANT SELECT ON `my db`.`t``x` TO 'u'@'%'"},
		{keywords.DialectSQLServer, `SET @p = 'C:\tmp\x'`},
		{keywords.DialectSQLServer, "GRANT SELECT ON [dbo].[my]]t] TO [u]"},
		{keywords.DialectSQLServer, "PRINT N'it''s'"},
		{keywords.DialectPostgreSQL, `COMMENT ON TABLE "My Table" IS 'x'`},
		{keywords.DialectPostgreSQL, "DO $q$ SELECT '$$' $q$"},
		{keywords.DialectSnowflake, `SET p = 'C:\tmp'`},
	}
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			stmt := utilParseOne(t, tt.dialect, tt.sql)
			got := utilSQLOf(t, stmt)
			if tt.sql == "DO $q$ SELECT '$$' $q$" {
				// The dollar-quote tag is not kept by the tokenizer; any tag
				// that does not occur in the body is equivalent.
				if got != "DO $q$ SELECT '$$' $q$" {
					t.Errorf("SQL() = %q", got)
				}
				return
			}
			if got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}
