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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// shapeCase is a script, its dialect and the statements it parses into
// (stmtShapes), or "error: <substring>" when it must not parse.
type shapeCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	want    string
}

func runShapeCases(t *testing.T, tests []shapeCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if want, isErr := strings.CutPrefix(tc.want, "error: "); isErr {
				if err == nil {
					defer ast.ReleaseAST(tree)
					t.Fatalf("parse %q (%s) = %v, want an error mentioning %q", tc.sql, tc.dialect, stmtShapes(tree), want)
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("parse %q (%s): error = %v, want it to mention %q", tc.sql, tc.dialect, err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
			defer ast.ReleaseAST(tree)
			if got := fmt.Sprint(stmtShapes(tree)); got != tc.want {
				t.Errorf("parse %q (%s) = %s, want %s", tc.sql, tc.dialect, got, tc.want)
			}
		})
	}
}

// A statement whose definition holds another statement ends where that
// statement ends: a statement on the next line without a ';' is an error
// outside SQL Server instead of being folded into its text.
func TestParser_NestedStatementBodyEnds(t *testing.T) {
	const missingSemi = "error: end of statement"
	pg, my, lite := keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite
	runShapeCases(t, []shapeCase{
		// PREPARE ... AS <stmt>
		{"prepare then drop", pg, "PREPARE s AS SELECT 1\nDROP TABLE t", missingSemi},
		{"prepare with types", pg, "PREPARE s (int, text) AS INSERT INTO t VALUES ($1, $2);\nDROP TABLE t",
			"[Utility(PREPARE) Drop]"},
		{"prepare union", pg, "PREPARE s AS SELECT 1 UNION SELECT 2", "[Utility(PREPARE)]"},
		{"prepare then commit line", pg, "PREPARE s AS SELECT a FROM t WHERE b = 1\nCOMMIT",
			"[Utility(PREPARE) Transaction]"},
		{"prepare from then drop", my, "PREPARE s FROM 'SELECT 1'\nDROP TABLE t", missingSemi},
		{"prepare bad body", pg, "PREPARE s AS SELECT FROM", "error: "},
		// DECLARE ... CURSOR FOR <query>
		{"cursor then drop", pg, "DECLARE c CURSOR FOR SELECT 1\nDROP TABLE t", missingSemi},
		{"cursor options", pg, "DECLARE c BINARY NO SCROLL CURSOR WITH HOLD FOR SELECT * FROM t FOR UPDATE",
			"[Utility(DECLARE)]"},
		// PostgreSQL functions, procedures, rules and triggers
		{"quoted function body then drop", pg,
			"CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql\nDROP TABLE t", missingSemi},
		{"function options on lines", pg,
			"CREATE FUNCTION f(a int) RETURNS int\nLANGUAGE sql\nSET search_path = public\nAS $$ SELECT a $$;",
			"[Utility(CREATE FUNCTION)]"},
		{"return body then drop", pg, "CREATE FUNCTION f() RETURNS int LANGUAGE sql RETURN 1\nDROP TABLE t", missingSemi},
		{"begin atomic", pg, "CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC INSERT INTO t VALUES (1); END;\nSELECT 1",
			"[Utility(CREATE PROCEDURE) Select]"},
		{"rule nothing then drop", pg, "CREATE RULE r AS ON INSERT TO t DO INSTEAD NOTHING\nDROP TABLE t", missingSemi},
		{"rule command then drop", pg, "CREATE RULE r AS ON INSERT TO t DO INSTEAD SELECT 1\nDROP TABLE t", missingSemi},
		{"rule command list", pg, "CREATE RULE r AS ON UPDATE TO t DO ALSO (INSERT INTO log VALUES (1); NOTIFY t)",
			"[Utility(CREATE RULE)]"},
		{"pg trigger then drop", pg,
			"CREATE TRIGGER trg BEFORE UPDATE ON t FOR EACH ROW EXECUTE FUNCTION touch()\nDROP TABLE t", missingSemi},
		{"pg trigger when", pg,
			"CREATE TRIGGER trg BEFORE UPDATE ON t FOR EACH ROW WHEN (OLD.a IS DISTINCT FROM NEW.a) EXECUTE FUNCTION touch()",
			"[Utility(CREATE TRIGGER)]"},
		// MySQL: the single statement of a trigger, event or routine body
		{"mysql trigger statement then drop", my,
			"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW SET NEW.a = 1\nDROP TABLE t", missingSemi},
		{"mysql trigger insert then drop", my,
			"CREATE TRIGGER tr AFTER INSERT ON t FOR EACH ROW INSERT INTO log VALUES (1)\nDROP TABLE t", missingSemi},
		{"mysql trigger same line", my,
			"CREATE TRIGGER tr AFTER INSERT ON t FOR EACH ROW INSERT INTO log VALUES (1) DROP TABLE t", "error: "},
		{"mysql trigger follows", my,
			"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW FOLLOWS other SET NEW.a = 1;\nSELECT 1",
			"[Utility(CREATE TRIGGER) Select]"},
		{"mysql trigger block", my,
			"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW\nBEGIN\n  IF NEW.a < 0 THEN SET NEW.a = 0; END IF;\nEND",
			"[Utility(CREATE TRIGGER)]"},
		{"mysql trigger block then select", my,
			"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.a = 1; END\nSELECT 1", missingSemi},
		{"mysql event then drop", my, "CREATE EVENT e ON SCHEDULE EVERY 1 HOUR DO DELETE FROM t\nDROP TABLE t", missingSemi},
		{"mysql event block", my, "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO BEGIN DELETE FROM t; DELETE FROM u; END",
			"[Utility(CREATE EVENT)]"},
		{"mysql alter event without body", my, "ALTER EVENT e DISABLE", "[Utility(ALTER EVENT)]"},
		{"mysql procedure then drop", my, "CREATE PROCEDURE p() SELECT 1\nDROP TABLE t", missingSemi},
		{"mysql labelled procedure", my, "CREATE PROCEDURE p() lbl: BEGIN SELECT 1; END lbl;\nSELECT 2",
			"[Utility(CREATE PROCEDURE) Select]"},
		{"mysql definer procedure", my,
			"CREATE DEFINER=`root`@`localhost` PROCEDURE p(IN a INT)\nBEGIN\n  SELECT a;\nEND",
			"[Utility(CREATE PROCEDURE)]"},
		{"mysql function return then select", my,
			"CREATE FUNCTION f(x INT) RETURNS INT DETERMINISTIC RETURN x + 1\nSELECT 2", missingSemi},
		{"mysql function characteristics", my,
			"CREATE FUNCTION f(x INT) RETURNS INT\nDETERMINISTIC\nCOMMENT 'c'\nRETURN x + 1;",
			"[Utility(CREATE FUNCTION)]"},
		{"mysql function returns set type", my, "CREATE FUNCTION f() RETURNS SET('a','b') RETURN 'a'",
			"[Utility(CREATE FUNCTION)]"},
		{"mysql view then drop", my, "CREATE ALGORITHM=MERGE VIEW v AS SELECT 1\nDROP TABLE t", missingSemi},
		{"mysql view check option", my, "CREATE ALGORITHM=MERGE VIEW v AS SELECT a FROM t WITH CASCADED CHECK OPTION",
			"[Utility(CREATE VIEW)]"},
		{"load data then drop", my, "LOAD DATA INFILE 'x' INTO TABLE t SET a = 1\nDROP TABLE t", missingSemi},
		{"load data set line", my, "LOAD DATA INFILE 'x' INTO TABLE t (a, @b)\nSET b = @b * 2", "[Utility(LOAD)]"},
		// SQLite and Snowflake
		{"sqlite trigger then select", lite,
			"CREATE TRIGGER tr AFTER INSERT ON t WHEN NEW.a > 1 BEGIN UPDATE u SET n = n + 1; END\nSELECT 1", missingSemi},
		{"snowflake task then drop", keywords.DialectSnowflake,
			"CREATE TASK tk WAREHOUSE = w SCHEDULE = '5 MINUTE' AS INSERT INTO t SELECT 1\nDROP TABLE t", missingSemi},
		{"snowflake scripting procedure", keywords.DialectSnowflake,
			"CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS BEGIN RETURN 'x'; END;\nSELECT 1",
			"[Utility(CREATE PROCEDURE) Select]"},
		// SQL Server keeps its own rules: a routine body runs to the end of
		// the batch.
		{"tsql procedure runs to batch end", keywords.DialectSQLServer, "CREATE PROCEDURE p AS SELECT 1\nSELECT 2",
			"[Utility(CREATE PROCEDURE)]"},
	})
}

func TestParser_UtilitySelectBoundaryRegressions(t *testing.T) {
	pg := keywords.DialectPostgreSQL
	runShapeCases(t, []shapeCase{
		{"pg trigger then select", pg,
			"CREATE TRIGGER trg AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f()\nSELECT 1",
			"error: end of statement"},
		{"pg trigger separated select", pg,
			"CREATE TRIGGER trg AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f(); SELECT 1",
			"[Utility(CREATE TRIGGER) Select]"},
		{"prepare same line select", pg, "PREPARE p AS SELECT 1 SELECT 2", "error: end of statement"},
		{"prepare separated select", pg, "PREPARE p AS SELECT 1; SELECT 2", "[Utility(PREPARE) Select]"},
		{"pg grant then select", pg, "GRANT SELECT ON t TO bob SELECT 1", "error: semicolon or end of statement"},
		{"pg copy then select", pg, "COPY t TO STDOUT SELECT 1", "error: semicolon or end of statement"},
	})
}

// GRANT, REVOKE, COPY, CALL and the other utility statements with a closed
// grammar end where it ends, so a statement written after them on the same
// line without a ';' is an error rather than part of their text.
func TestParser_UtilityTrailingStatementOnSameLine(t *testing.T) {
	const missingSemi = "error: semicolon or end of statement"
	pg, my := keywords.DialectPostgreSQL, keywords.DialectMySQL
	runShapeCases(t, []shapeCase{
		{"grant then drop", pg, "GRANT SELECT ON t TO u DROP TABLE t", missingSemi},
		{"revoke then drop", pg, "REVOKE SELECT ON t FROM u DROP TABLE t", missingSemi},
		{"grant garbage", pg, "GRANT SELECT ON t TO u garbage", missingSemi},
		{"grant missing to", pg, "GRANT SELECT ON t", "error: expected TO"},
		{"revoke missing grantee", pg, "REVOKE SELECT ON t FROM", "error: grantee"},
		{"grant then commit line", pg, "GRANT SELECT ON t TO u\nCOMMIT", "[Utility(GRANT) Transaction]"},
		{"grant on lines", pg, "GRANT\nSELECT, INSERT\nON t\nTO u", "[Utility(GRANT)]"},
		{"pg grant options", pg, "GRANT r TO u WITH ADMIN OPTION GRANTED BY x", "[Utility(GRANT)]"},
		{"pg16 grant options", pg, "GRANT r TO u WITH INHERIT FALSE, SET TRUE", "[Utility(GRANT)]"},
		{"pg revoke grant option", pg, "REVOKE GRANT OPTION FOR SELECT ON t FROM u, GROUP g CASCADE", "[Utility(REVOKE)]"},
		{"pg column privileges", pg, "GRANT SELECT (a, b), UPDATE (c) ON t TO \"Mixed Case\"", "[Utility(GRANT)]"},
		{"pg function privileges", pg, "GRANT EXECUTE ON FUNCTION f(int, text) TO PUBLIC", "[Utility(GRANT)]"},
		{"mysql account", my, "GRANT SELECT ON db.* TO 'u'@'h', app@'%' WITH GRANT OPTION", "[Utility(GRANT)]"},
		{"mysql resource limits", my,
			"GRANT ALL ON db.* TO 'u'@'h' REQUIRE SSL WITH MAX_QUERIES_PER_HOUR 10 MAX_UPDATES_PER_HOUR 5",
			"[Utility(GRANT)]"},
		{"mysql identified by", my, "GRANT SELECT ON *.* TO u@'%' IDENTIFIED BY 'x' WITH GRANT OPTION", "[Utility(GRANT)]"},
		{"mysql revoke ignore", my, "REVOKE IF EXISTS SELECT ON t FROM u IGNORE UNKNOWN USER", "[Utility(REVOKE)]"},
		{"mysql grant as", my, "GRANT SELECT ON t TO u AS root WITH ROLE DEFAULT", "[Utility(GRANT)]"},
		{"oracle options", keywords.DialectOracle, "GRANT SELECT ON t TO u WITH HIERARCHY OPTION CONTAINER = ALL",
			"[Utility(GRANT)]"},
		{"oracle cascade constraints", keywords.DialectOracle, "REVOKE REFERENCES ON t FROM u CASCADE CONSTRAINTS",
			"[Utility(REVOKE)]"},
		{"snowflake copy grants", keywords.DialectSnowflake,
			"GRANT OWNERSHIP ON TABLE t TO ROLE r COPY CURRENT GRANTS", "[Utility(GRANT)]"},
		{"snowflake database role", keywords.DialectSnowflake, "GRANT DATABASE ROLE d.r TO ROLE x", "[Utility(GRANT)]"},
		{"clickhouse all except", keywords.DialectClickHouse, "REVOKE SELECT ON db.* FROM ALL EXCEPT admin",
			"[Utility(REVOKE)]"},
		{"clickhouse replace option", keywords.DialectClickHouse,
			"GRANT ON CLUSTER c SELECT(x, y) ON db.t TO u WITH REPLACE OPTION", "[Utility(GRANT)]"},
		{"tsql grant then select", keywords.DialectSQLServer, "GRANT SELECT ON t TO u SELECT 1",
			"[Utility(GRANT) Select]"},
		// COPY (PostgreSQL)
		{"copy then drop", pg, "COPY t FROM 'f' DROP TABLE t", missingSemi},
		{"copy garbage", pg, "COPY t FROM 'f' garbage", missingSemi},
		{"copy options", pg, "COPY t (a, b) FROM STDIN WITH (FORMAT csv, HEADER true)", "[Utility(COPY)]"},
		{"copy query", pg, "COPY (SELECT * FROM t) TO '/tmp/x.csv' CSV HEADER", "[Utility(COPY)]"},
		{"copy legacy options", pg,
			"COPY t FROM '/tmp/x' WITH DELIMITER AS ',' NULL AS '' CSV HEADER QUOTE '\"' FORCE NOT NULL a, b",
			"[Utility(COPY)]"},
		{"copy program where", pg, "COPY t FROM PROGRAM 'gunzip -c x.gz' (FORMAT csv) WHERE a > 1", "[Utility(COPY)]"},
		{"copy where then drop", pg, "COPY t FROM 'f' WHERE a > 1 DROP TABLE t", missingSemi},
		// CALL
		{"call then drop", pg, "CALL p(1) DROP TABLE t", missingSemi},
		{"call named args then drop", pg, "CALL p(a => 1) DROP TABLE t", missingSemi},
		{"call then commit line", pg, "CALL p(1)\nCOMMIT", "[Call Transaction]"},
		{"oracle call into", keywords.DialectOracle, "CALL f() INTO :x", "[Utility(CALL)]"},
		// The rest of the utility statements end at a statement word.
		{"vacuum then drop", pg, "VACUUM t DROP TABLE t", missingSemi},
		{"analyze then drop", pg, "ANALYZE t DROP TABLE t", missingSemi},
		{"listen then drop", pg, "LISTEN c DROP TABLE t", missingSemi},
		{"use then drop", my, "USE db DROP TABLE t", missingSemi},
		{"vacuum analyze", pg, "VACUUM FULL ANALYZE t", "[Utility(VACUUM)]"},
		{"lock share update", pg, "LOCK TABLE t IN SHARE UPDATE EXCLUSIVE MODE", "[Utility(LOCK)]"},
		{"flush read lock", my, "FLUSH TABLES WITH READ LOCK", "[Utility(FLUSH)]"},
		{"analyze histogram", my, "ANALYZE TABLE t UPDATE HISTOGRAM ON c WITH 10 BUCKETS", "[Utility(ANALYZE)]"},
		{"analyze drop histogram", my, "ANALYZE TABLE t DROP HISTOGRAM ON c", "[Utility(ANALYZE)]"},
		{"oracle analyze delete statistics", keywords.DialectOracle, "ANALYZE TABLE t DELETE STATISTICS",
			"[Utility(ANALYZE)]"},
		{"mariadb analyze statement", keywords.DialectMariaDB, "ANALYZE FORMAT=JSON SELECT 1", "[Explain]"},
		{"oracle flashback before drop", keywords.DialectOracle, "FLASHBACK TABLE orders TO BEFORE DROP",
			"[Utility(FLASHBACK)]"},
		{"deallocate prepare", pg, "DEALLOCATE PREPARE s", "[Utility(DEALLOCATE)]"},
		{"reindex table", pg, "REINDEX TABLE t", "[Utility(REINDEX)]"},
		{"xa commit", my, "XA COMMIT 'x'", "[Utility(XA)]"},
		{"clickhouse system drop", keywords.DialectClickHouse, "SYSTEM DROP DNS CACHE", "[Utility(SYSTEM)]"},
	})
}

// COMMIT and ROLLBACK are non-reserved outside SQL Server, so after a
// statement that can take an implicit alias they are that alias, on the
// same line or the next, as the database reads them; after a clause that
// takes no alias they start the next statement. In SQL Server they are
// reserved and always start one.
func TestParser_TransactionWordAfterStatement(t *testing.T) {
	var tests []shapeCase
	for _, d := range []keywords.SQLDialect{
		keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB,
		keywords.DialectSQLite, keywords.DialectOracle, keywords.DialectSnowflake,
		keywords.DialectClickHouse, keywords.DialectGeneric,
	} {
		tests = append(tests,
			shapeCase{string(d) + "/select item alias", d, "SELECT 1\nCOMMIT", "[Select]"},
			shapeCase{string(d) + "/table alias", d, "SELECT a FROM t\nrollback", "[Select]"},
			shapeCase{string(d) + "/same line alias", d, "SELECT a FROM t rollback", "[Select]"},
			shapeCase{string(d) + "/after where", d, "SELECT a FROM t WHERE b = 1\nCOMMIT", "[Select Transaction]"},
			shapeCase{string(d) + "/after explicit alias", d, "SELECT a AS x\nROLLBACK", "[Select Transaction]"},
		)
	}
	tests = append(tests,
		shapeCase{"sqlserver/select item", keywords.DialectSQLServer, "SELECT 1\nCOMMIT", "[Select Transaction]"},
		shapeCase{"sqlserver/table", keywords.DialectSQLServer, "SELECT a FROM t\nrollback", "[Select Transaction]"},
		shapeCase{"postgresql/end is reserved", keywords.DialectPostgreSQL, "SELECT 1\nEND", "[Select Transaction]"},
	)
	runShapeCases(t, tests)
}

// Utility statements are accepted only in the dialects that have them.
func TestParser_UtilityStatementDialects(t *testing.T) {
	const notStatement = "error: expected statement"
	runShapeCases(t, []shapeCase{
		{"do in mysql", keywords.DialectMySQL, "DO $$ BEGIN END $$", notStatement},
		{"do expr in mysql", keywords.DialectMySQL, "DO SLEEP(1)", "[Utility(DO)]"},
		{"do in oracle", keywords.DialectOracle, "DO $$ BEGIN END $$", notStatement},
		{"do in postgresql", keywords.DialectPostgreSQL, "DO LANGUAGE plpgsql $$ BEGIN END $$", "[Utility(DO)]"},
		{"do expr in postgresql", keywords.DialectPostgreSQL, "DO 1", notStatement},
		{"vacuum in oracle", keywords.DialectOracle, "VACUUM", notStatement},
		{"vacuum in mysql", keywords.DialectMySQL, "VACUUM", notStatement},
		{"vacuum in sqlite", keywords.DialectSQLite, "VACUUM", "[Utility(VACUUM)]"},
		{"load data in postgresql", keywords.DialectPostgreSQL, "LOAD DATA INFILE 'x' INTO TABLE t", notStatement},
		{"load library in postgresql", keywords.DialectPostgreSQL, "LOAD 'auto_explain'", "[Utility(LOAD)]"},
		{"load data in mysql", keywords.DialectMySQL, "LOAD DATA INFILE 'x' INTO TABLE t", "[Utility(LOAD)]"},
		{"copy in mysql", keywords.DialectMySQL, "COPY t FROM 'f'", notStatement},
		{"listen in mysql", keywords.DialectMySQL, "LISTEN c", notStatement},
		{"cluster in oracle", keywords.DialectOracle, "CLUSTER t", notStatement},
		{"reindex in mysql", keywords.DialectMySQL, "REINDEX t", notStatement},
		{"pragma in postgresql", keywords.DialectPostgreSQL, "PRAGMA x", notStatement},
		{"pragma in sqlite", keywords.DialectSQLite, "PRAGMA foreign_keys = ON", "[Pragma]"},
		{"attach in postgresql", keywords.DialectPostgreSQL, "ATTACH DATABASE 'f' AS a", notStatement},
		{"optimize in postgresql", keywords.DialectPostgreSQL, "OPTIMIZE TABLE t", notStatement},
		{"flush in postgresql", keywords.DialectPostgreSQL, "FLUSH TABLES", notStatement},
		{"show in oracle", keywords.DialectOracle, "SHOW TABLES", notStatement},
		{"show in sqlite", keywords.DialectSQLite, "SHOW TABLES", notStatement},
		{"kill in postgresql", keywords.DialectPostgreSQL, "KILL 1", notStatement},
		{"lock in sqlite", keywords.DialectSQLite, "LOCK TABLE t", notStatement},
		{"grant in sqlite", keywords.DialectSQLite, "GRANT SELECT ON t TO u", notStatement},
		{"set in sqlite", keywords.DialectSQLite, "SET x = 1", notStatement},
		{"use in postgresql", keywords.DialectPostgreSQL, "USE db", notStatement},
		{"call in sqlserver", keywords.DialectSQLServer, "CALL p()", notStatement},
		{"comment on in mysql", keywords.DialectMySQL, "COMMENT ON TABLE t IS 'x'", notStatement},
		{"table in sqlite", keywords.DialectSQLite, "TABLE t", notStatement},
		// A parser without a dialect accepts all of them.
		{"generic vacuum", keywords.DialectGeneric, "VACUUM", "[Utility(VACUUM)]"},
		{"generic listen", keywords.DialectGeneric, "LISTEN c", "[Utility(LISTEN)]"},
		{"generic flush", keywords.DialectGeneric, "FLUSH TABLES", "[Utility(FLUSH)]"},
		{"generic do", keywords.DialectGeneric, "DO $$ x $$", "[Utility(DO)]"},
		{"generic pragma", keywords.DialectGeneric, "PRAGMA x", "[Pragma]"},
	})
}

// reparseSQL parses sql, writes every statement back with SQL() and
// checks that the result parses to the same statements.
func reparseSQL(t *testing.T, sql string, dialect keywords.SQLDialect) string {
	t.Helper()
	tree, err := ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	defer ast.ReleaseAST(tree)
	parts := make([]string, len(tree.Statements))
	for i, s := range tree.Statements {
		w, ok := s.(interface{ SQL() string })
		if !ok {
			t.Fatalf("%T has no SQL()", s)
		}
		parts[i] = w.SQL()
	}
	out := strings.Join(parts, ";\n")
	again, err := ParseWithDialect(out, dialect)
	if err != nil {
		t.Fatalf("reparse %q: %v", out, err)
	}
	defer ast.ReleaseAST(again)
	if a, b := fmt.Sprint(stmtShapes(tree)), fmt.Sprint(stmtShapes(again)); a != b {
		t.Fatalf("reparse %q: %s, want %s", out, b, a)
	}
	for i, s := range again.Statements {
		w, ok := s.(interface{ SQL() string })
		if !ok {
			t.Fatalf("%T has no SQL()", s)
		}
		if got := w.SQL(); got != parts[i] {
			t.Fatalf("round trip of %q: %q, want %q", sql, got, parts[i])
		}
	}
	return out
}

// ALTER DEFAULT PRIVILEGES ... GRANT | REVOKE parses (PostgreSQL) and
// round-trips.
func TestParser_AlterDefaultPrivileges(t *testing.T) {
	pg := keywords.DialectPostgreSQL
	for _, sql := range []string{
		"ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO u",
		"ALTER DEFAULT PRIVILEGES FOR ROLE r IN SCHEMA s GRANT SELECT ON TABLES TO u",
		"ALTER DEFAULT PRIVILEGES FOR USER a, b IN SCHEMA s1, s2 GRANT ALL ON SEQUENCES TO u WITH GRANT OPTION",
		"ALTER DEFAULT PRIVILEGES IN SCHEMA s REVOKE SELECT ON TABLES FROM u CASCADE",
		"ALTER DEFAULT PRIVILEGES REVOKE GRANT OPTION FOR EXECUTE ON FUNCTIONS FROM PUBLIC",
	} {
		t.Run(sql, func(t *testing.T) {
			if out := reparseSQL(t, sql, pg); out != sql {
				t.Errorf("SQL() = %q, want %q", out, sql)
			}
		})
	}
	runShapeCases(t, []shapeCase{
		{"then drop on next line", pg, "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO u\nDROP TABLE t",
			"error: semicolon or end of statement"},
		{"then drop on same line", pg, "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO u DROP TABLE t",
			"error: semicolon or end of statement"},
		{"no grant", pg, "ALTER DEFAULT PRIVILEGES IN SCHEMA s", "error: GRANT or REVOKE"},
		{"mysql has none", keywords.DialectMySQL, "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO u", "error: "},
	})
}

// MySQL assigns with := inside an expression only to a user variable;
// PostgreSQL's f(a := 1) is a named argument.
func TestParser_AssignmentOperatorPlaces(t *testing.T) {
	my := keywords.DialectMySQL
	runShapeCases(t, []shapeCase{
		{"function argument", my, "SELECT f(a := 1)", "error: "},
		{"subscript", my, "SELECT arr[1:=2] FROM t", "error: "},
		{"column target", my, "SELECT a := 1 FROM t", "error: "},
		{"system variable", my, "SELECT @@x := 1", "error: "},
		{"placeholder", my, "SELECT ? := 1", "error: "},
		{"mariadb function argument", keywords.DialectMariaDB, "SELECT f(a := 1)", "error: "},
		{"set", my, "SET @v := 1", "[Set]"},
		{"select item", my, "SELECT @v := a + 1 FROM t", "[Select]"},
		{"where", my, "SELECT 1 FROM t WHERE (@a := 1) > 0", "[Select]"},
		{"pg named argument", keywords.DialectPostgreSQL, "SELECT f(a := 1, b => 2)", "[Select]"},
		{"generic named argument", keywords.DialectGeneric, "SELECT f(a := 1)", "[Select]"},
	})
	for _, tc := range []struct {
		sql     string
		dialect keywords.SQLDialect
		want    string
	}{
		{"SELECT @rownum := @rownum + 1 AS rn FROM t, (SELECT @rownum := 0) r", my,
			"SELECT @rownum := @rownum + 1 AS rn FROM t, (SELECT @rownum := 0) r"},
		// := is written back as the equivalent =>.
		{"SELECT make_interval(days := 7)", keywords.DialectPostgreSQL, "SELECT make_interval(days => 7)"},
	} {
		if out := reparseSQL(t, tc.sql, tc.dialect); out != tc.want {
			t.Errorf("SQL() = %q, want %q", out, tc.want)
		}
	}
}

// MariaDB's DELETE HISTORY FROM t deletes the history of a system-versioned
// table: DELETE history FROM history is that statement on the table
// history, and a delimited `history` target stays a multi-table delete
// when it is written back.
func TestParser_DeleteHistoryTarget(t *testing.T) {
	maria := keywords.DialectMariaDB
	for _, tc := range []struct {
		sql, want string
		history   bool
	}{
		{"DELETE history FROM history", "DELETE HISTORY FROM history", true},
		{"DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2024-01-01'", "DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2024-01-01'", true},
		{"DELETE `history` FROM history", "DELETE `history` FROM history", false},
		{"DELETE `history` FROM history JOIN t ON t.id = history.id",
			"DELETE `history` FROM history INNER JOIN t ON t.id = history.id", false},
		{"DELETE h FROM history h", "DELETE h FROM history h", false},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			if out := reparseSQL(t, tc.sql, maria); out != tc.want {
				t.Errorf("SQL() = %q, want %q", out, tc.want)
			}
			tree, err := ParseWithDialect(tc.sql, maria)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			del, ok := tree.Statements[0].(*ast.DeleteStatement)
			if !ok {
				t.Fatalf("got %T", tree.Statements[0])
			}
			history := false
			if x := del.Extras; x != nil {
				for _, m := range x.Modifiers {
					history = history || m == "HISTORY"
				}
			}
			if history != tc.history {
				t.Errorf("HISTORY modifier = %v, want %v", history, tc.history)
			}
		})
	}
}

// tsqlElseIfChain builds IF ... ELSE IF ... ELSE ... with n branches,
// followed by another statement.
func tsqlElseIfChain(n int) string {
	var sb strings.Builder
	sb.WriteString("IF @x = 0 SELECT 0\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&sb, "ELSE IF @x = %d SELECT %d\n", i, i)
	}
	sb.WriteString("ELSE SELECT -1\nSELECT 99")
	return sb.String()
}

// A T-SQL ELSE IF chain is one statement however long it is: it is parsed
// branch by branch, not by recursion, so it neither hits the recursion
// limit nor falls back to the verbatim scan that swallowed the next
// statement, and its cost is linear.
func TestParser_TSQLElseIfChain(t *testing.T) {
	for _, n := range []int{1, 2, 150, 10000} {
		tree, err := ParseWithDialect(tsqlElseIfChain(n), keywords.DialectSQLServer)
		if err != nil {
			t.Fatalf("%d branches: %v", n, err)
		}
		if got := fmt.Sprint(stmtShapes(tree)); got != "[Utility(IF) Select]" {
			t.Errorf("%d branches: %s", n, got)
		}
		ast.ReleaseAST(tree)
	}

	// IF ... ; ELSE IF ...: a ';' may close each branch.
	tree, err := ParseWithDialect("IF @x = 1 SELECT 1; ELSE IF @x = 2 SELECT 2; ELSE SELECT 3\nSELECT 4",
		keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(stmtShapes(tree)); got != "[Utility(IF) Select]" {
		t.Errorf("chain with semicolons: %s", got)
	}
	ast.ReleaseAST(tree)

	if testing.Short() {
		return
	}
	measure := func(n int) time.Duration {
		sql := tsqlElseIfChain(n)
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			tree, err := ParseWithDialect(sql, keywords.DialectSQLServer)
			d := time.Since(start)
			if err != nil {
				t.Fatalf("%d branches: %v", n, err)
			}
			ast.ReleaseAST(tree)
			if d < best {
				best = d
			}
		}
		return best
	}
	small, large := measure(2500), measure(10000)
	if ratio := float64(large) / float64(small); ratio > 10 {
		t.Errorf("4x the branches took %.1fx the time (%v vs %v), want linear", ratio, large, small)
	}
}

// A line holding only GO ends the batch wherever it appears in SQL Server,
// also inside a block, a CTE or a subquery, and on every parse entry point.
func TestParser_GOLineInsideNestedConstructs(t *testing.T) {
	tests := []struct {
		name, sql string
	}{
		{"begin end block", "BEGIN\nSELECT 1\nGO\nEND"},
		{"cte", "WITH c AS (\nSELECT 1 AS a\nGO\n) SELECT a FROM c"},
		{"subquery", "SELECT * FROM (SELECT 1 AS a\nGO\n) x"},
		{"in list subquery", "SELECT 1 WHERE 1 IN (SELECT 1\nGO\n)"},
	}
	tokenize := func(t *testing.T, sql string) []models.TokenWithSpan {
		t.Helper()
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		tkz.SetDialect(keywords.DialectSQLServer)
		tokens, err := tkz.TokenizeString(sql)
		if err != nil {
			t.Fatal(err)
		}
		return tokens
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tree, err := ParseWithDialect(tc.sql, keywords.DialectSQLServer); err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("parse: no error")
			} else if !strings.Contains(err.Error(), "GO") {
				t.Fatalf("parse: error = %v, want a GO error", err)
			}

			// The context-aware path reports the same error.
			p := NewParser(WithDialect("sqlserver"))
			defer p.Release()
			tree, err := p.ParseContextFromModelTokens(context.Background(), tokenize(t, tc.sql))
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("ParseContextFromModelTokens: no error")
			}
			if !strings.Contains(err.Error(), "GO") {
				t.Fatalf("ParseContextFromModelTokens: error = %v, want a GO error", err)
			}
		})
	}
}

// A statement that ran across a GO line and failed is reported by
// ParseWithRecovery, which resumes at the batch boundary.
func TestParser_RecoveryAfterFailedStatementWithGOLine(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectSQLServer)
	tokens, err := tkz.TokenizeString("SELECT a FROM t WHERE a IN (1,\nGO\nSELECT 2\nGO\nSELECT 3")
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithDialect("sqlserver"))
	defer p.Release()
	stmts, errs := p.ParseWithRecoveryFromModelTokens(tokens)
	tree := &ast.AST{Statements: stmts}
	defer ast.ReleaseAST(tree)
	if len(errs) == 0 {
		t.Fatal("expected an error for the statement that ran across GO")
	}
	got := fmt.Sprint(stmtShapes(tree))
	if !strings.HasSuffix(got, "Select BatchSeparator Select]") {
		t.Fatalf("recovery shapes = %s, want the batches after the GO line", got)
	}
}

// Review follow-ups: forms main accepted that the statement grammars must
// keep accepting, and same-line statements after option lists.
func TestParser_UtilityGrammarReviewCases(t *testing.T) {
	const missingSemi = "error: end of statement"
	pg, my, gen := keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectGeneric
	snow, ch := keywords.DialectSnowflake, keywords.DialectClickHouse
	runShapeCases(t, []shapeCase{
		// COPY file names and old option spellings
		{"copy escape string", pg, "COPY t FROM E'/x'", "[Utility(COPY)]"},
		{"copy dollar string", pg, "COPY t FROM $$/x$$", "[Utility(COPY)]"},
		{"copy using delimiters", pg, "COPY t FROM STDIN USING DELIMITERS ','", "[Utility(COPY)]"},
		{"copy with delimiters", pg, "COPY t FROM STDIN WITH DELIMITERS ','", "[Utility(COPY)]"},
		{"generic copy legacy", gen, "COPY t FROM '/x' WITH DELIMITER AS ','", "[Utility(COPY)]"},
		{"generic copy then drop", gen, "COPY t FROM '/x' DROP TABLE t", missingSemi},
		{"generic copy redshift options", gen, "COPY t FROM 's3://b/x' IAM_ROLE 'arn' FORMAT AS PARQUET", "[Utility(COPY)]"},
		{"redshift copy options", keywords.DialectRedshift, "COPY t FROM 's3://b/x' IAM_ROLE 'arn' CSV", "[Utility(COPY)]"},
		// BigQuery LOAD DATA
		{"bigquery load into", keywords.DialectBigQuery, "LOAD DATA INTO t FROM FILES (format='CSV', uris=['gs://x'])",
			"[Utility(LOAD)]"},
		{"bigquery load overwrite", keywords.DialectBigQuery, "LOAD DATA OVERWRITE t FROM FILES (format='CSV')",
			"[Utility(LOAD)]"},
		// GRANT grantees and options
		{"mysql current_user()", my, "GRANT ALL ON db.* TO CURRENT_USER()", "[Utility(GRANT)]"},
		{"mysql require x509", my, "GRANT SELECT ON db.t TO u REQUIRE X509 WITH GRANT OPTION", "[Utility(GRANT)]"},
		{"mysql grant option then limit", my, "GRANT SELECT ON db.t TO u WITH GRANT OPTION MAX_QUERIES_PER_HOUR 1",
			"[Utility(GRANT)]"},
		{"mysql random password", my, "GRANT SELECT ON mysql.* TO u IDENTIFIED BY RANDOM PASSWORD", "[Utility(GRANT)]"},
		{"mariadb identified via", keywords.DialectMariaDB,
			"GRANT SELECT ON db.t TO 'u'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('x') OR unix_socket", "[Utility(GRANT)]"},
		{"snowflake application", snow, "GRANT USAGE ON DATABASE d TO APPLICATION a", "[Utility(GRANT)]"},
		{"snowflake identifier()", snow, "GRANT SELECT ON TABLE db.sc.t TO ROLE IDENTIFIER('r')", "[Utility(GRANT)]"},
		{"bracket grantee generic", gen, "GRANT SELECT ON dbo.Customers TO [AppUser]", "[Utility(GRANT)]"},
		{"bracket grantee mysql", my, "GRANT SELECT ON [dbo].[t] TO [u]", "[Utility(GRANT)]"},
		{"bracket grantee then drop", pg, "GRANT SELECT ON [dbo].[t] TO [u] DROP TABLE t", missingSemi},
		// Same-line statements after option lists
		{"load data then select", my, "LOAD DATA INFILE '/x' INTO TABLE t SELECT 2", missingSemi},
		{"load data columns then select", my, "LOAD DATA INFILE '/x' INTO TABLE t (a,b) SELECT 2", missingSemi},
		{"load data set then select", my, "LOAD DATA INFILE '/x' INTO TABLE t SET a = 1 SELECT 2", missingSemi},
		{"load data ignore lines then select", my, "LOAD DATA INFILE '/x' INTO TABLE t IGNORE 1 LINES SELECT 2", missingSemi},
		{"load data replace", my,
			"LOAD DATA INFILE '/x' REPLACE INTO TABLE t CHARACTER SET utf8 IGNORE 1 LINES (a, @b) SET b = @b",
			"[Utility(LOAD)]"},
		{"pg function then select", pg, "CREATE FUNCTION f() RETURNS int AS $$ select 1 $$ LANGUAGE sql SELECT 2", missingSemi},
		{"pg procedure then select", pg, "CREATE PROCEDURE p() LANGUAGE sql AS $$ select 1 $$ SELECT 2", missingSemi},
		{"pg event trigger then select", pg, "CREATE EVENT TRIGGER et ON ddl_command_start EXECUTE FUNCTION f() SELECT 2",
			missingSemi},
		{"pg event trigger", pg,
			"CREATE EVENT TRIGGER et ON ddl_command_start WHEN TAG IN ('DROP TABLE') EXECUTE FUNCTION f()",
			"[Utility(CREATE EVENT TRIGGER)]"},
		{"pg policy with check", pg, "CREATE POLICY p ON t FOR UPDATE USING (a = 1) WITH CHECK (b = 2)",
			"[Utility(CREATE POLICY)]"},
		{"snowflake function then select", snow, "CREATE FUNCTION f() RETURNS INT AS 'select 1' SELECT 2", missingSemi},
		{"snowflake stream then select", snow, "CREATE STREAM s ON TABLE t SELECT 2", missingSemi},
		{"snowflake pipe then select", snow, "CREATE PIPE p AUTO_INGEST = TRUE AS COPY INTO t FROM @s\nSELECT 2", missingSemi},
		{"snowflake pipe", snow, "CREATE PIPE p AS COPY INTO t FROM @s FILE_FORMAT = (TYPE = 'CSV')",
			"[Utility(CREATE PIPE)]"},
		{"snowflake alert then select", snow,
			"CREATE ALERT a WAREHOUSE = w SCHEDULE = '1 minute' IF (EXISTS (SELECT 1 FROM t)) THEN CALL p()\nSELECT 2",
			missingSemi},
		{"snowflake execute as caller", snow,
			"CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER AS $$ BEGIN RETURN 1; END $$",
			"[Utility(CREATE PROCEDURE)]"},
		{"clickhouse function then select", ch, "CREATE FUNCTION f AS (x) -> x + 1 SELECT 2", missingSemi},
		{"clickhouse function then select line", ch, "CREATE FUNCTION f AS (x) -> x + 1\nSELECT 2", missingSemi},
		{"bigquery row access policy", keywords.DialectBigQuery,
			"CREATE ROW ACCESS POLICY p ON t GRANT TO ('x') FILTER USING (true)", "[Utility(CREATE ROW)]"},
		// Oracle-style routines: accepted without a dialect, not in
		// PostgreSQL or MySQL.
		{"generic plsql procedure", gen, "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END p;", "[Utility(CREATE PROCEDURE)]"},
		{"generic java function", gen, "CREATE FUNCTION f RETURN NUMBER AS LANGUAGE JAVA NAME 'X.f() return int'",
			"[Utility(CREATE FUNCTION)]"},
		{"pg plsql procedure", pg, "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END p;", missingSemi},
		{"pg named argument needs a name", pg, "SELECT f(select := 1)", "error: "},
	})
}
