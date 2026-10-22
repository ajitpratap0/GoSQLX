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
	"testing"
)

func TestSplitStatements_Procedural(t *testing.T) {
	mysqlRoutine := `CREATE PROCEDURE p(IN n INT)
BEGIN
  DECLARE i INT DEFAULT 0;
  IF n > 0 THEN
    SET i = 1;
  ELSEIF n < 0 THEN
    SET i = 2;
  ELSE
    SET i = 3;
  END IF;
  WHILE i < 10 DO
    SET i = i + 1;
  END WHILE;
  REPEAT SET i = i - 1; UNTIL i < 5 END REPEAT;
  lbl: LOOP SET i = i + 1; LEAVE lbl; END LOOP lbl;
  CASE i WHEN 1 THEN SELECT 1; ELSE SELECT 2; END CASE;
END`

	cases := []struct {
		name    string
		sql     string
		dialect string
		want    []string
	}{
		// --- T-SQL ---
		{"tsql if-begin-end", "IF 1 = 1 BEGIN SELECT 1; SELECT 2; END; SELECT 3;", "sqlserver",
			[]string{"IF 1 = 1 BEGIN SELECT 1; SELECT 2; END", " SELECT 3"}},
		{"tsql proc", "CREATE PROCEDURE p AS BEGIN SET NOCOUNT ON; SELECT 1; END; SELECT 2", "mssql",
			[]string{"CREATE PROCEDURE p AS BEGIN SET NOCOUNT ON; SELECT 1; END", " SELECT 2"}},
		{"tsql try catch", "BEGIN TRY SELECT 1/0; END TRY BEGIN CATCH SELECT 2; END CATCH; SELECT 3", "tsql",
			[]string{"BEGIN TRY SELECT 1/0; END TRY BEGIN CATCH SELECT 2; END CATCH", " SELECT 3"}},
		{"tsql begin transaction", "BEGIN TRANSACTION; UPDATE t SET a = 1; COMMIT TRANSACTION", "sqlserver",
			[]string{"BEGIN TRANSACTION", " UPDATE t SET a = 1", " COMMIT TRANSACTION"}},
		{"tsql begin tran in proc", "CREATE PROC p AS BEGIN BEGIN TRAN; UPDATE t SET a = 1; COMMIT; END; SELECT 1", "sqlserver",
			[]string{"CREATE PROC p AS BEGIN BEGIN TRAN; UPDATE t SET a = 1; COMMIT; END", " SELECT 1"}},
		{"tsql end then if without semicolon", "IF @a = 1 BEGIN SELECT 1; END IF @b = 1 BEGIN SELECT 2; END; SELECT 3", "sqlserver",
			[]string{"IF @a = 1 BEGIN SELECT 1; END IF @b = 1 BEGIN SELECT 2; END", " SELECT 3"}},
		{"tsql while with begin", "WHILE @i < 3 BEGIN SET @i += 1; END; SELECT 1", "sqlserver",
			[]string{"WHILE @i < 3 BEGIN SET @i += 1; END", " SELECT 1"}},
		{"tsql loop join hint is not a loop", "CREATE PROC p AS BEGIN SELECT * FROM a INNER LOOP JOIN b ON a.x = b.x; SELECT 2; END; SELECT 3", "sqlserver",
			[]string{"CREATE PROC p AS BEGIN SELECT * FROM a INNER LOOP JOIN b ON a.x = b.x; SELECT 2; END", " SELECT 3"}},

		// --- GO batches ---
		{"go basic", "SELECT 1\nGO\nSELECT 2\nGO", "sqlserver", []string{"SELECT 1\n", "SELECT 2\n"}},
		{"go crlf", "SELECT 1\r\nGO\r\nSELECT 2\r\n", "sqlserver", []string{"SELECT 1\r\n", "SELECT 2\r\n"}},
		{"go lowercase with count", "SELECT 1\ngo 5\nSELECT 2", "sqlserver", []string{"SELECT 1\n", "SELECT 2"}},
		{"go with trailing comment", "SELECT 1\nGO -- batch\nSELECT 2", "sqlserver", []string{"SELECT 1\n", "SELECT 2"}},
		{"go indented", "SELECT 1\n   GO  \nSELECT 2", "sqlserver", []string{"SELECT 1\n", "SELECT 2"}},
		{"go after semicolon", "SELECT 1;\nGO\nSELECT 2;", "sqlserver", []string{"SELECT 1", "SELECT 2"}},
		{"go resets unbalanced block", "BEGIN SELECT 1;\nGO\nSELECT 2;\nGO\n", "sqlserver", []string{"BEGIN SELECT 1;\n", "SELECT 2"}},
		{"go not alone on line", "SELECT 1 GO\nSELECT 2", "sqlserver", []string{"SELECT 1 GO\nSELECT 2"}},
		{"go inside string", "SELECT '\nGO\n'; SELECT 2", "sqlserver", []string{"SELECT '\nGO\n'", " SELECT 2"}},
		{"go inside comment", "/*\nGO\n*/ SELECT 1", "sqlserver", []string{"/*\nGO\n*/ SELECT 1"}},
		{"go identifier prefix", "SELECT 1\nGOTO x", "sqlserver", []string{"SELECT 1\nGOTO x"}},
		{"go after byte order mark", "\uFEFFGO\nSELECT 2", "sqlserver", []string{"SELECT 2"}},
		{"go ignored for other dialects", "SELECT 1\nGO\nSELECT 2", "postgresql", []string{"SELECT 1\nGO\nSELECT 2"}},

		// --- Triggers and transactions elsewhere ---
		{"sqlite trigger", "CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE u SET n = 1; END;", "sqlite",
			[]string{"CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE u SET n = 1; END"}},
		{"sqlite trigger with case and two statements",
			"CREATE TRIGGER tr AFTER INSERT ON t WHEN NEW.a > 0 BEGIN UPDATE u SET n = CASE WHEN NEW.a > 1 THEN 1 ELSE 2 END; DELETE FROM v; END; SELECT 1", "sqlite",
			[]string{"CREATE TRIGGER tr AFTER INSERT ON t WHEN NEW.a > 0 BEGIN UPDATE u SET n = CASE WHEN NEW.a > 1 THEN 1 ELSE 2 END; DELETE FROM v; END", " SELECT 1"}},
		{"sqlite transactions", "BEGIN; INSERT INTO t VALUES (1); COMMIT; BEGIN IMMEDIATE; ROLLBACK; BEGIN DEFERRED TRANSACTION; END", "sqlite",
			[]string{"BEGIN", " INSERT INTO t VALUES (1)", " COMMIT", " BEGIN IMMEDIATE", " ROLLBACK", " BEGIN DEFERRED TRANSACTION", " END"}},
		{"pg transactions", "BEGIN; SELECT 1; END; BEGIN ISOLATION LEVEL SERIALIZABLE; BEGIN READ ONLY; BEGIN NOT DEFERRABLE; SELECT 2", "postgresql",
			[]string{"BEGIN", " SELECT 1", " END", " BEGIN ISOLATION LEVEL SERIALIZABLE", " BEGIN READ ONLY", " BEGIN NOT DEFERRABLE", " SELECT 2"}},
		{"pg begin atomic", "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END; SELECT 3", "postgresql",
			[]string{"CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END", " SELECT 3"}},
		{"pg dollar body stays opaque", "DO $$ BEGIN PERFORM 1; END $$; SELECT 1", "postgresql",
			[]string{"DO $$ BEGIN PERFORM 1; END $$", " SELECT 1"}},
		{"begin as column name", "SELECT begin FROM t; SELECT 2", "postgresql", []string{"SELECT begin FROM t", " SELECT 2"}},
		{"begin as list item", "SELECT a, begin, b FROM t; SELECT 2", "mysql", []string{"SELECT a, begin, b FROM t", " SELECT 2"}},
		{"qualified begin", "SELECT t.begin, @begin FROM t; SELECT 2", "sqlserver", []string{"SELECT t.begin, @begin FROM t", " SELECT 2"}},
		{"case expression at top level", "SELECT CASE WHEN a THEN 1 END; SELECT 2", "", []string{"SELECT CASE WHEN a THEN 1 END", " SELECT 2"}},
		{"stray end at top level", "END; SELECT 1", "postgresql", []string{"END", " SELECT 1"}},
		{"begin column in create table", "CREATE TABLE t (begin INT, x INT); INSERT INTO t VALUES (1, 2); UPDATE t SET end = 1; SELECT 3", "mysql",
			[]string{"CREATE TABLE t (begin INT, x INT)", " INSERT INTO t VALUES (1, 2)", " UPDATE t SET end = 1", " SELECT 3"}},
		{"begin column added by alter table", "ALTER TABLE t ADD COLUMN begin int; SELECT 1; SELECT y FROM t ORDER BY end; SELECT 2", "postgresql",
			[]string{"ALTER TABLE t ADD COLUMN begin int", " SELECT 1", " SELECT y FROM t ORDER BY end", " SELECT 2"}},
		{"begin column modified", "ALTER TABLE t MODIFY begin TIME NOT NULL; SELECT end FROM t; SELECT 2", "mysql",
			[]string{"ALTER TABLE t MODIFY begin TIME NOT NULL", " SELECT end FROM t", " SELECT 2"}},

		// --- MySQL / MariaDB routines ---
		{"mysql routine without delimiter", mysqlRoutine + ";\nSELECT 9", "mysql", []string{mysqlRoutine, "\nSELECT 9"}},
		{"mysql drop if exists inside body", "CREATE PROCEDURE p() BEGIN DROP TABLE IF EXISTS x; CREATE TABLE IF NOT EXISTS y (a INT); END; SELECT 1", "mariadb",
			[]string{"CREATE PROCEDURE p() BEGIN DROP TABLE IF EXISTS x; CREATE TABLE IF NOT EXISTS y (a INT); END", " SELECT 1"}},
		{"mysql if function in body", "CREATE PROCEDURE p() BEGIN SELECT IF(a, 1, 2) FROM t; SELECT 2; END; SELECT 3", "mysql",
			[]string{"CREATE PROCEDURE p() BEGIN SELECT IF(a, 1, 2) FROM t; SELECT 2; END", " SELECT 3"}},
		{"mariadb begin not atomic", "BEGIN NOT ATOMIC SELECT 1; SELECT 2; END; SELECT 3", "mariadb",
			[]string{"BEGIN NOT ATOMIC SELECT 1; SELECT 2; END", " SELECT 3"}},

		// --- Generic PL-style bodies ---
		{"for loop", "CREATE PROCEDURE p() BEGIN FOR r IN 1..3 LOOP INSERT INTO t VALUES (r); END LOOP; END; SELECT 1", "",
			[]string{"CREATE PROCEDURE p() BEGIN FOR r IN 1..3 LOOP INSERT INTO t VALUES (r); END LOOP; END", " SELECT 1"}},
		{"nested blocks", "BEGIN BEGIN SELECT 1; END; SELECT 2; END; SELECT 3", "",
			[]string{"BEGIN BEGIN SELECT 1; END; SELECT 2; END", " SELECT 3"}},
		{"keywords in comments and strings", "BEGIN SELECT 'END;'; -- END;\n/* END; */ SELECT 2; END; SELECT 3", "",
			[]string{"BEGIN SELECT 'END;'; -- END;\n/* END; */ SELECT 2; END", " SELECT 3"}},
		{"unbalanced begin falls back to plain splitting", "CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2", "mysql",
			[]string{"CREATE PROCEDURE p() BEGIN SELECT 1", " SELECT 2"}},
		{"unbalanced case falls back", "CREATE PROCEDURE p() BEGIN SELECT CASE WHEN a THEN 1; SELECT 2; END; SELECT 3", "",
			[]string{"CREATE PROCEDURE p() BEGIN SELECT CASE WHEN a THEN 1", " SELECT 2", " END", " SELECT 3"}},

		// --- MySQL DELIMITER ---
		{"delimiter procedure", "SELECT 1;\nDELIMITER //\nCREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND//\nDELIMITER ;\nSELECT 3;", "mysql",
			[]string{"SELECT 1", "CREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND", "SELECT 3"}},
		{"delimiter dollar", "DELIMITER $$\nCREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET NEW.a = 1; $$\nDELIMITER ;\n", "mariadb",
			[]string{"CREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW SET NEW.a = 1; "}},
		{"delimiter lowercase and double semicolon", "delimiter ;;\nSELECT 1; SELECT 2;;\nDELIMITER ;\nSELECT 3", "mysql",
			[]string{"SELECT 1; SELECT 2", "SELECT 3"}},
		{"delimiter ignored for postgres", "DELIMITER //\nSELECT 1", "postgresql", []string{"DELIMITER //\nSELECT 1"}},
		{"delimiter as column name", "SELECT delimiter\nFROM t; SELECT 1", "mysql", []string{"SELECT delimiter\nFROM t", " SELECT 1"}},

		// --- Oracle ---
		{"oracle anonymous block", "DECLARE v NUMBER; w NUMBER; BEGIN v := 1; w := 2; END; SELECT 1 FROM dual", "oracle",
			[]string{"DECLARE v NUMBER; w NUMBER; BEGIN v := 1; w := 2; END", " SELECT 1 FROM dual"}},
		{"oracle bare begin block", "BEGIN NULL; NULL; END;\nSELECT 1 FROM dual", "oracle",
			[]string{"BEGIN NULL; NULL; END", "\nSELECT 1 FROM dual"}},
		{"oracle procedure is", "CREATE OR REPLACE PROCEDURE p IS v NUMBER; BEGIN v := 1; IF v = 1 THEN v := 2; END IF; END p; SELECT 1 FROM dual", "oracle",
			[]string{"CREATE OR REPLACE PROCEDURE p IS v NUMBER; BEGIN v := 1; IF v = 1 THEN v := 2; END IF; END p", " SELECT 1 FROM dual"}},
		{"oracle function with cursor is", "CREATE FUNCTION f RETURN NUMBER AS CURSOR c IS SELECT 1 FROM dual; v NUMBER; BEGIN OPEN c; RETURN 1; END f; SELECT 2 FROM dual", "oracle",
			[]string{"CREATE FUNCTION f RETURN NUMBER AS CURSOR c IS SELECT 1 FROM dual; v NUMBER; BEGIN OPEN c; RETURN 1; END f", " SELECT 2 FROM dual"}},
		{"oracle package", "CREATE PACKAGE pk AS PROCEDURE a; FUNCTION b RETURN NUMBER; END pk; CREATE PACKAGE BODY pk AS PROCEDURE a IS BEGIN NULL; END a; FUNCTION b RETURN NUMBER IS BEGIN RETURN 1; END b; END pk; SELECT 1 FROM dual", "oracle",
			[]string{"CREATE PACKAGE pk AS PROCEDURE a; FUNCTION b RETURN NUMBER; END pk", " CREATE PACKAGE BODY pk AS PROCEDURE a IS BEGIN NULL; END a; FUNCTION b RETURN NUMBER IS BEGIN RETURN 1; END b; END pk", " SELECT 1 FROM dual"}},
		{"oracle trigger with declare", "CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW DECLARE x NUMBER; BEGIN x := 1; END; SELECT 1 FROM dual", "oracle",
			[]string{"CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW DECLARE x NUMBER; BEGIN x := 1; END", " SELECT 1 FROM dual"}},
		{"oracle call spec has no body", "CREATE FUNCTION f RETURN NUMBER AS LANGUAGE JAVA NAME 'X.f() return int'; SELECT 1 FROM dual", "oracle",
			[]string{"CREATE FUNCTION f RETURN NUMBER AS LANGUAGE JAVA NAME 'X.f() return int'", " SELECT 1 FROM dual"}},
		{"oracle create view as", "CREATE VIEW v AS SELECT 1 FROM dual; SELECT 2 FROM dual", "oracle",
			[]string{"CREATE VIEW v AS SELECT 1 FROM dual", " SELECT 2 FROM dual"}},
		{"oracle slash terminator", "SELECT 1 FROM dual\n/\nSELECT 2 FROM dual\n/\n", "oracle",
			[]string{"SELECT 1 FROM dual\n", "SELECT 2 FROM dual\n"}},
		{"oracle slash after block", "BEGIN\n  NULL;\nEND;\n/\nSELECT 3 FROM dual;", "oracle",
			[]string{"BEGIN\n  NULL;\nEND", "SELECT 3 FROM dual"}},
		{"oracle slash division", "SELECT 1\n/ 2 FROM dual; SELECT 2", "oracle", []string{"SELECT 1\n/ 2 FROM dual", " SELECT 2"}},
		{"slash ignored for other dialects", "SELECT 1\n/\nSELECT 2", "postgresql", []string{"SELECT 1\n/\nSELECT 2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitStatements(tc.sql, tc.dialect)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SplitStatements(%q, %q)\n got  %q\n want %q", tc.sql, tc.dialect, got, tc.want)
			}
		})
	}
}

// TestSplitStatements_ProceduralNoAlloc guards the "single allocation"
// contract of the splitter for scripts that contain blocks.
func TestSplitStatements_ProceduralNoAlloc(t *testing.T) {
	src := "CREATE TRIGGER tr AFTER INSERT ON t BEGIN UPDATE u SET n = CASE WHEN a THEN 1 END; END; SELECT 1; BEGIN; COMMIT;"
	for _, d := range []string{"", "sqlite", "sqlserver", "oracle", "mysql"} {
		n := testing.AllocsPerRun(50, func() { _ = SplitStatements(src, d) })
		if n > 1 {
			t.Errorf("dialect %q: %v allocations, want at most 1", d, n)
		}
	}
}

func TestCommentsOnly(t *testing.T) {
	for in, want := range map[string]bool{
		"":                     true,
		"  \n\t":               true,
		"-- c":                 true,
		"-- c\n/* d */ -- e\n": true,
		"/* unterminated":      true,
		"SELECT 1":             false,
		"-- c\nSELECT 1":       false,
		"/* c */ SELECT 1":     false,
		"/* c */ ; -- d":       false,
		"(":                    false,
	} {
		if got := commentsOnly(in); got != want {
			t.Errorf("commentsOnly(%q) = %v, want %v", in, got, want)
		}
	}
}
