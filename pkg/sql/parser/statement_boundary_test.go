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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// stmtShapes describes each statement as its type name without the package
// prefix and "Statement" suffix; a UtilityStatement adds its Kind:
// [Set Select Utility(IF)].
func stmtShapes(tree *ast.AST) []string {
	out := make([]string, len(tree.Statements))
	for i, s := range tree.Statements {
		name := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%T", s), "*ast."), "Statement")
		if u, ok := s.(*ast.UtilityStatement); ok {
			name += "(" + u.Kind + ")"
		}
		out[i] = name
	}
	return out
}

// Scripts written without semicolons: T-SQL batches end each statement
// where the next one starts; other dialects accept only a transaction
// statement on a line of its own.
func TestParser_ScriptsWithoutSemicolons(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		// (a) A utility statement after a DML statement that ended implicitly.
		{"transaction around update", keywords.DialectSQLServer,
			"BEGIN TRANSACTION\nUPDATE t SET a = 1 WHERE id = 2\nCOMMIT",
			"[Transaction Update Transaction]"},
		{"set around select", keywords.DialectSQLServer,
			"SET NOCOUNT ON\nSELECT 1\nSET NOCOUNT OFF", "[Set Select Set]"},
		{"print after select", keywords.DialectSQLServer,
			"SELECT a FROM t\nPRINT 'done'", "[Select Utility(PRINT)]"},
		{"print after where", keywords.DialectSQLServer,
			"SELECT a FROM t WHERE x = 1 PRINT 'done'", "[Select Utility(PRINT)]"},
		{"set variable after insert", keywords.DialectSQLServer,
			"INSERT INTO t (a) VALUES (1)\nSET @x = 2", "[Insert Set]"},
		{"commit after delete", keywords.DialectSQLServer,
			"DELETE FROM t WHERE a = 1\nCOMMIT TRANSACTION", "[Delete Transaction]"},
		{"exec after select", keywords.DialectSQLServer,
			"SELECT 1\nEXEC dbo.p 1", "[Select Utility(EXEC)]"},
		{"declare after update from", keywords.DialectSQLServer,
			"UPDATE t SET a = 1 FROM t JOIN u ON u.id = t.id\nDECLARE @x INT", "[Update Utility(DECLARE)]"},
		{"cte query then select", keywords.DialectSQLServer,
			"WITH c AS (SELECT 1 AS a) SELECT a FROM c\nSELECT 2", "[Select Select]"},
		{"begin tran inside script", keywords.DialectSQLServer,
			"SELECT 1\nBEGIN TRAN\nSELECT 2\nCOMMIT", "[Select Transaction Select Transaction]"},
		{"go separates batches", keywords.DialectSQLServer,
			"SELECT 1\nGO\nSELECT 2\nGO 3\nPRINT 'x'", "[Select BatchSeparator Select BatchSeparator Utility(PRINT)]"},
		{"go after a utility statement", keywords.DialectSQLServer,
			"USE db\nGO\nSET NOCOUNT ON\nGO", "[Use BatchSeparator Set BatchSeparator]"},
		{"deny then select", keywords.DialectSQLServer,
			"DENY DELETE ON t TO r\nSELECT 1", "[Utility(DENY) Select]"},
		{"grant ends after its principal", keywords.DialectSQLServer,
			"GRANT SELECT, INSERT ON t TO r\nREVOKE UPDATE ON t FROM r\nSELECT 1",
			"[Utility(GRANT) Utility(REVOKE) Select]"},
		{"grant with grant option", keywords.DialectSQLServer,
			"GRANT EXECUTE ON SCHEMA::dbo TO r WITH GRANT OPTION\nSELECT 1", "[Utility(GRANT) Select]"},

		// (b) Table variables.
		{"table variable dml", keywords.DialectSQLServer,
			"DECLARE @t TABLE (id INT)\nINSERT INTO @t (id) VALUES (1)\nUPDATE @t SET id = 2\nDELETE FROM @t WHERE id = 2\nSELECT * FROM @t",
			"[Utility(DECLARE) Insert Update Delete Select]"},
		{"table variable alias and join", keywords.DialectSQLServer,
			"SELECT * FROM @t AS x JOIN dbo.u ON u.id = x.id JOIN @v v ON v.id = x.id", "[Select]"},
		{"table variable merge target", keywords.DialectSQLServer,
			"MERGE INTO @t AS tgt USING src ON tgt.id = src.id WHEN MATCHED THEN UPDATE SET id = src.id;", "[Merge]"},

		// (c) Verbatim DDL and ALTER TABLE text actions.
		{"create schema keeps its elements", keywords.DialectSQLServer,
			"CREATE SCHEMA s\nCREATE TABLE t (a INT)", "[Utility(CREATE SCHEMA)]"},
		{"create schema then select", keywords.DialectSQLServer,
			"CREATE SCHEMA s AUTHORIZATION dbo\nSELECT 1", "[Utility(CREATE SCHEMA) Select]"},
		{"alter table nocheck then alter table", keywords.DialectSQLServer,
			"ALTER TABLE t NOCHECK CONSTRAINT ALL\nALTER TABLE u ADD c INT", "[Alter Alter]"},
		{"alter database set then select", keywords.DialectSQLServer,
			"ALTER DATABASE db SET RECOVERY SIMPLE\nSELECT 1", "[Utility(ALTER DATABASE) Select]"},
		{"ddl script", keywords.DialectSQLServer,
			"CREATE TABLE t (a INT)\nCREATE INDEX ix ON t (a)\nDROP TABLE t", "[CreateTable CreateIndex Drop]"},
		{"drop if exists then create", keywords.DialectSQLServer,
			"DROP TABLE IF EXISTS t\nCREATE TABLE t (a INT)", "[Drop CreateTable]"},

		// IF / WHILE bodies.
		{"if without block then create", keywords.DialectSQLServer,
			"IF OBJECT_ID(N'dbo.t') IS NOT NULL DROP TABLE dbo.t\nCREATE TABLE dbo.t (a INT)",
			"[Utility(IF) CreateTable]"},
		{"if else then select", keywords.DialectSQLServer,
			"IF @x = 1\n  SELECT 1\nELSE\n  SELECT 2\nSELECT 3", "[Utility(IF) Select]"},
		{"if semicolon else", keywords.DialectSQLServer,
			"IF @x = 1 PRINT 'a'; ELSE PRINT 'b'; SELECT 3", "[Utility(IF) Select]"},
		{"if blocks then select", keywords.DialectSQLServer,
			"IF @x = 1 BEGIN SELECT 1 END ELSE BEGIN SELECT 2 END\nSELECT 3", "[Utility(IF) Select]"},
		{"if rollback else commit", keywords.DialectSQLServer,
			"BEGIN TRAN\nUPDATE t SET a = 1\nIF @@ERROR <> 0 ROLLBACK ELSE COMMIT",
			"[Transaction Update Utility(IF)]"},
		{"nested if", keywords.DialectSQLServer,
			"IF @a = 1 IF @b = 1 PRINT 'ab' ELSE PRINT 'a'\nSELECT 1", "[Utility(IF) Select]"},
		{"if exists subquery body", keywords.DialectSQLServer,
			"IF NOT EXISTS (SELECT 1 FROM t WHERE a = 1) INSERT INTO t (a) VALUES (1)\nSELECT 1",
			"[Utility(IF) Select]"},
		{"while block then print", keywords.DialectSQLServer,
			"WHILE @i < 10 BEGIN SET @i = @i + 1 END\nPRINT @i", "[Utility(WHILE) Utility(PRINT)]"},
		{"while single statement", keywords.DialectSQLServer,
			"WHILE @i < 10 SET @i = @i + 1\nSELECT @i", "[Utility(WHILE) Select]"},
		{"try catch block then select", keywords.DialectSQLServer,
			"BEGIN TRY\n  SELECT 1\nEND TRY\nBEGIN CATCH\n  THROW\nEND CATCH\nSELECT 2",
			"[Utility(BEGIN) Select]"},

		// Other dialects: transaction statements on their own line.
		{"pg update then commit", keywords.DialectPostgreSQL,
			"UPDATE t SET a = 1 WHERE id = 2\nCOMMIT", "[Update Transaction]"},
		{"pg select then commit", keywords.DialectPostgreSQL,
			"SELECT a FROM t WHERE a > 0\nCOMMIT", "[Select Transaction]"},
		// Without a WHERE, PostgreSQL reads a non-reserved word after the
		// table as its alias, as the server would.
		{"pg commit after a table is its alias", keywords.DialectPostgreSQL,
			"SELECT a FROM t\ncommit", "[Select]"},
		{"mysql start transaction script", keywords.DialectMySQL,
			"START TRANSACTION\nUPDATE t SET a = 1\nCOMMIT", "[Transaction Update Transaction]"},
		{"mysql begin script", keywords.DialectMySQL,
			"BEGIN\nINSERT INTO t VALUES (1)\nROLLBACK", "[Transaction Insert Transaction]"},
		{"pg begin work script", keywords.DialectPostgreSQL,
			"BEGIN WORK\nDELETE FROM t WHERE a = 1\nCOMMIT\nSET x = 1", "[Transaction Delete Transaction Set]"},
		{"sqlite begin with semicolons", keywords.DialectSQLite,
			"BEGIN TRANSACTION;\nINSERT INTO t VALUES (1);\nEND TRANSACTION;", "[Transaction Insert Transaction]"},
		{"start transaction with consistent snapshot", keywords.DialectMySQL,
			"START TRANSACTION WITH CONSISTENT SNAPSHOT\nSELECT 1", "[Transaction Select]"},
		{"pg end after update", keywords.DialectPostgreSQL,
			"BEGIN TRANSACTION\nUPDATE t SET a = 1 WHERE id = 2\nEND", "[Transaction Update Transaction]"},
		{"pg abort after delete", keywords.DialectPostgreSQL,
			"DELETE FROM t WHERE a = 1\nABORT", "[Delete Transaction]"},
		{"pg release savepoint after update", keywords.DialectPostgreSQL,
			"SAVEPOINT s\nUPDATE t SET a = 1 WHERE id = 2\nRELEASE SAVEPOINT s", "[Transaction Update Transaction]"},
		{"sqlite end transaction without semicolons", keywords.DialectSQLite,
			"BEGIN TRANSACTION\nINSERT INTO t VALUES (1)\nEND TRANSACTION", "[Transaction Insert Transaction]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
			if got := fmt.Sprint(stmtShapes(tree)); got != tc.want {
				t.Errorf("statements = %s, want %s", got, tc.want)
			}
		})
	}
}

// Words that do not start a statement are still errors after a statement
// written without a semicolon, and other dialects do not split a statement
// at words that start one only in T-SQL.
func TestParser_ScriptsWithoutSemicolonsErrors(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSQLServer, "SELECT 1 FROM t garbage garbage2"},
		{keywords.DialectSQLServer, "UPDATE t SET a = 1 WHERE b = 2 garbage"},
		{keywords.DialectSQLServer, "ALTER TABLE t ADD c INT garbage"},
		{keywords.DialectSQLServer, "SELECT 1\nSELECT 2 garbage garbage"},
		{keywords.DialectSQLServer, "SELECT 1 ELSE SELECT 2"},
		{keywords.DialectSQLServer, "ROLLBACK ELSE COMMIT"},
		{keywords.DialectPostgreSQL, "SELECT a FROM t\nPRINT 'x'"},
		{keywords.DialectMySQL, "SELECT 1\nSET @a = 1"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			if tree, err := ParseWithDialect(tc.sql, tc.dialect); err == nil {
				t.Fatalf("parsed as %v, want an error", stmtShapes(tree))
			}
		})
	}
}

// The IF / WHILE text runs to the end of its body and no further.
func TestParser_TSQLConditionalText(t *testing.T) {
	tests := []struct {
		sql  string
		want string
	}{
		{"IF OBJECT_ID(N'x') IS NOT NULL DROP TABLE x\nCREATE TABLE x (a INT)",
			"IF OBJECT_ID(N'x') IS NOT NULL DROP TABLE x"},
		{"IF @a = 1 PRINT 'a'; ELSE PRINT 'b'; SELECT 1", "IF @a = 1 PRINT 'a'; ELSE PRINT 'b'"},
		{"WHILE @i < 3 SET @i = @i + 1\nSELECT 1", "WHILE @i < 3 SET @i = @i + 1"},
		// A body the parser reads differently from SQL Server keeps the
		// verbatim scan to the next ';'.
		{"IF @a = 1 SELECT 1 garbage; SELECT 2", "IF @a = 1 SELECT 1 garbage"},
		// A condition that never reaches a statement keyword likewise.
		{"IF @a = 1 GOTO done", "IF @a = 1 GOTO done"},
	}
	for _, tc := range tests {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			u, ok := tree.Statements[0].(*ast.UtilityStatement)
			if !ok {
				t.Fatalf("statement 0 is %T, want *ast.UtilityStatement", tree.Statements[0])
			}
			if u.Text != tc.want {
				t.Errorf("text = %q, want %q", u.Text, tc.want)
			}
		})
	}
}

// Routine, trigger and PL/SQL bodies are one statement: their inner ';' and
// END do not end it.
func TestParser_RoutineBodiesAreOneStatement(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"sqlite trigger", keywords.DialectSQLite,
			"CREATE TRIGGER trg AFTER INSERT ON t BEGIN UPDATE u SET n = n + 1; END;\nSELECT 1;",
			"[Utility(CREATE TRIGGER) Select]"},
		{"sqlite trigger with case and two statements", keywords.DialectSQLite,
			"CREATE TRIGGER trg AFTER UPDATE ON t FOR EACH ROW WHEN NEW.a > 0 BEGIN UPDATE u SET n = CASE WHEN NEW.a > 1 THEN 1 ELSE 0 END; INSERT INTO log VALUES (NEW.a); END",
			"[Utility(CREATE TRIGGER)]"},
		{"mysql procedure", keywords.DialectMySQL,
			"CREATE PROCEDURE p() BEGIN IF x > 0 THEN SELECT 1; ELSEIF x < 0 THEN SELECT 2; END IF; WHILE x > 0 DO SET x = x - 1; END WHILE; END;\nSELECT 1;",
			"[Utility(CREATE PROCEDURE) Select]"},
		{"mysql trigger", keywords.DialectMySQL,
			"CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.a = 1; END",
			"[Utility(CREATE TRIGGER)]"},
		{"mysql function", keywords.DialectMySQL,
			"CREATE FUNCTION f(x INT) RETURNS INT DETERMINISTIC BEGIN DECLARE y INT; SET y = x + 1; RETURN y; END",
			"[Utility(CREATE FUNCTION)]"},
		{"pg begin atomic", keywords.DialectPostgreSQL,
			"CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC INSERT INTO t VALUES (1); INSERT INTO t VALUES (2); END;\nSELECT 1;",
			"[Utility(CREATE PROCEDURE) Select]"},
		{"tsql procedure", keywords.DialectSQLServer,
			"CREATE PROCEDURE p AS\nBEGIN\n  SET NOCOUNT ON;\n  UPDATE t SET a = 1;\nEND",
			"[Utility(CREATE PROCEDURE)]"},
		{"tsql procedure runs to go", keywords.DialectSQLServer,
			"CREATE PROCEDURE p AS SELECT 1\nSELECT 2\nGO\nEXEC p",
			"[Utility(CREATE PROCEDURE) BatchSeparator Utility(EXEC)]"},
		{"oracle anonymous block", keywords.DialectOracle,
			"BEGIN NULL; END;\nSELECT 1 FROM dual;", "[Utility(BEGIN) Select]"},
		{"oracle block with commit", keywords.DialectOracle,
			"BEGIN UPDATE t SET a = 1; COMMIT; END;", "[Utility(BEGIN)]"},
		{"oracle declare block", keywords.DialectOracle,
			"DECLARE x NUMBER := 1; BEGIN UPDATE t SET a = x; END;\nSELECT 1 FROM dual;",
			"[Utility(DECLARE) Select]"},
		{"oracle loop and exception", keywords.DialectOracle,
			"BEGIN FOR r IN (SELECT id FROM t) LOOP UPDATE u SET x = r.id WHERE id = r.id; END LOOP; COMMIT; EXCEPTION WHEN OTHERS THEN ROLLBACK; RAISE; END;",
			"[Utility(BEGIN)]"},
		{"oracle procedure", keywords.DialectOracle,
			"CREATE OR REPLACE PROCEDURE p AS BEGIN UPDATE t SET a = 1; END p;\nSELECT 1 FROM dual;",
			"[Utility(CREATE PROCEDURE) Select]"},
		{"oracle trigger", keywords.DialectOracle,
			"CREATE OR REPLACE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW BEGIN :NEW.id := s.NEXTVAL; END;",
			"[Utility(CREATE TRIGGER)]"},
		{"oracle package body", keywords.DialectOracle,
			"CREATE OR REPLACE PACKAGE BODY pkg AS PROCEDURE p IS BEGIN NULL; END p; END pkg;\nSELECT 1 FROM dual;",
			"[Utility(CREATE PACKAGE BODY) Select]"},
		// An unclosed block falls back to ';' boundaries, as SplitStatements does.
		{"unclosed block", keywords.DialectOracle,
			"BEGIN NULL; SELECT 1 FROM dual;", "[Utility(BEGIN) Select]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q (%s): %v", tc.sql, tc.dialect, err)
			}
			if got := fmt.Sprint(stmtShapes(tree)); got != tc.want {
				t.Errorf("statements = %s, want %s", got, tc.want)
			}
		})
	}
}

// The context-aware and the error-recovering entry points share the
// statement loop's handling of GO lines and implicit statement ends.
func TestParser_ScriptsWithoutSemicolonsOtherEntryPoints(t *testing.T) {
	const sql = "SET NOCOUNT ON\nSELECT 1\nGO\nUPDATE t SET a = 1\nCOMMIT"
	const want = "[Set Select BatchSeparator Update Transaction]"
	tkz, err := tokenizer.NewWithDialect(keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("tokenizer: %v", err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}

	p := NewParser(WithDialect(string(keywords.DialectSQLServer)))
	defer p.Release()
	tree, err := p.ParseContextFromModelTokens(context.Background(), tokens)
	if err != nil {
		t.Fatalf("ParseContextFromModelTokens: %v", err)
	}
	if got := fmt.Sprint(stmtShapes(tree)); got != want {
		t.Errorf("context parse = %s, want %s", got, want)
	}
	ast.ReleaseAST(tree)

	p2 := NewParser(WithDialect(string(keywords.DialectSQLServer)))
	defer p2.Release()
	stmts, errs := p2.ParseWithRecoveryFromModelTokens(tokens)
	if len(errs) != 0 {
		t.Fatalf("ParseWithRecovery errors: %v", errs)
	}
	if got := fmt.Sprint(stmtShapes(&ast.AST{Statements: stmts})); got != want {
		t.Errorf("recovery parse = %s, want %s", got, want)
	}
}

func TestParser_RecoveryPreservesBatchBoundaryAfterError(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectSQLServer)
	tokens, err := tkz.TokenizeString("SELECT FROM\nGO 2\nSELECT 2")
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithDialect("sqlserver"))
	defer p.Release()
	stmts, errs := p.ParseWithRecoveryFromModelTokens(tokens)
	tree := &ast.AST{Statements: stmts}
	defer ast.ReleaseAST(tree)
	if len(errs) == 0 {
		t.Fatal("expected error for invalid first batch")
	}
	if got := fmt.Sprint(stmtShapes(tree)); got != "[BatchSeparator Select]" {
		t.Fatalf("recovery lost batch boundary: %s", got)
	}
	sep, ok := stmts[0].(*ast.BatchSeparator)
	if !ok || sep.RepeatCount != 2 {
		t.Fatalf("recovery lost GO repeat count: %#v", stmts[0])
	}
}

// A script full of unclosed blocks falls back to ';' boundaries for each
// statement. The block-tracking scans that run into the end of the input
// are bounded, so such input is parsed in linear time.
func TestParser_UnclosedBlocksBoundedWork(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSQLServer, strings.Repeat("CREATE PROCEDURE p AS BEGIN SELECT 1; ", 2000)},
		{keywords.DialectOracle, strings.Repeat("BEGIN NULL; ", 2000)},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect), func(t *testing.T) {
			tkz, err := tokenizer.NewWithDialect(tc.dialect)
			if err != nil {
				t.Fatalf("tokenizer: %v", err)
			}
			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Fatalf("tokenize: %v", err)
			}
			p := NewParser(WithDialect(string(tc.dialect)))
			defer p.Release()
			tree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			if n := len(tree.Statements); n != 2000 {
				t.Errorf("statements = %d, want 2000", n)
			}
			if limit := 8 * len(p.tokens); p.openBlockWork > limit {
				t.Errorf("wasted block-scan work = %d tokens, want at most %d", p.openBlockWork, limit)
			}
		})
	}
}

// TestParser_GOLineInsideStatement checks that a line holding only GO [n]
// ends the batch wherever it appears, as sqlcmd splits the script there: a
// statement that would run across it is an error, not a statement with a
// column or alias named go. GO with an invalid repeat count gets its own
// error instead of a confusing one from the statement parser.
func TestParser_GOLineInsideStatement(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string // substring of the error
	}{
		{"select list", "SELECT a,\ngo\nFROM t", "GO batch separator inside a statement"},
		// GO ends the first batch before it; the second one starts with FROM.
		{"alias position", "SELECT a\nGO 2\nFROM t", "FROM"},
		{"where clause", "UPDATE t SET a = 1 WHERE\nGO\nb = 2", "GO batch separator inside a statement"},
		{"lower case with count", "SELECT a,\n  go 3\nFROM t", "GO batch separator inside a statement"},
		{"zero count", "SELECT 1\nGO 0\nSELECT 2", "invalid GO repeat count"},
		{"fractional count", "SELECT 1\nGO 1.5\nSELECT 2", "invalid GO repeat count"},
		{"zero count first", "GO 0\nSELECT 2", "invalid GO repeat count"},
		{"zero count last", "SELECT 1\nGO 0", "invalid GO repeat count"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectSQLServer)
			if err == nil {
				defer ast.ReleaseAST(tree)
				t.Fatalf("parsed as %v, want an error", stmtShapes(tree))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// Other dialects have no GO directive: go is an ordinary name there.
	tree, err := ParseWithDialect("SELECT a,\ngo\nFROM t", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("postgresql: %v", err)
	}
	ast.ReleaseAST(tree)

	// GO on the same line as other text is not a separator.
	for _, sql := range []string{"SELECT a, go FROM t", "SELECT a,\ngo, b\nFROM t"} {
		tree, err := ParseWithDialect(sql, keywords.DialectSQLServer)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		ast.ReleaseAST(tree)
	}
}

// TestParser_RecoveryStopsAtGOLineInsideStatement checks that the recovering
// parser reports a statement that ran across a GO line and keeps the batch
// boundary.
func TestParser_RecoveryStopsAtGOLineInsideStatement(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectSQLServer)
	tokens, err := tkz.TokenizeString("SELECT a,\nGO\nFROM t\nGO\nSELECT 2")
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser(WithDialect("sqlserver"))
	defer p.Release()
	stmts, errs := p.ParseWithRecoveryFromModelTokens(tokens)
	tree := &ast.AST{Statements: stmts}
	defer ast.ReleaseAST(tree)
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "GO batch separator inside a statement") {
		t.Fatalf("errors = %v, want a GO separator error first", errs)
	}
	if got := fmt.Sprint(stmtShapes(tree)); !strings.HasPrefix(got, "[BatchSeparator") || !strings.HasSuffix(got, "BatchSeparator Select]") {
		t.Fatalf("recovery shapes = %s", got)
	}
}
