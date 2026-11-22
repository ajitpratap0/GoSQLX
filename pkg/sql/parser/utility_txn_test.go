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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// utilityCase is an input and the statement types it parses to, or nil when
// it must be rejected.
type utilityCase struct {
	dialect keywords.SQLDialect
	sql     string
	want    []string
}

const (
	tTxn  = "*ast.TransactionStatement"
	tSet  = "*ast.SetStatement"
	tUse  = "*ast.UseStatement"
	tUtil = "*ast.UtilityStatement"
	tSel  = "*ast.SelectStatement"
	tUpd  = "*ast.UpdateStatement"
	tDrop = "*ast.DropStatement"
)

func runUtilityCases(t *testing.T, tests []utilityCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(string(tt.dialect)+"/"+tt.sql, func(t *testing.T) {
			tree, err := ParseWithDialect(tt.sql, tt.dialect)
			if tt.want == nil {
				if err == nil {
					got := make([]string, len(tree.Statements))
					for i, s := range tree.Statements {
						got[i] = fmt.Sprintf("%T", s)
					}
					t.Fatalf("parsed as %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := make([]string, len(tree.Statements))
			for i, s := range tree.Statements {
				got[i] = fmt.Sprintf("%T", s)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("statements = %v, want %v", got, tt.want)
			}
		})
	}
}

// Outside SQL Server a statement kept verbatim never takes in the next
// statement: a statement on the next line without a ';' between them is an
// error, as after SELECT 1, unless it is a transaction statement.
func TestParser_UtilityStatementDoesNotSwallowNextLine(t *testing.T) {
	pg, my := keywords.DialectPostgreSQL, keywords.DialectMySQL
	runUtilityCases(t, []utilityCase{
		// Rejected: two statements without a ';'.
		{pg, "SELECT 1\nSELECT 2", nil},
		{pg, "SET x = 1\nDROP TABLE users", nil},
		{pg, "SET x = 1 DROP TABLE users", nil},
		{my, "SET @x = 1 SELECT @x", nil},
		{my, "SET x = 1\nDROP TABLE users", nil},
		{my, "USE db\nDELETE FROM users", nil},
		{pg, "GRANT SELECT ON t TO u\nDROP TABLE t", nil},
		{my, "GRANT SELECT ON t TO u\nDROP TABLE t", nil},
		{pg, "REVOKE SELECT ON t FROM u\nDROP TABLE t", nil},
		{pg, "COPY t FROM 'x'\nDROP TABLE t", nil},
		{pg, "CALL p()\nDROP TABLE t", nil},
		{my, "CALL p()\nDROP TABLE t", nil},
		{pg, "VACUUM\nDROP TABLE t", nil},
		{pg, "ANALYZE t\nDROP TABLE t", nil},
		{pg, "CREATE EXTENSION foo\nDROP TABLE t", nil},
		{pg, "CREATE SCHEMA s\nDROP TABLE t", nil},
		{pg, "LOCK TABLE t\nDROP TABLE t", nil},
		{pg, "DO $$ BEGIN END $$\nDROP TABLE t", nil},
		{pg, "EXECUTE p(1)\nSELECT 1", nil},
		{pg, "COMMENT ON TABLE t IS 'x'\nDELETE FROM t", nil},
		{pg, "CREATE ROLE r\nCREATE TABLE t (a INT)", nil},
		{pg, "DROP EXTENSION foo\nDROP TABLE t", nil},
		{keywords.DialectSnowflake, "USE WAREHOUSE w\nSELECT 1", nil},

		// Accepted: a ';', a transaction statement on its own line, or
		// words that belong to the statement.
		{pg, "SET x = 1;\nDROP TABLE users", []string{tSet, tDrop}},
		{pg, "SET x = 1\nCOMMIT", []string{tSet, tTxn}},
		{pg, "SET x = 1\nROLLBACK", []string{tSet, tTxn}},
		{pg, "SET search_path TO a,\nb", []string{tSet}},
		{my, "SET CHARACTER SET utf8", []string{tSet}},
		{my, "SET x = 1 +\nREPLACE(a, b, c)", []string{tSet}},
		{my, "SET @a = (SELECT 1), @b = 2", []string{tSet}},
		{pg, "GRANT SELECT,\nINSERT ON t TO u", []string{tUtil}},
		{pg, "GRANT SELECT ON ALL TABLES IN SCHEMA s TO u\nWITH GRANT OPTION", []string{tUtil}},
		{pg, "CREATE SCHEMA s\nCREATE TABLE t (a INT)\nGRANT SELECT ON t TO u", []string{tUtil}},
		{pg, "CREATE ROLE r\nWITH LOGIN PASSWORD 'x'", []string{tUtil}},
		{pg, "CREATE SEQUENCE s\nSTART WITH 1\nINCREMENT BY 1", []string{tUtil}},
		{pg, "ALTER ROLE r\nSET search_path = a", []string{tUtil}},
		{pg, "ALTER ROLE r\nRESET ALL", []string{tUtil}},
		{pg, "ALTER DOMAIN d\nDROP CONSTRAINT c", []string{tUtil}},
		{pg, "COPY t (a, b)\nFROM STDIN\nWITH (FORMAT csv)", []string{tUtil}},
		{pg, "PREPARE p AS\nSELECT 1", []string{tUtil}},
		{pg, "DECLARE c CURSOR FOR\nSELECT 1", []string{tUtil}},
		{my, "LOAD DATA INFILE 'f' INTO TABLE t\nSET c = 1", []string{tUtil}},
		{keywords.DialectSnowflake, "COPY INTO t\nFROM @s\nFILE_FORMAT = (TYPE = CSV)", []string{tUtil}},
		{keywords.DialectOracle, "SET TRANSACTION USE ROLLBACK SEGMENT rbs", []string{tSet}},
	})
}

// A transaction statement ends where its dialect's grammar ends: the
// statement on the next line is parsed on its own, and words that are not
// part of the grammar are an error.
func TestParser_TransactionStatementGrammar(t *testing.T) {
	pg, my, ms := keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLServer
	gen := keywords.DialectGeneric
	runUtilityCases(t, []utilityCase{
		// The next statement is never folded in.
		{pg, "BEGIN\nVALUES (1)\nCOMMIT", []string{tTxn, "*ast.Values", tTxn}},
		{pg, "BEGIN\nSAVEPOINT a", []string{tTxn, tTxn}},
		{pg, "BEGIN\nCOPY t FROM 'x'", []string{tTxn, tUtil}},
		{pg, "BEGIN\nEXPLAIN SELECT 1", []string{tTxn, "*ast.ExplainStatement"}},
		{pg, "BEGIN\nLOCK TABLE t", []string{tTxn, tUtil}},
		{pg, "COMMIT\nTABLE t", []string{tTxn, tUtil}},
		{pg, "BEGIN\nSET x = 1\nCOMMIT", []string{tTxn, tSet, tTxn}},
		{my, "BEGIN\nUPDATE t SET a = 1\nCOMMIT", []string{tTxn, tUpd, tTxn}},

		// Words outside the grammar.
		{pg, "BEGIN banana split", nil},
		{pg, "BEGIN\nbanana split", nil},
		{pg, "COMMIT AND CHAIN banana", nil},
		{pg, "COMMIT AND", nil},
		{pg, "ROLLBACK TO banana apple", nil},
		{pg, "ROLLBACK TO", nil},
		{pg, "START TRANSACTION foo bar", nil},
		{my, "START TRANSACTION foo bar", nil},
		{pg, "BEGIN SELECT 1; END;", nil},
		{pg, "BEGIN ISOLATION LEVEL", nil},
		{pg, "BEGIN READ", nil},
		{my, "BEGIN TRANSACTION", nil},
		{my, "START TRANSACTION READ ONLY READ WRITE", nil},
		{my, "RELEASE sp1", nil},
		{my, "COMMIT AND CHAIN NO", nil},
		{ms, "BEGIN TRAN\nOPEN c", nil},
		{ms, "COMMIT TRANSACTION WITH (DELAYED_DURABILITY = MAYBE)", nil},
		{keywords.DialectOracle, "START TRANSACTION", nil},
		{keywords.DialectSnowflake, "SAVEPOINT a", nil},
		{keywords.DialectSQLite, "START TRANSACTION", nil},
		{keywords.DialectSQLite, "ABORT", nil},
		{keywords.DialectMySQL, "END", nil},

		// PostgreSQL.
		{pg, "BEGIN", []string{tTxn}},
		{pg, "BEGIN WORK", []string{tTxn}},
		{pg, "BEGIN ISOLATION LEVEL SERIALIZABLE, READ ONLY", []string{tTxn}},
		{pg, "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY", []string{tTxn}},
		{pg, "BEGIN TRANSACTION READ WRITE NOT DEFERRABLE", []string{tTxn}},
		{pg, "START TRANSACTION ISOLATION LEVEL REPEATABLE READ", []string{tTxn}},
		{pg, "COMMIT AND NO CHAIN", []string{tTxn}},
		{pg, "COMMIT PREPARED 'x'", []string{tTxn}},
		{pg, "ROLLBACK PREPARED 'x'", []string{tTxn}},
		{pg, "ROLLBACK WORK TO SAVEPOINT a", []string{tTxn}},
		{pg, "ROLLBACK TO a", []string{tTxn}},
		{pg, "SAVEPOINT a", []string{tTxn}},
		{pg, "RELEASE SAVEPOINT a", []string{tTxn}},
		{pg, "RELEASE a", []string{tTxn}},
		{pg, "END WORK", []string{tTxn}},
		{pg, "ABORT WORK AND CHAIN", []string{tTxn}},
		// MySQL and MariaDB.
		{my, "BEGIN WORK", []string{tTxn}},
		{my, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY", []string{tTxn}},
		{keywords.DialectMariaDB, "START TRANSACTION READ WRITE", []string{tTxn}},
		{my, "COMMIT WORK AND NO CHAIN NO RELEASE", []string{tTxn}},
		{my, "ROLLBACK AND CHAIN RELEASE", []string{tTxn}},
		{my, "ROLLBACK WORK TO SAVEPOINT sp", []string{tTxn}},
		{my, "RELEASE SAVEPOINT sp", []string{tTxn}},
		// SQL Server.
		{ms, "BEGIN TRAN t1 WITH MARK 'x'", []string{tTxn}},
		{ms, "BEGIN TRAN @t WITH MARK N'desc'", []string{tTxn}},
		{ms, "BEGIN DISTRIBUTED TRANSACTION", []string{tTxn}},
		{ms, "COMMIT TRANSACTION t1", []string{tTxn}},
		{ms, "COMMIT WORK", []string{tTxn}},
		{ms, "COMMIT TRANSACTION WITH (DELAYED_DURABILITY = ON) SELECT 1", []string{tTxn, tSel}},
		{ms, "ROLLBACK TRANSACTION @t", []string{tTxn}},
		{ms, "SAVE TRAN s1", []string{tTxn}},
		{ms, "BEGIN TRAN\nUPDATE t SET a = 1\nCOMMIT TRAN", []string{tTxn, tUpd, tTxn}},
		// Oracle, SQLite, Snowflake, ClickHouse, BigQuery.
		{keywords.DialectOracle, "COMMIT WORK", []string{tTxn}},
		{keywords.DialectOracle, "COMMIT COMMENT 'x' WRITE NOWAIT", []string{tTxn}},
		{keywords.DialectOracle, "COMMIT FORCE 'x', 12", []string{tTxn}},
		{keywords.DialectOracle, "ROLLBACK FORCE 'x'", []string{tTxn}},
		{keywords.DialectOracle, "ROLLBACK TO SAVEPOINT a", []string{tTxn}},
		{keywords.DialectSQLite, "BEGIN IMMEDIATE TRANSACTION", []string{tTxn}},
		{keywords.DialectSQLite, "BEGIN DEFERRED", []string{tTxn}},
		{keywords.DialectSQLite, "END TRANSACTION", []string{tTxn}},
		{keywords.DialectSQLite, "ROLLBACK TRANSACTION TO sp2", []string{tTxn}},
		{keywords.DialectSnowflake, "BEGIN TRANSACTION NAME t1", []string{tTxn}},
		{keywords.DialectSnowflake, "START TRANSACTION NAME t1", []string{tTxn}},
		{keywords.DialectSnowflake, "COMMIT WORK", []string{tTxn}},
		{keywords.DialectClickHouse, "BEGIN TRANSACTION", []string{tTxn}},
		{keywords.DialectClickHouse, "ROLLBACK", []string{tTxn}},
		{keywords.DialectBigQuery, "COMMIT TRANSACTION", []string{tTxn}},
		// Generic accepts every dialect's form, like the default dialect.
		{gen, "END", []string{tTxn}},
		{gen, "ABORT", []string{tTxn}},
		{gen, "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE", []string{tTxn}},
		{gen, "START TRANSACTION WITH CONSISTENT SNAPSHOT", []string{tTxn}},
		{gen, "COMMIT WORK AND NO CHAIN", []string{tTxn}},
		{gen, "SAVEPOINT a", []string{tTxn}},
	})
}

// The generic dialect behaves like no dialect for END and ABORT.
func TestParser_GenericDialectEndAbort(t *testing.T) {
	for _, sql := range []string{"END", "ABORT", "END TRANSACTION"} {
		for _, d := range []keywords.SQLDialect{keywords.DialectGeneric, ""} {
			tree, err := ParseWithDialect(sql, d)
			if err != nil {
				t.Fatalf("%q in %q: %v", sql, d, err)
			}
			if _, ok := tree.Statements[0].(*ast.TransactionStatement); !ok {
				t.Fatalf("%q in %q: got %T", sql, d, tree.Statements[0])
			}
		}
	}
}

// <=> is MySQL's null-safe equality and pgvector's distance operator in
// PostgreSQL; == is equality in SQLite and ClickHouse. Other dialects have
// neither.
func TestParser_NullSafeAndDoubleEqualsDialects(t *testing.T) {
	ok := []string{tSel}
	var tests []utilityCase
	for _, d := range []keywords.SQLDialect{
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectPostgreSQL,
	} {
		tests = append(tests, utilityCase{d, "SELECT a <=> b FROM t", ok})
	}
	tests = append(tests, utilityCase{keywords.DialectMySQL, "SELECT a FROM t WHERE a <= > b", nil})
	for _, d := range []keywords.SQLDialect{
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite,
		keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectGeneric,
	} {
		tests = append(tests, utilityCase{d, "SELECT a <=> b FROM t", nil})
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectSQLite, keywords.DialectClickHouse} {
		tests = append(tests, utilityCase{d, "SELECT a FROM t WHERE a == 1", ok})
	}
	for _, d := range []keywords.SQLDialect{
		keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectPostgreSQL,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSnowflake,
		keywords.DialectGeneric,
	} {
		tests = append(tests, utilityCase{d, "SELECT a FROM t WHERE a == 1", nil})
	}
	runUtilityCases(t, tests)
}

// A T-SQL block must balance and an IF / WHILE needs a body; the block
// bodies themselves stay verbatim.
func TestParser_TSQLBlockShape(t *testing.T) {
	ms := keywords.DialectSQLServer
	runUtilityCases(t, []utilityCase{
		{ms, "BEGIN SELECT 1", nil},
		{ms, "BEGIN SELECT 1 END END", nil},
		{ms, "IF 1=1 BEGIN SELECT 1", nil},
		{ms, "IF 1=1", nil},
		{ms, "WHILE 1=1", nil},
		{ms, "IF 1=1 SELECT 1 ELSE", nil},
		{ms, "IF 1=1 SELECT 1 ELSE\nGO", nil},
		{ms, "END", nil},
		{ms, "BEGIN TRY SELECT 1 END TRY BEGIN CATCH SELECT 2", nil},

		{ms, "BEGIN SELECT 1 END", []string{tUtil}},
		{ms, "BEGIN\n  SELECT CASE WHEN a = 1 THEN 1 END FROM t\nEND", []string{tUtil}},
		{ms, "BEGIN TRY SELECT 1 END TRY BEGIN CATCH SELECT 2 END CATCH", []string{tUtil}},
		{ms, "IF 1=1 SELECT 1 ELSE SELECT 2", []string{tUtil}},
		{ms, "IF CASE WHEN @a = 1 THEN 1 END = 1 SELECT 1", []string{tUtil}},
		{ms, "IF @x = 1 GOTO done", []string{tUtil}},
		{ms, "IF UPDATE(col) PRINT 'x'", []string{tUtil}},
		{ms, "IF @@ERROR <> 0 ROLLBACK ELSE COMMIT", []string{tUtil}},
		{ms, "WHILE 1=1 BEGIN SELECT 1 END", []string{tUtil}},
		{ms, "WHILE @i < 10 SET @i = @i + 1", []string{tUtil}},
		{ms, "IF @x = 1\n    PRINT 'a'\nELSE\n    PRINT 'b'", []string{tUtil}},
	})
}
