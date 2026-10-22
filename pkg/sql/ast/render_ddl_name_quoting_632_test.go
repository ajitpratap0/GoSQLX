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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func createTable(s ast.Statement) *ast.CreateTableStatement {
	c, _ := s.(*ast.CreateTableStatement)
	return c
}

func createIndex(s ast.Statement) *ast.CreateIndexStatement {
	c, _ := s.(*ast.CreateIndexStatement)
	return c
}

func mergeAction(s ast.Statement) *ast.MergeAction {
	if m, ok := s.(*ast.MergeStatement); ok && len(m.WhenClauses) > 0 {
		return m.WhenClauses[0].Action
	}
	return nil
}

func showStmt(s ast.Statement) *ast.ShowStatement {
	sh, _ := s.(*ast.ShowStatement)
	return sh
}

func pragmaStmt(s ast.Statement) *ast.PragmaStatement {
	p, _ := s.(*ast.PragmaStatement)
	return p
}

func firstColumnExpr(s ast.Statement) ast.Expression {
	if sel := firstSelect(s); sel != nil && len(sel.Columns) > 0 {
		return sel.Columns[0]
	}
	return nil
}

// ddlNameRenderCases lists the DDL, utility-statement and expression name
// positions SQL() and the formatter used to write verbatim (#632). Each Input
// stores Want (the hostile text with its quotes removed) in the position
// Extract reads back; pkg/formatter/render_ddl_name_quoting_632_test.go
// mirrors this list for FormatAST.
func ddlNameRenderCases() []aliasRenderCase {
	const hostile = `a; DROP TABLE x; --`
	const hostileQ = `"a; DROP TABLE x; --"`
	const hostileUpper = `A; DROP TABLE X; --`
	return []aliasRenderCase{
		{"create_table_name", `CREATE TABLE ` + hostileQ + ` (a INT)`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil {
				return c.Name
			}
			return ""
		}},
		{"create_table_qualified_name", `CREATE TABLE s.` + hostileQ + ` (a INT)`, "s." + hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil {
				return c.Name
			}
			return ""
		}},
		{"create_table_column", `CREATE TABLE t (` + hostileQ + ` INT)`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Columns) > 0 {
				return c.Columns[0].Name
			}
			return ""
		}},
		{"create_table_column_type", `CREATE TABLE t (a ` + hostileQ + `)`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Columns) > 0 {
				return c.Columns[0].Type
			}
			return ""
		}},
		{"primary_key_column", `CREATE TABLE t (a INT, PRIMARY KEY (` + hostileQ + `))`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Constraints) > 0 && len(c.Constraints[0].Columns) > 0 {
				return c.Constraints[0].Columns[0]
			}
			return ""
		}},
		{"foreign_key_ref_table", `CREATE TABLE t (a INT, FOREIGN KEY (a) REFERENCES ` + hostileQ + ` (b))`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Constraints) > 0 && c.Constraints[0].References != nil {
				return c.Constraints[0].References.Table
			}
			return ""
		}},
		{"foreign_key_ref_column", `CREATE TABLE t (a INT, FOREIGN KEY (a) REFERENCES r (` + hostileQ + `))`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Constraints) > 0 && c.Constraints[0].References != nil &&
				len(c.Constraints[0].References.Columns) > 0 {
				return c.Constraints[0].References.Columns[0]
			}
			return ""
		}},
		{"column_references_table", `CREATE TABLE t (a INT REFERENCES ` + hostileQ + ` (b))`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Columns) > 0 && len(c.Columns[0].Constraints) > 0 &&
				c.Columns[0].Constraints[0].References != nil {
				return c.Columns[0].Constraints[0].References.Table
			}
			return ""
		}},
		{"partition_by_column", `CREATE TABLE t (a INT) PARTITION BY RANGE (` + hostileQ + `)`, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && c.PartitionBy != nil && len(c.PartitionBy.Columns) > 0 {
				return c.PartitionBy.Columns[0]
			}
			return ""
		}},
		{"table_option_value", `CREATE TABLE t (a INT) ENGINE = ` + hostileQ, hostile, func(s ast.Statement) string {
			if c := createTable(s); c != nil && len(c.Options) > 0 {
				return c.Options[0].Value
			}
			return ""
		}},
		{"create_index_name", `CREATE INDEX ` + hostileQ + ` ON t (a)`, hostile, func(s ast.Statement) string {
			if c := createIndex(s); c != nil {
				return c.Name
			}
			return ""
		}},
		{"create_index_table", `CREATE INDEX i ON ` + hostileQ + ` (a)`, hostile, func(s ast.Statement) string {
			if c := createIndex(s); c != nil {
				return c.Table
			}
			return ""
		}},
		{"create_index_column", `CREATE INDEX i ON t (` + hostileQ + `)`, hostile, func(s ast.Statement) string {
			if c := createIndex(s); c != nil && len(c.Columns) > 0 {
				return c.Columns[0].Column
			}
			return ""
		}},
		{"create_index_using", `CREATE INDEX i ON t USING ` + hostileQ + ` (a)`, hostile, func(s ast.Statement) string {
			if c := createIndex(s); c != nil {
				return c.Using
			}
			return ""
		}},
		{"drop_table", `DROP TABLE ` + hostileQ, hostile, func(s ast.Statement) string {
			if d, ok := s.(*ast.DropStatement); ok && len(d.Names) > 0 {
				return d.Names[0]
			}
			return ""
		}},
		{"drop_view_second_name", `DROP VIEW v, ` + hostileQ + ` CASCADE`, hostile, func(s ast.Statement) string {
			if d, ok := s.(*ast.DropStatement); ok && len(d.Names) > 1 {
				return d.Names[1]
			}
			return ""
		}},
		{"drop_index_qualified", `DROP INDEX s.` + hostileQ, "s." + hostile, func(s ast.Statement) string {
			if d, ok := s.(*ast.DropStatement); ok && len(d.Names) > 0 {
				return d.Names[0]
			}
			return ""
		}},
		{"truncate_table", `TRUNCATE TABLE t, ` + hostileQ, hostile, func(s ast.Statement) string {
			if tr, ok := s.(*ast.TruncateStatement); ok && len(tr.Tables) > 1 {
				return tr.Tables[1]
			}
			return ""
		}},
		{"refresh_materialized_view", `REFRESH MATERIALIZED VIEW ` + hostileQ, hostile, func(s ast.Statement) string {
			if r, ok := s.(*ast.RefreshMaterializedViewStatement); ok {
				return r.Name
			}
			return ""
		}},
		{"on_conflict_constraint", `INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT ` + hostileQ + ` DO NOTHING`, hostile, func(s ast.Statement) string {
			if i, ok := s.(*ast.InsertStatement); ok && i.OnConflict != nil {
				return i.OnConflict.Constraint
			}
			return ""
		}},
		{"merge_update_set_column", `MERGE INTO t USING s ON 1 = 1 WHEN MATCHED THEN UPDATE SET ` + hostileQ + ` = 1`, hostile, func(s ast.Statement) string {
			if a := mergeAction(s); a != nil && len(a.SetClauses) > 0 {
				return a.SetClauses[0].Column
			}
			return ""
		}},
		{"merge_insert_column", `MERGE INTO t USING s ON 1 = 1 WHEN NOT MATCHED THEN INSERT (` + hostileQ + `) VALUES (1)`, hostile, func(s ast.Statement) string {
			if a := mergeAction(s); a != nil && len(a.Columns) > 0 {
				return a.Columns[0]
			}
			return ""
		}},
		{"function_name", `SELECT ` + hostileQ + `(1) FROM t`, hostile, func(s ast.Statement) string {
			if f, ok := firstColumnExpr(s).(*ast.FunctionCall); ok {
				return f.Name
			}
			return ""
		}},
		{"for_update_of", `SELECT * FROM t FOR UPDATE OF ` + hostileQ, hostile, func(s ast.Statement) string {
			if sel := firstSelect(s); sel != nil && sel.For != nil && len(sel.For.Tables) > 0 {
				return sel.For.Tables[0]
			}
			return ""
		}},
		{"interval_value", `SELECT INTERVAL 'a''; DROP TABLE x; --' FROM t`, `a'; DROP TABLE x; --`, func(s ast.Statement) string {
			if iv, ok := firstColumnExpr(s).(*ast.IntervalExpression); ok {
				return iv.Value
			}
			return ""
		}},
		{"cast_type", `SELECT a::` + hostileQ + ` FROM t`, hostile, func(s ast.Statement) string {
			if c, ok := firstColumnExpr(s).(*ast.CastExpression); ok {
				return c.Type
			}
			return ""
		}},
		{"extract_field", `SELECT EXTRACT(` + hostileQ + ` FROM d) FROM t`, hostileUpper, func(s ast.Statement) string {
			if e, ok := firstColumnExpr(s).(*ast.ExtractExpression); ok {
				return e.Field
			}
			return ""
		}},
		{"show_generic", `SHOW ` + hostileQ, hostileUpper, func(s ast.Statement) string {
			if sh := showStmt(s); sh != nil {
				return sh.ShowType
			}
			return ""
		}},
		{"show_create_table", `SHOW CREATE TABLE ` + hostileQ, hostile, func(s ast.Statement) string {
			if sh := showStmt(s); sh != nil {
				return sh.ObjectName
			}
			return ""
		}},
		{"show_columns_from", `SHOW COLUMNS FROM ` + hostileQ, hostile, func(s ast.Statement) string {
			if sh := showStmt(s); sh != nil {
				return sh.ObjectName
			}
			return ""
		}},
		{"show_tables_from", `SHOW TABLES FROM ` + hostileQ, hostile, func(s ast.Statement) string {
			if sh := showStmt(s); sh != nil {
				return sh.From
			}
			return ""
		}},
		{"describe_table", `DESCRIBE ` + hostileQ, hostile, func(s ast.Statement) string {
			if d, ok := s.(*ast.DescribeStatement); ok {
				return d.TableName
			}
			return ""
		}},
		{"replace_into_table", `REPLACE INTO ` + hostileQ + ` (a) VALUES (1)`, hostile, func(s ast.Statement) string {
			if r, ok := s.(*ast.ReplaceStatement); ok {
				return r.TableName
			}
			return ""
		}},
		{"pragma_name", `PRAGMA ` + hostileQ, hostile, func(s ast.Statement) string {
			if p := pragmaStmt(s); p != nil {
				return p.Name
			}
			return ""
		}},
		{"pragma_arg", `PRAGMA table_info(` + hostileQ + `)`, hostile, func(s ast.Statement) string {
			if p := pragmaStmt(s); p != nil {
				return p.Arg
			}
			return ""
		}},
		{"pragma_value_identifier", `PRAGMA journal_mode = ` + hostileQ, hostile, func(s ast.Statement) string {
			if p := pragmaStmt(s); p != nil {
				return p.Value
			}
			return ""
		}},
		{"pragma_value_string", `PRAGMA journal_mode = 'a''; DROP TABLE x; --'`, `a'; DROP TABLE x; --`, func(s ast.Statement) string {
			if p := pragmaStmt(s); p != nil {
				return p.Value
			}
			return ""
		}},
	}
}

// TestHostileDDLNames_SQL_ReparseAsOneStatement_PR632 checks that SQL()
// quotes DDL object, column, constraint and function names (and escapes the
// value positions listed in ddlNameRenderCases) so the output re-parses to
// exactly one statement carrying the same text in the same position.
func TestHostileDDLNames_SQL_ReparseAsOneStatement_PR632(t *testing.T) {
	for _, tc := range ddlNameRenderCases() {
		t.Run(tc.Name, func(t *testing.T) {
			parsed := 0
			for _, d := range aliasRenderDialects {
				tree, err := gosqlx.ParseWithDialect(tc.Input, d)
				if err != nil {
					continue
				}
				if len(tree.Statements) != 1 || tc.Extract(tree.Statements[0]) != tc.Want {
					ast.ReleaseAST(tree)
					continue // this dialect does not store the name in the tested position
				}
				parsed++
				rendered := tree.SQL()
				ast.ReleaseAST(tree)

				tree2, err := gosqlx.ParseWithDialect(rendered, d)
				if err != nil {
					t.Errorf("[%s] re-parse of %q: %v", d, rendered, err)
					continue
				}
				if n := len(tree2.Statements); n != 1 {
					t.Errorf("[%s] SQL() output re-parses to %d statements, want 1: %s", d, n, rendered)
				} else if got := tc.Extract(tree2.Statements[0]); got != tc.Want {
					t.Errorf("[%s] name after round trip = %q, want %q (SQL: %s)", d, got, tc.Want, rendered)
				}
				ast.ReleaseAST(tree2)
			}
			if parsed == 0 {
				t.Fatalf("no dialect parsed %q", tc.Input)
			}
		})
	}
}

// TestDDLNameRendering_Benign_PR632 pins the exact SQL() output for ordinary
// DDL, utility statements and function calls: plain names stay bare and
// keyword-named functions keep their form, and each output re-parses to one
// statement that renders identically.
func TestDDLNameRendering_Benign_PR632(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		input   string
		want    string
	}{
		{"", `CREATE TABLE s.t (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, owner_id INT REFERENCES users (id))`,
			`CREATE TABLE s.t (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, owner_id INT REFERENCES users (id))`},
		{"", `CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b), FOREIGN KEY (b) REFERENCES r (id))`,
			`CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b), FOREIGN KEY (b) REFERENCES r (id))`},
		{"", `CREATE TABLE "Mixed" ("Col" INT)`, `CREATE TABLE "Mixed" ("Col" INT)`},
		{"", `CREATE TABLE t ("select" INT)`, `CREATE TABLE t ("select" INT)`},
		{"", `CREATE TABLE t (a Nullable(String), c Enum8('a' = 1, 'b' = -2), d DateTime64(3, 'UTC'))`,
			`CREATE TABLE t (a Nullable(String), c Enum8('a'= 1, 'b'= - 2), d DateTime64(3, 'UTC'))`},
		{"", `CREATE TABLE t (a ENUM('x', 'y'))`, `CREATE TABLE t (a ENUM('x', 'y'))`},
		{"", `CREATE TABLE t (a INT) ENGINE = InnoDB`, `CREATE TABLE t (a INT) ENGINE=InnoDB`},
		{keywords.DialectClickHouse, `CREATE TABLE t (a INT) ENGINE = MergeTree()`, `CREATE TABLE t (a INT) ENGINE=MergeTree()`},
		{"", `CREATE TABLE t (a INT) PARTITION BY RANGE (a)`, `CREATE TABLE t (a INT) PARTITION BY RANGE (a)`},
		{"", `CREATE UNIQUE INDEX IF NOT EXISTS s.i ON s.t USING btree (a, b DESC)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS s.i ON s.t USING btree (a, b DESC)`},
		{"", `DROP TABLE IF EXISTS a, s.b CASCADE`, `DROP TABLE IF EXISTS a, s.b CASCADE`},
		{"", `TRUNCATE TABLE a, b`, `TRUNCATE TABLE a, b`},
		{"", `REFRESH MATERIALIZED VIEW CONCURRENTLY s.mv`, `REFRESH MATERIALIZED VIEW CONCURRENTLY s.mv`},
		{"", `INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT t_pkey DO NOTHING`,
			`INSERT INTO t (a) VALUES (1) ON CONFLICT ON CONSTRAINT t_pkey DO NOTHING`},
		{"", `MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.a = s.a WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a)`,
			`MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.a = s.a WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a)`},
		{"", `SELECT COUNT(*), COALESCE(a, 1), NOW(), IF(a, 1, 2), "Fn"(1) FROM t`,
			`SELECT COUNT(*), COALESCE(a, 1), NOW(), IF(a, 1, 2), "Fn"(1) FROM t`},
		{keywords.DialectClickHouse, `SELECT quantile(0.5)(x) FROM t`, `SELECT quantile(0.5)(x) FROM t`},
		{"", `SELECT * FROM t FOR UPDATE OF t`, `SELECT * FROM t FOR UPDATE OF t`},
		{"", `SELECT INTERVAL '1 day', INTERVAL 5 DAY FROM t`, `SELECT INTERVAL '1 day', INTERVAL 5 DAY FROM t`},
		{"", `SELECT EXTRACT(YEAR FROM d) FROM t`, `SELECT EXTRACT(YEAR FROM d) FROM t`},
		{"", `SELECT CAST(a AS VARCHAR(10)), CAST(b AS DECIMAL(10, 2)), c::TEXT FROM t`,
			`SELECT CAST(a AS VARCHAR(10)), CAST(b AS DECIMAL(10,2)), CAST(c AS TEXT) FROM t`},
		{"", `SHOW TABLES`, `SHOW TABLES`},
		{"", `SHOW CREATE TABLE s.t`, `SHOW CREATE TABLE s.t`},
		{"", `SHOW COLUMNS FROM t`, `SHOW COLUMNS FROM t`},
		{"", `SHOW INDEX FROM t`, `SHOW INDEX FROM t`},
		{"", `SHOW TABLES FROM db`, `SHOW TABLES FROM db`},
		{"", `DESCRIBE s.t`, `DESCRIBE s.t`},
		{"", `REPLACE INTO t (a) VALUES (1)`, `REPLACE INTO t (a) VALUES (1)`},
		{"", `PRAGMA table_info(users)`, `PRAGMA table_info(users)`},
		{"", `PRAGMA journal_mode = WAL`, `PRAGMA journal_mode = WAL`},
		{"", `PRAGMA cache_size = 2000`, `PRAGMA cache_size = 2000`},
		{keywords.DialectSQLServer, `DROP TABLE #tmp`, `DROP TABLE #tmp`},
		{keywords.DialectSQLServer, `TRUNCATE TABLE #tmp`, `TRUNCATE TABLE #tmp`},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Errorf("SQL() mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			tree2, err := gosqlx.ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("re-parse of %q: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if n := len(tree2.Statements); n != 1 {
				t.Fatalf("SQL() output re-parses to %d statements, want 1: %s", n, got)
			}
			if again := tree2.SQL(); again != got {
				t.Errorf("SQL() not stable across a round trip\n first: %s\nsecond: %s", got, again)
			}
		})
	}
}

// assertNoBreakOrComment tokenizes rendered SQL and fails if it contains a
// statement terminator or a comment, i.e. if a hand-built name or value
// escaped its position. The output need not re-parse.
func assertNoBreakOrComment(t *testing.T, rendered string) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(rendered))
	if err != nil {
		t.Fatalf("tokenize %q: %v", rendered, err)
	}
	for _, tok := range toks {
		if tok.Token.Type == models.TokenTypeSemicolon {
			t.Fatalf("rendered SQL contains a statement terminator: %s", rendered)
		}
	}
	if len(tkz.Comments) > 0 {
		t.Fatalf("rendered SQL contains a comment: %s", rendered)
	}
}

// TestHandBuiltHostileDDLNames_NoStatementBreak_PR632 checks hand-built ASTs:
// DDL names, types, option values and function names that never came from
// the parser must not escape their position either.
func TestHandBuiltHostileDDLNames_NoStatementBreak_PR632(t *testing.T) {
	const evil = `x; DROP TABLE y; --`
	evilRef := &ast.ReferenceDefinition{Table: evil, Columns: []string{evil}}
	evilCol := ast.ColumnDef{Name: evil, Type: evil,
		Constraints: []ast.ColumnConstraint{{Type: "REFERENCES", References: evilRef}}}
	evilCon := ast.TableConstraint{Name: evil, Type: "FOREIGN KEY", Columns: []string{evil}, References: evilRef}
	one := &ast.LiteralValue{Value: "1", Type: "INTEGER"}
	nodes := []interface{ SQL() string }{
		&ast.CreateTableStatement{Name: evil, Columns: []ast.ColumnDef{evilCol},
			Constraints: []ast.TableConstraint{evilCon,
				{Name: evil, Type: "PRIMARY KEY", Columns: []string{evil}},
				{Name: evil, Type: "UNIQUE", Columns: []string{evil}}},
			Inherits:    []string{evil},
			PartitionBy: &ast.PartitionBy{Type: "RANGE", Columns: []string{evil}},
			Options:     []ast.TableOption{{Name: "ENGINE", Value: evil}, {Name: "COMMENT", Value: "a') ; DROP TABLE y; --"}}},
		&ast.CreateTableStatement{Name: "t", Columns: []ast.ColumnDef{{Name: "a", Type: "INT) ; DROP TABLE y; --"}}},
		&ast.CreateTableStatement{Name: "t", Columns: []ast.ColumnDef{{Name: "a", Type: "ENUM('a\\'; DROP TABLE y; --')"}}},
		&ast.CreateIndexStatement{Name: evil, Table: evil, Using: evil, Columns: []ast.IndexColumn{{Column: evil}}},
		&ast.AlterTableStatement{Table: evil, Actions: []ast.AlterTableAction{ //nolint:staticcheck // hand-built legacy node
			{Type: "ADD COLUMN", ColumnDef: &evilCol},
			{Type: "DROP COLUMN", ColumnName: evil},
			{Type: "ADD CONSTRAINT", Constraint: &evilCon}}},
		&ast.DropStatement{ObjectType: "TABLE", Names: []string{evil, "@" + evil}},
		&ast.TruncateStatement{Tables: []string{evil}},
		&ast.RefreshMaterializedViewStatement{Name: evil},
		&ast.InsertStatement{TableName: "t", Values: [][]ast.Expression{{one}},
			OnConflict: &ast.OnConflict{Constraint: evil, Action: ast.OnConflictAction{DoNothing: true}}},
		&ast.MergeStatement{TargetTable: ast.TableReference{Name: "t"}, SourceTable: ast.TableReference{Name: "s"},
			OnCondition: one, WhenClauses: []*ast.MergeWhenClause{
				{Type: "MATCHED", Action: &ast.MergeAction{ActionType: "UPDATE", SetClauses: []ast.SetClause{{Column: evil, Value: one}}}},
				{Type: "NOT_MATCHED", Action: &ast.MergeAction{ActionType: "INSERT", Columns: []string{evil}, Values: []ast.Expression{one}}}}},
		&ast.FunctionCall{Name: evil, Arguments: []ast.Expression{one}},
		&ast.FunctionCall{Name: "s." + evil, Arguments: []ast.Expression{one}},
		&ast.SelectStatement{Columns: []ast.Expression{one}, From: []ast.TableReference{{Name: "t"}},
			For: &ast.ForClause{LockType: "UPDATE", Tables: []string{evil}}},
		&ast.IntervalExpression{Value: `1'; DROP TABLE y; --`},
		&ast.ExtractExpression{Field: evil, Source: &ast.Identifier{Name: "d"}},
		&ast.CastExpression{Expr: one, Type: evil},
		&ast.ShowStatement{ShowType: "CREATE TABLE", ObjectName: evil},
		&ast.ShowStatement{ShowType: evil, From: evil},
		&ast.ShowStatement{ShowType: "CREATE " + evil, ObjectName: "t"},
		&ast.DescribeStatement{TableName: evil},
		&ast.ReplaceStatement{TableName: evil, Values: [][]ast.Expression{{one}}},
		&ast.PragmaStatement{Name: evil, Arg: evil},
		&ast.PragmaStatement{Name: "p", Value: evil},
		&ast.Ident{Name: evil},
		&ast.PeriodDefinition{Name: &ast.Identifier{Name: evil}, StartCol: &ast.Identifier{Name: evil}, EndCol: &ast.Identifier{Name: evil}},
		&ast.InsertStatement{TableName: "@" + evil, Values: [][]ast.Expression{{one}}},
		&ast.DeleteStatement{TableName: "#" + evil},
	}
	for _, n := range nodes {
		assertNoBreakOrComment(t, n.SQL())
	}
	seq := []interface{ ToSQL() string }{
		&ast.CreateSequenceStatement{Name: &ast.Identifier{Name: evil}},
		&ast.AlterSequenceStatement{Name: &ast.Identifier{Name: evil}},
		&ast.DropSequenceStatement{Name: &ast.Identifier{Name: evil}},
	}
	for _, n := range seq {
		assertNoBreakOrComment(t, n.ToSQL())
	}
}

// TestQualifiedName_SpecialCharsOnlyLeading_PR632 checks that '#' stays bare
// only as the leading SQL Server temp-table marker and '@' only as a
// Snowflake stage reference made of path characters: anywhere else the
// tokenizer does not accept them bare (and MySQL treats '#' as a comment),
// so the part is quoted. '$' is a bare identifier character, but never the
// first one (Oracle v$session, Snowflake SYSTEM$TYPEOF).
func TestQualifiedName_SpecialCharsOnlyLeading_PR632(t *testing.T) {
	cases := []struct{ in, want string }{
		{"#tmp", "#tmp"},
		{"##global", "##global"},
		{"db.#tmp", "db.#tmp"},
		{"a#b", `"a#b"`},
		{"a$b", "a$b"},
		{"v$session", "v$session"},
		{"$a", `"$a"`},
		{"1$a", `"1$a"`},
		{"a@b", `"a@b"`},
		{"@stage", "@stage"},
		{"@db.sch.stage/path/file.csv", "@db.sch.stage/path/file.csv"},
		{"@~/staged", "@~/staged"},
		{"@%t", "@%t"},
		{"@s x", `"@s x"`},
		{"@s;x", `"@s;x"`},
		{"@s--x", `"@s--x"`},
	}
	for _, tc := range cases {
		if got := ast.QuoteQualifiedName(tc.in); got != tc.want {
			t.Errorf("QuoteQualifiedName(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	if got := strings.Count(ast.QuoteQualifiedName(`@x"y`), `""`); got != 1 {
		t.Errorf(`QuoteQualifiedName(@x"y) must double the embedded quote, got %s`, ast.QuoteQualifiedName(`@x"y`))
	}
}
