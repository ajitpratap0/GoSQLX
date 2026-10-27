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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
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

// ddlNameRenderCases mirrors the list in
// pkg/sql/ast/render_ddl_name_quoting_632_test.go: the DDL, utility-statement
// and expression name positions the formatter used to write verbatim (#632),
// plus the formatter-only CREATE MATERIALIZED VIEW TABLESPACE name.
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
		{"create_table_column_type", `CREATE TABLE t (a ` + hostileQ + `)`, hostileQ, func(s ast.Statement) string {
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
		{"cast_type", `SELECT a::` + hostileQ + ` FROM t`, hostileQ, func(s ast.Statement) string {
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
		{"materialized_view_tablespace", `CREATE MATERIALIZED VIEW v TABLESPACE ` + hostileQ + ` AS SELECT 1`, hostile, func(s ast.Statement) string {
			if m, ok := s.(*ast.CreateMaterializedViewStatement); ok {
				return m.Tablespace
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

// TestHostileDDLNames_FormatAST_ReparseAsOneStatement_PR632 checks that
// FormatAST, in compact and readable styles, quotes DDL object, column,
// constraint and function names (and escapes the value positions listed in
// ddlNameRenderCases) so the output re-parses to exactly one statement
// carrying the same text in the same position.
func TestHostileDDLNames_FormatAST_ReparseAsOneStatement_PR632(t *testing.T) {
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
				for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
					rendered := formatter.FormatAST(tree, opts)
					tree2, err := gosqlx.ParseWithDialect(rendered, d)
					if err != nil {
						t.Errorf("[%s] re-parse of %q: %v", d, rendered, err)
						continue
					}
					if n := len(tree2.Statements); n != 1 {
						t.Errorf("[%s] FormatAST output re-parses to %d statements, want 1: %s", d, n, rendered)
					} else if got := tc.Extract(tree2.Statements[0]); got != tc.Want {
						t.Errorf("[%s] name after round trip = %q, want %q (SQL: %s)", d, got, tc.Want, rendered)
					}
					ast.ReleaseAST(tree2)
				}
				ast.ReleaseAST(tree)
			}
			if parsed == 0 {
				t.Fatalf("no dialect parsed %q", tc.Input)
			}
		})
	}
}

// TestFormat_DDLNameQuoting_PR632 pins gosqlx.Format output: hostile DDL
// names are quoted, while ordinary DDL, keyword-named functions and SHOW
// statements are unchanged apart from SHOW COLUMNS/INDEX regaining FROM.
func TestFormat_DDLNameQuoting_PR632(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`CREATE TABLE "t; DROP TABLE x; --" (a INT)`, "CREATE TABLE \"t; DROP TABLE x; --\" (\n  a INT\n)"},
		{`DROP TABLE "t; DROP TABLE x; --"`, "DROP TABLE \"t; DROP TABLE x; --\""},
		{`CREATE TABLE s.t (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL)`,
			"CREATE TABLE s.t (\n  id INT PRIMARY KEY,\n  name VARCHAR(100) NOT NULL\n)"},
		{`CREATE INDEX idx ON t (a, b DESC)`, "CREATE INDEX idx ON t (a, b DESC)"},
		{`DROP TABLE IF EXISTS a, s.b CASCADE`, "DROP TABLE IF EXISTS a, s.b CASCADE"},
		{`TRUNCATE TABLE a, b`, "TRUNCATE TABLE a, b"},
		{`SELECT COUNT(*), COALESCE(a, 1), IF(a, 1, 2) FROM t`, "SELECT COUNT(*), COALESCE(a, 1), IF(a, 1, 2)\nFROM t"},
		{`SHOW COLUMNS FROM t`, "SHOW COLUMNS FROM t"},
		{`SHOW TABLES`, "SHOW TABLES"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := gosqlx.Format(tc.input, gosqlx.DefaultFormatOptions())
			if err != nil {
				t.Fatalf("Format(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Format mismatch\n got: %q\nwant: %q", got, tc.want)
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

// TestHandBuiltHostileDDLNames_FormatAST_NoStatementBreak_PR632 checks
// hand-built ASTs rendered by FormatStatement: DDL names, types, option
// values and SHOW/DESCRIBE/sequence names that never came from the parser
// must not escape their position either.
func TestHandBuiltHostileDDLNames_FormatAST_NoStatementBreak_PR632(t *testing.T) {
	const evil = `x; DROP TABLE y; --`
	evilRef := &ast.ReferenceDefinition{Table: evil, Columns: []string{evil}}
	evilCol := ast.ColumnDef{Name: evil, Type: evil,
		Constraints: []ast.ColumnConstraint{{Type: "REFERENCES", References: evilRef}}}
	evilCon := ast.TableConstraint{Name: evil, Type: "FOREIGN KEY", Columns: []string{evil}, References: evilRef}
	one := &ast.LiteralValue{Value: "1", Type: "INTEGER"}
	stmts := []ast.Statement{
		&ast.CreateTableStatement{Name: evil, Columns: []ast.ColumnDef{evilCol},
			Constraints: []ast.TableConstraint{evilCon,
				{Name: evil, Type: "PRIMARY KEY", Columns: []string{evil}},
				{Name: evil, Type: "UNIQUE", Columns: []string{evil}}},
			Inherits:    []string{evil},
			PartitionBy: &ast.PartitionBy{Type: "RANGE", Columns: []string{evil}},
			Options:     []ast.TableOption{{Name: "ENGINE", Value: evil}}},
		&ast.CreateIndexStatement{Name: evil, Table: evil, Using: evil,
			Columns: []ast.IndexColumn{{Column: evil, Collate: evil}}},
		&ast.AlterTableStatement{Table: evil, Actions: []ast.AlterTableAction{ //nolint:staticcheck // hand-built legacy node
			{Type: "ADD COLUMN", ColumnDef: &evilCol},
			{Type: "DROP COLUMN", ColumnName: evil},
			{Type: "ADD CONSTRAINT", Constraint: &evilCon}}},
		&ast.DropStatement{ObjectType: "TABLE", Names: []string{evil}},
		&ast.TruncateStatement{Tables: []string{evil}},
		&ast.RefreshMaterializedViewStatement{Name: evil},
		&ast.CreateMaterializedViewStatement{Name: "v", Tablespace: evil,
			Query: &ast.SelectStatement{Columns: []ast.Expression{one}}},
		&ast.InsertStatement{TableName: "t", Values: [][]ast.Expression{{one}},
			OnConflict: &ast.OnConflict{Constraint: evil, Action: ast.OnConflictAction{DoNothing: true}}},
		&ast.MergeStatement{TargetTable: ast.TableReference{Name: "t"}, SourceTable: ast.TableReference{Name: "s"},
			OnCondition: one, WhenClauses: []*ast.MergeWhenClause{
				{Type: "MATCHED", Action: &ast.MergeAction{ActionType: "UPDATE", SetClauses: []ast.SetClause{{Column: evil, Value: one}}}},
				{Type: "NOT_MATCHED", Action: &ast.MergeAction{ActionType: "INSERT", Columns: []string{evil}, Values: []ast.Expression{one}}}}},
		&ast.SelectStatement{Columns: []ast.Expression{&ast.FunctionCall{Name: evil}}, From: []ast.TableReference{{Name: "t"}},
			For: &ast.ForClause{LockType: "UPDATE", Tables: []string{evil}}},
		&ast.CreateSequenceStatement{Name: &ast.Identifier{Name: evil}},
		&ast.AlterSequenceStatement{Name: &ast.Identifier{Name: evil}},
		&ast.DropSequenceStatement{Name: &ast.Identifier{Name: evil}},
		&ast.ShowStatement{ShowType: "CREATE TABLE", ObjectName: evil},
		&ast.ShowStatement{ShowType: evil, From: evil},
		&ast.DescribeStatement{TableName: evil},
		&ast.PragmaStatement{Name: evil, Arg: evil},
	}
	// ReadableStyle ends statements with a terminator of its own; turn that
	// off so any ';' in the output came from a name.
	readable := ast.ReadableStyle()
	readable.AddSemicolon = false
	for _, s := range stmts {
		for _, opts := range []ast.FormatOptions{ast.CompactStyle(), readable} {
			assertNoBreakOrComment(t, formatter.FormatStatement(s, opts))
		}
	}
}

// TestFormat_UnsupportedRawSQLStaysCommented_PR632 checks that an unsupported
// statement whose raw text contains a line break (from a string literal or
// quoted identifier) stays entirely inside the "-- UNSUPPORTED:" comment.
func TestFormat_UnsupportedRawSQLStaysCommented_PR632(t *testing.T) {
	for _, raw := range []string{"CREATE SEQUENCE s\nDROP TABLE x", "CREATE SEQUENCE s\r\nDROP TABLE x", "CREATE SEQUENCE s\rDROP TABLE x"} {
		out := formatter.FormatStatement(&ast.UnsupportedStatement{Kind: "CREATE SEQUENCE", RawSQL: raw}, ast.ReadableStyle())
		tkz := tokenizer.GetTokenizer()
		toks, err := tkz.Tokenize([]byte(out))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			t.Fatalf("tokenize %q: %v", out, err)
		}
		for _, tok := range toks {
			if tok.Token.Type != models.TokenTypeEOF {
				t.Fatalf("raw SQL escaped the comment: %q", out)
			}
		}
		for _, line := range strings.FieldsFunc(out, func(r rune) bool { return r == '\n' || r == '\r' }) {
			if !strings.HasPrefix(line, "--") {
				t.Fatalf("line %q of %q is not commented", line, out)
			}
		}
	}

	// The same through the parser: a Snowflake CREATE STAGE is kept verbatim
	// with its string literal (line break included) quoted, so the text in
	// the literal never turns into a live statement after formatting.
	const sql = "CREATE STAGE s COMMENT = 'a\nDROP TABLE x'"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	defer ast.ReleaseAST(tree)
	out := formatter.FormatAST(tree, ast.ReadableStyle())
	tree2, err := gosqlx.ParseWithDialect(out, keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("re-parse %q: %v", out, err)
	}
	defer ast.ReleaseAST(tree2)
	if len(tree2.Statements) != 1 {
		t.Fatalf("formatted statement re-parses to %d statements: %q", len(tree2.Statements), out)
	}
	if _, ok := tree2.Statements[0].(*ast.UtilityStatement); !ok {
		t.Fatalf("re-parsed statement is %T, want *ast.UtilityStatement: %q", tree2.Statements[0], out)
	}
}
