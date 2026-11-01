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
	goast "go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// The parser produces AlterStatement, so exercise the legacy node directly
// as well as covering parser-produced nodes in the differential tests below.
func TestAlterTableSQLSeparators(t *testing.T) {
	add := ast.AlterTableAction{Type: "ADD COLUMN", ColumnDef: &ast.ColumnDef{Name: "a", Type: "INT"}}
	drop := ast.AlterTableAction{Type: "DROP COLUMN", ColumnName: "b"}
	for _, dialect := range keywords.AllDialects() {
		for _, tc := range []struct {
			name    string
			actions []ast.AlterTableAction
			want    string
		}{
			{"single", []ast.AlterTableAction{add}, "ALTER TABLE t ADD COLUMN a INT"},
			{"mixed", []ast.AlterTableAction{add, drop}, "ALTER TABLE t ADD COLUMN a INT, DROP COLUMN b"},
			{"three", []ast.AlterTableAction{drop, add, {Type: "DROP COLUMN", ColumnName: "c"}}, "ALTER TABLE t DROP COLUMN b, ADD COLUMN a INT, DROP COLUMN c"},
			{"empty", nil, "ALTER TABLE t"},
		} {
			t.Run(string(dialect)+"/"+tc.name, func(t *testing.T) {
				stmt := &ast.AlterTableStatement{Table: "t", Actions: tc.actions} //nolint:staticcheck // Regression for the legacy node.
				if got := stmt.SQL(); got != tc.want {
					t.Fatalf("SQL() = %q, want %q", got, tc.want)
				}
				checkAlterSQL(t, stmt, dialect, len(tc.actions) > 0)
			})
		}
	}
}

func checkAlterSQL(t *testing.T, stmt ast.Statement, dialect keywords.SQLDialect, roundtrip bool) {
	t.Helper()
	tree := &ast.AST{Statements: []ast.Statement{stmt}}
	sql := tree.SQL()
	style := ast.CompactStyle()
	style.Dialect = string(dialect)
	if got := formatter.FormatAST(tree, style); got != sql {
		t.Errorf("SQL/visitor mismatch:\n SQL: %s\nvisitor: %s", sql, got)
	}
	if !roundtrip {
		return
	}
	again, err := gosqlx.ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("reparse %q: %v", sql, err)
	}
	defer ast.ReleaseAST(again)
	if len(again.Statements) != 1 {
		t.Fatalf("reparsed %d statements, want 1", len(again.Statements))
	}
	if got := again.SQL(); got != sql {
		t.Errorf("roundtrip:\nfirst: %s\nagain: %s", sql, got)
	}
}

func TestAlterTableSQLDialectActions(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectGeneric, "ALTER TABLE t ADD COLUMN a INT, DROP COLUMN b"},
		{keywords.DialectPostgreSQL, "ALTER TABLE t ADD COLUMN a INT, ALTER COLUMN b TYPE BIGINT, DROP COLUMN c, RENAME COLUMN d TO e, ADD CONSTRAINT uq UNIQUE (a), DROP CONSTRAINT old_uq"},
		{keywords.DialectMySQL, "ALTER TABLE t ADD COLUMN a INT, MODIFY COLUMN b BIGINT, CHANGE COLUMN c d INT, DROP COLUMN e, ADD CONSTRAINT uq UNIQUE (a), DROP FOREIGN KEY fk"},
		{keywords.DialectMariaDB, "ALTER TABLE t ADD COLUMN a INT, MODIFY COLUMN b BIGINT, DROP COLUMN c"},
		{keywords.DialectSQLServer, "ALTER TABLE t ADD a INT, b INT"},
		{keywords.DialectOracle, "ALTER TABLE t ADD (a NUMBER, b VARCHAR2(10))"},
		{keywords.DialectSQLite, "ALTER TABLE t RENAME COLUMN a TO b"},
		{keywords.DialectSnowflake, "ALTER TABLE t ADD COLUMN a INT, DROP COLUMN b"},
		{keywords.DialectBigQuery, "ALTER TABLE t ADD COLUMN a INT64, DROP COLUMN b"},
		{keywords.DialectRedshift, "ALTER TABLE t ADD COLUMN a INT, DROP COLUMN b"},
		{keywords.DialectClickHouse, "ALTER TABLE t ADD COLUMN a Int32, MODIFY COLUMN b Int64, DROP COLUMN c"},
	}
	for _, tc := range tests {
		t.Run(string(tc.dialect), func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			for _, stmt := range tree.Statements {
				checkAlterSQL(t, stmt, tc.dialect, true)
			}
		})
	}
}

// Visit every SQL file, using the real-world directory's dialect and the
// generic dialect used by the existing corpus suite. Non-ALTER statements
// are outside this regression's contract.
func TestAlterTableSQLCorpus(t *testing.T) {
	count := 0
	for _, root := range []string{"../../../testdata/realworld", "../../../testdata/corpus"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			dialect := keywords.DialectGeneric
			if strings.HasSuffix(root, "realworld") {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				dialect = keywords.SQLDialect(strings.Split(filepath.ToSlash(rel), "/")[0])
				if !keywords.IsValidDialect(string(dialect)) {
					t.Fatalf("unknown dialect: %s", dialect)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, sql := range gosqlx.SplitStatements(string(data), string(dialect)) {
				if !strings.Contains(strings.ToUpper(sql), "ALTER") {
					continue
				}
				t.Run(path+":"+strconv.Itoa(i+1), func(t *testing.T) {
					tree, err := gosqlx.ParseWithDialect(sql, dialect)
					if err != nil {
						t.Fatalf("parse corpus ALTER input: %v", err)
					}
					defer ast.ReleaseAST(tree)
					for _, stmt := range tree.Statements {
						if a, ok := stmt.(*ast.AlterStatement); ok && a.Type == ast.AlterTypeTable {
							count++
							checkAlterSQL(t, stmt, dialect, true)
						}
					}
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if count == 0 {
		t.Fatal("no ALTER TABLE corpus statements checked")
	}
	t.Logf("checked %d corpus ALTER TABLE statements", count)
}

// Extract SQL literals from parser tests instead of maintaining a stale copy.
// Negative tests and dialect-specific inputs may fail to parse; each accepted
// ALTER TABLE is checked in every dialect that accepts that literal.
func TestAlterTableSQLParserInputs(t *testing.T) {
	files, err := filepath.Glob("../parser/*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	count, rejected := 0, 0
	for _, file := range files {
		fset := token.NewFileSet()
		fileAST, err := goparser.ParseFile(fset, file, nil, goparser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		goast.Inspect(fileAST, func(node goast.Node) bool {
			lit, ok := node.(*goast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			sql, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			upper := strings.ToUpper(sql)
			if !strings.Contains(upper, "ALTER") || !strings.Contains(upper, "TABLE") {
				return true
			}
			for _, dialect := range keywords.AllDialects() {
				tree, err := gosqlx.ParseWithDialect(sql, dialect)
				if err != nil {
					rejected++
					continue
				}
				func() {
					defer ast.ReleaseAST(tree)
					for i, stmt := range tree.Statements {
						if a, ok := stmt.(*ast.AlterStatement); ok && a.Type == ast.AlterTypeTable {
							count++
							name := fset.Position(lit.Pos()).String() + "/" + string(dialect) + "/" + strconv.Itoa(i)
							t.Run(name, func(t *testing.T) { checkAlterSQL(t, stmt, dialect, true) })
						}
					}
				}()
			}
			return true
		})
	}
	if count == 0 {
		t.Fatal("no parser ALTER TABLE inputs checked")
	}
	t.Logf("checked %d accepted ALTER TABLE inputs; %d rejected input/dialect combinations", count, rejected)
}

func BenchmarkAlterTableSQLSeparators(b *testing.B) {
	stmt := &ast.AlterTableStatement{Table: "t", Actions: []ast.AlterTableAction{ //nolint:staticcheck // Benchmark the repaired legacy node.
		{Type: "ADD COLUMN", ColumnDef: &ast.ColumnDef{Name: "a", Type: "INT"}},
		{Type: "DROP COLUMN", ColumnName: "b"},
	}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = stmt.SQL()
	}
}
