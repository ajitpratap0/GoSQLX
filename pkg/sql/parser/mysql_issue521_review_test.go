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
	"errors"
	"strings"
	"testing"
	"time"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Review follow-ups for issue #521 (multi-part column references and
// parenthesized join groups).

func issue521FirstColumn(t *testing.T, tree *ast.AST) *ast.Identifier {
	t.Helper()
	sel := issue521Select(t, tree)
	if len(sel.Columns) == 0 {
		t.Fatal("no select columns")
	}
	id, ok := sel.Columns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[0])
	}
	return id
}

// Each part of a quoted multi-part name must be rendered on its own:
// `my-db`.`t`.`c` used to come back as "my-db.t".c, a single identifier.
func TestIssue521_QuotedMultiPartRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"mysql backticks with hyphen", keywords.DialectMySQL,
			"SELECT `my-db`.`t`.`c` FROM t", `SELECT "my-db".t.c FROM t`},
		{"postgres double quotes with space", keywords.DialectPostgreSQL,
			`SELECT "my db"."t"."c" FROM t`, `SELECT "my db".t."c" FROM t`},
		{"four parts, quoted middle", keywords.DialectSQLServer,
			`SELECT c."s-1".t.col FROM t`, `SELECT c."s-1".t.col FROM t`},
		{"two parts unchanged", keywords.DialectMySQL,
			"SELECT `my-db`.`t` FROM t", `SELECT "my-db".t FROM t`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			id := issue521FirstColumn(t, tree)
			got := tree.SQL()
			if got != tt.want {
				t.Fatalf("SQL() = %s, want %s", got, tt.want)
			}
			if s := id.SQL(); !strings.HasPrefix(tt.want, "SELECT "+s+" ") {
				t.Errorf("Identifier.SQL() = %s, disagrees with statement SQL() %s", s, got)
			}

			tree2, err := gosqlx.ParseWithDialect(got, tt.dialect)
			if err != nil {
				t.Fatalf("reparse of %s: %v", got, err)
			}
			id2 := issue521FirstColumn(t, tree2)
			if id2.Table != id.Table || id2.Name != id.Name {
				t.Errorf("reparse changed the reference: Table %q Name %q, want Table %q Name %q",
					id2.Table, id2.Name, id.Table, id.Name)
			}

			norm, err := gosqlx.Normalize(tt.sql)
			if err == nil && !strings.Contains(norm, strings.TrimSuffix(strings.TrimPrefix(tt.want, "SELECT "), " FROM t")) {
				t.Errorf("Normalize = %s, want it to contain the per-part quoted reference from %s", norm, tt.want)
			}
		})
	}

	// A qualifier with an empty part renders the same through the fast and
	// buffered paths.
	id := &ast.Identifier{Table: "a..b", Name: "c"}
	if got, want := id.SQL(), `a."".b.c`; got != want {
		t.Errorf("Identifier{Table: %q}.SQL() = %s, want %s", id.Table, got, want)
	}
}

func TestIssue521_ColumnRefPartLimit(t *testing.T) {
	// Five parts is the longest supported form (SQL Server
	// server.database.schema.table.column).
	for _, sql := range []string{"SELECT a.b.c.d.e FROM t", "SELECT a.b.c.d.* FROM t"} {
		tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectSQLServer)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if id := issue521FirstColumn(t, tree); id.Table != "a.b.c.d" {
			t.Errorf("%s: Table = %q, want a.b.c.d", sql, id.Table)
		}
	}

	if _, err := gosqlx.Parse("SELECT a.b.c.d.e.f FROM t"); err == nil ||
		!strings.Contains(err.Error(), "more than 5 parts") {
		t.Errorf("six-part reference: err = %v, want a 'more than 5 parts' error", err)
	}

	// A long dotted chain used to take quadratic time (a 1 MB chain ran for
	// ~10 s). It must now fail fast at the sixth part.
	long := "SELECT " + strings.Repeat("a.", 50000) + "a FROM t"
	start := time.Now()
	_, err := gosqlx.Parse(long)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("50k-part reference took %v", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "more than 5 parts") {
		t.Errorf("50k-part reference: err = %v, want a 'more than 5 parts' error", err)
	}
}

// ExtractColumnsQualified must describe db.t.col with the same Schema/Table
// split that ExtractTablesQualified uses for the table db.t.
func TestIssue521_ExtractColumnsQualifiedMatchesTables(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT db.t.col, c.s.t.x FROM db.t", keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cols := gosqlx.ExtractColumnsQualified(tree)
	want := map[gosqlx.QualifiedName]bool{
		{Schema: "db", Table: "t", Name: "col"}: false,
		{Schema: "c.s", Table: "t", Name: "x"}:  false,
	}
	for _, c := range cols {
		if _, ok := want[c]; !ok {
			t.Errorf("unexpected column %+v", c)
			continue
		}
		want[c] = true
	}
	for q, seen := range want {
		if !seen {
			t.Errorf("missing column %+v in %+v", q, cols)
		}
	}

	tables := gosqlx.ExtractTablesQualified(tree)
	if len(tables) != 1 {
		t.Fatalf("tables = %+v, want one", tables)
	}
	if tables[0].Schema != "db" || tables[0].Name != "t" {
		t.Fatalf("table = %+v, want {Schema: db, Name: t}", tables[0])
	}
}

func TestIssue521_ModifiersAfterJoinGroupRejected(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		wantErr string
	}{
		{"AS alias on join group", keywords.DialectPostgreSQL,
			"SELECT * FROM (a JOIN b ON a.id = b.id) AS x", "alias after a parenthesized join group"},
		{"bare alias on join group", keywords.DialectMySQL,
			"SELECT * FROM (a JOIN b ON a.id = b.id) x", "alias after a parenthesized join group"},
		{"bare alias on single parenthesized table", keywords.DialectMySQL,
			"SELECT * FROM (a) x", "alias after a parenthesized join group"},
		{"alias on nested group", keywords.DialectMySQL,
			"SELECT * FROM ((a JOIN b ON a.id = b.id) AS x JOIN c ON c.id = a.id)", "alias after a parenthesized join group"},
		{"ClickHouse FINAL on join group", keywords.DialectClickHouse,
			"SELECT * FROM (a JOIN b ON a.id = b.id) FINAL", "FINAL after a parenthesized join group"},
		{"ClickHouse FINAL on single parenthesized table", keywords.DialectClickHouse,
			"SELECT * FROM (a) FINAL", "FINAL after a parenthesized join group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err == nil {
				t.Fatalf("expected an error, got SQL %s", tree.SQL())
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
			if code := string(goerrors.ErrCodeUnsupportedFeature); !strings.Contains(err.Error(), code) {
				t.Errorf("error %q does not carry code %s", err.Error(), code)
			}
		})
	}

}

// Quoted identifiers directly after "(" start a join group.
func TestIssue521_QuotedNameAfterParen(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"mysql backticks", keywords.DialectMySQL,
			"SELECT * FROM (`a` JOIN `b` ON `a`.`id` = `b`.`id`) JOIN `c` ON `c`.`id` = `a`.`id`"},
		{"sqlserver brackets", keywords.DialectSQLServer,
			"SELECT * FROM ([a] JOIN [b] ON [a].[id] = [b].[id]) JOIN [c] ON [c].[id] = [a].[id]"},
	}
	const want = "SELECT * FROM a INNER JOIN b ON a.id = b.id INNER JOIN c ON c.id = a.id"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, tt.dialect)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := tree.SQL(); got != want {
				t.Errorf("SQL() = %s, want %s", got, want)
			}
		})
	}
}

// The context snippet of a qualifier error must come from the SQL source, not
// from hint text passed in its place.
func TestIssue521_QualifierErrorHasNoBogusSnippet(t *testing.T) {
	for _, sql := range []string{"SELECT t. FROM t", "SELECT a.b. FROM t"} {
		_, err := gosqlx.Parse(sql)
		if err == nil {
			t.Fatalf("%s: expected an error", sql)
		}
		var pe *goerrors.Error
		if !errors.As(err, &pe) {
			t.Fatalf("%s: error %T is not *errors.Error", sql, err)
		}
		if pe.Context != nil && strings.Contains(pe.Context.SQL, "syntax") {
			t.Errorf("%s: context snippet is hint text: %q", sql, pe.Context.SQL)
		}
		if strings.Contains(err.Error(), "| Use ") {
			t.Errorf("%s: error prints hint text as a source line:\n%s", sql, err.Error())
		}
	}
}

// TestIssue521_DoubleParenFromShapes pins how FROM handles a "((" start after
// parenthesized join groups were added. Shapes that are join groups (or a
// derived table inside one) parse as join groups. Since #612 a "((" that opens
// a parenthesized query expression (a parenthesized set operation, or a
// doubly-parenthesized subquery) parses as a derived table.
func TestIssue521_DoubleParenFromShapes(t *testing.T) {
	parses := []struct{ sql, want string }{
		{"SELECT * FROM ((a JOIN b ON a.id = b.id))",
			"SELECT * FROM a INNER JOIN b ON a.id = b.id"},
		{"SELECT * FROM ((SELECT a FROM x) t)",
			"SELECT * FROM (SELECT a FROM x) t"},
		{"SELECT * FROM ((SELECT a FROM x) t JOIN y ON t.a = y.a)",
			"SELECT * FROM (SELECT a FROM x) t INNER JOIN y ON t.a = y.a"},
		{"SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t",
			"SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t"},
		{"SELECT * FROM ((SELECT 1 AS a) UNION ALL (SELECT 2)) AS t",
			"SELECT * FROM ((SELECT 1 AS a) UNION ALL (SELECT 2)) t"},
		{"SELECT * FROM ((SELECT 1) INTERSECT (SELECT 1)) q",
			"SELECT * FROM ((SELECT 1) INTERSECT (SELECT 1)) q"},
		{"SELECT * FROM ((SELECT a FROM x)) t",
			"SELECT * FROM (SELECT a FROM x) t"},
	}
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		for _, tc := range parses {
			tree, err := gosqlx.ParseWithDialect(tc.sql, d)
			if err != nil {
				t.Errorf("%s: %q: unexpected error: %v", d, tc.sql, err)
				continue
			}
			if got := tree.SQL(); got != tc.want {
				t.Errorf("%s: %q: SQL() = %q, want %q", d, tc.sql, got, tc.want)
			}
		}
	}
}
