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
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"reflect"
	"testing"
)

func TestDialectConstructsTableConstructs(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSnowflake, "SELECT * FROM t PIVOT (SUM(amt) FOR month IN (ANY ORDER BY month) DEFAULT ON NULL (0)) AS p"},
		{keywords.DialectSnowflake, "SELECT * FROM t PIVOT (SUM(amt) FOR month IN ('Jan', 'Feb') DEFAULT ON NULL (0)) AS p"},
		{keywords.DialectClickHouse, "SELECT * FROM hits FINAL SAMPLE 0.1 WHERE x = 1"},
		{keywords.DialectClickHouse, "SELECT * FROM hits SAMPLE 1/10 OFFSET 1/2"},
		{keywords.DialectClickHouse, "SELECT * FROM hits FINAL"},
		{keywords.DialectClickHouse, `SELECT * FROM hits "FINAL"`},
		{keywords.DialectClickHouse, `SELECT * FROM hits AS "FINAL"`},
		{keywords.DialectClickHouse, "SELECT * FROM hits SAMPLE 0.1"},
		{keywords.DialectClickHouse, "SELECT * FROM hits AS h FINAL SAMPLE 0.1"},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM (generate_series(1,3), unnest(ARRAY['a','b'])) WITH ORDINALITY AS r(n, s, i)"},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM (f(x) AS (a int, b text))"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("want SELECT, got %T", tree.Statements[0])
			}
			want := stmt.SQL()
			formatted, err := gosqlx.FormatWithDialect(tc.sql, gosqlx.FormatOptions{}, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			shape := dialectConstructTreeShape(t, tree)
			for _, rendered := range []string{want, formatted} {
				reparsed, err := gosqlx.ParseWithDialect(rendered, tc.dialect)
				if err != nil {
					t.Fatalf("reparse %q: %v", rendered, err)
				}
				defer ast.ReleaseAST(reparsed)
				if got := dialectConstructTreeShape(t, reparsed); !reflect.DeepEqual(got, shape) {
					t.Errorf("tree changed after rendering %q", rendered)
				}
				again, ok := reparsed.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("want SELECT, got %T", reparsed.Statements[0])
				}
				if got := again.SQL(); got != want {
					t.Errorf("round trip = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestDialectConstructsTableConstructInspection(t *testing.T) {
	cases := []struct {
		dialect         keywords.SQLDialect
		sql             string
		literals, calls int
	}{
		{keywords.DialectSnowflake, "SELECT * FROM t PIVOT (SUM(amt) FOR month IN (ANY ORDER BY month) DEFAULT ON NULL (0))", 1, 1},
		{keywords.DialectClickHouse, "SELECT * FROM hits FINAL SAMPLE 1/10 OFFSET 1/2", 4, 0},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM (generate_series(1,3), unnest(ARRAY['a','b'])) WITH ORDINALITY AS r(n,s,i)", 4, 2},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			literals, calls := 0, 0
			ast.Inspect(tree.Statements[0], func(node ast.Node) bool {
				switch node.(type) {
				case *ast.LiteralValue:
					literals++
				case *ast.FunctionCall:
					calls++
				}
				return true
			})
			if literals != tc.literals || calls != tc.calls {
				t.Fatalf("visited %d literals, %d calls; want %d, %d", literals, calls, tc.literals, tc.calls)
			}
		})
	}
}

func TestDialectConstructsTableConstructRejectMalformed(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectSnowflake, "SELECT * FROM t PIVOT (SUM(amt) FOR month IN ('Jan') DEFAULT ON NULL ())"},
		{keywords.DialectSQLServer, "SELECT * FROM t PIVOT (SUM(amt) FOR month IN (1) DEFAULT ON NULL (0)) p"},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM ()"},
		{keywords.DialectPostgreSQL, `SELECT * FROM ROWS FROM (f(x)) WITH "ORDINALITY"`},
		{keywords.DialectClickHouse, "SELECT * FROM hits FINAL FINAL"},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM (f(x) AS (a, b text))"},
		{keywords.DialectPostgreSQL, "SELECT * FROM ROWS FROM (f(x) AS (a int, b))"},
		{keywords.DialectClickHouse, "SELECT * FROM hits SAMPLE 1/"},
		{keywords.DialectClickHouse, "SELECT * FROM hits SAMPLE 0.1 OFFSET"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.dialect)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Fatal("expected malformed or unsupported syntax to be rejected")
			}
		})
	}
}

func TestDialectConstructsSampleExpressionMutation(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT * FROM hits FINAL SAMPLE 1/10 OFFSET 1/2", keywords.DialectClickHouse)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("got %T", tree.Statements[0])
	}
	if stmt.Sample == nil {
		t.Fatal("missing SAMPLE")
	}
	stmt.Sample.Size = &ast.LiteralValue{Value: "0.5", Type: "FLOAT"}
	stmt.Sample.OffsetSize = &ast.LiteralValue{Value: "0.25", Type: "FLOAT"}
	want := "SELECT * FROM hits FINAL SAMPLE 0.5 OFFSET 0.25"
	if got := stmt.SQL(); got != want {
		t.Errorf("SQL = %q, want %q", got, want)
	}
	if got := formatter.FormatAST(tree, ast.CompactStyle()); got != want {
		t.Errorf("FormatAST = %q, want %q", got, want)
	}
}
