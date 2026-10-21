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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestCompositeFieldAccessRoundTrip(t *testing.T) {
	queries := []string{
		`SELECT (f(x)).a FROM t`,
		`SELECT (f(t.x)).a AS a, (f(t.x)).b AS b FROM t`,
		`SELECT (t.payload).name FROM t`,
		`SELECT (f(x)).* FROM t`,
		`SELECT (f(x))."*" FROM t`,
		`SELECT (f(x))."Odd""Field" FROM t`,
		`SELECT (f(x))."a.b" FROM t`,
		`SELECT (f(x))."field); DROP TABLE t; --" FROM t`,
		`SELECT ((f(x)).a).b FROM t`,
		`SELECT (f(x)).a.b FROM t`,
		`SELECT (f(x)).items[1].name FROM t`,
		`SELECT (f(x)).items[1:2] FROM t`,
		`SELECT (f(x)).items[:2] FROM t`,
		`SELECT (items[1]).name FROM t`,
		`SELECT (a)."order" FROM t`,
		`SELECT (a)."ORDER" FROM t`,
		`SELECT (a)[1] FROM t`,
		`SELECT (a + b)[1] FROM t`,
		`SELECT (a)[1].c FROM t`,
		`SELECT (t.a)[1].c FROM t`,
		`SELECT (f(x))[1].c FROM t`,
		`SELECT (a + b)[1].c FROM t`,
		`SELECT (a)[1][2].c FROM t`,
		`SELECT (a)[1:2][1].c FROM t`,
		`SELECT (a)[1].items[2].c FROM t`,
		`SELECT ((a).b)[1] FROM t`,
		`SELECT (a).b[1].c FROM t`,
		`SELECT (SELECT f(x) FROM t).a`,
		`SELECT (x, y).f1 FROM t`,
		`SELECT (f(x)).a + 1 FROM t WHERE (f(x)).b = 2 ORDER BY (f(x)).a`,
		`SELECT CAST((f(x)).a AS integer) FROM t`,
	}
	for _, dialect := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL} {
		t.Run(string(dialect), func(t *testing.T) {
			for _, query := range queries {
				t.Run(query, func(t *testing.T) {
					tree, err := gosqlx.ParseWithDialect(query, dialect)
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					defer ast.ReleaseAST(tree)
					if got := tree.SQL(); got != query {
						t.Errorf("SQL() = %q, want %q", got, query)
					}
					for _, output := range []string{tree.SQL(), formatter.FormatAST(tree, ast.CompactStyle()), formatter.FormatAST(tree, ast.ReadableStyle())} {
						again, err := gosqlx.ParseWithDialect(output, dialect)
						if err != nil {
							t.Fatalf("reparse %q: %v", output, err)
						}
						if got := again.SQL(); got != query {
							t.Errorf("round-trip = %q, want %q", got, query)
						}
						ast.ReleaseAST(again)
					}
				})
			}
		})
	}
}

func TestCompositeFieldAccessInvalid(t *testing.T) {
	for _, query := range []string{
		`SELECT (f(x)). FROM t`,
		`SELECT (f(x)).123 FROM t`,
		`SELECT (f(x)).'name' FROM t`,
		`SELECT (f(x)).* .name FROM t`,
		`SELECT (f(x)).*[1] FROM t`,
		`SELECT (f(x)).items[] FROM t`,
		`SELECT (f(x)).items[1 FROM t`,
		`SELECT (f(x))` + strings.Repeat(`.a`, 101) + ` FROM t`,
	} {
		t.Run(query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(query, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected invalid composite access to be rejected")
			}
		})
	}
}

func TestCompositeFieldAccessTraversal(t *testing.T) {
	tree, err := gosqlx.Parse(`SELECT (outer_fn(inner_fn(t.x))).a FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	var functions []string
	ast.Inspect(tree.Statements[0], func(n ast.Node) bool {
		if fn, ok := n.(*ast.FunctionCall); ok {
			functions = append(functions, fn.Name)
		}
		return true
	})
	if got := strings.Join(functions, ","); got != "outer_fn,inner_fn" {
		t.Fatalf("Inspect lost nested calls: %q", got)
	}
	if got := strings.Join(gosqlx.ExtractFunctions(tree), ","); got != "inner_fn,outer_fn" {
		t.Fatalf("ExtractFunctions lost nested calls: %q", got)
	}
	if got := strings.Join(gosqlx.ExtractColumns(tree), ","); got != "x" {
		t.Fatalf("ExtractColumns = %q, want x", got)
	}
}

func TestJoinedTableFunction(t *testing.T) {
	for _, query := range []string{
		`SELECT f.a FROM t CROSS JOIN LATERAL get_items(t.x) f`,
		`SELECT f.a FROM t LEFT JOIN LATERAL get_items(t.x) f ON true`,
		`SELECT f.a FROM t INNER JOIN get_items(t.x) f ON f.a = t.id`,
		`SELECT f.a FROM t CROSS JOIN LATERAL app.get_items(t.x) f`,
	} {
		t.Run(query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(query, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
			}
			if len(stmt.Joins) != 1 || stmt.Joins[0].Right.TableFunc == nil {
				t.Fatal("JOIN must retain its function call in the AST")
			}
			ref := stmt.Joins[0].Right
			if ref.Alias != "f" || ref.Lateral != strings.Contains(query, "LATERAL") || len(ref.TableFunc.Arguments) != 1 {
				t.Fatalf("unexpected joined table reference: %+v", ref)
			}
			if got := tree.SQL(); got != query {
				t.Errorf("SQL() = %q, want %q", got, query)
			}
			for _, output := range []string{tree.SQL(), formatter.FormatAST(tree, ast.CompactStyle())} {
				again, err := gosqlx.ParseWithDialect(output, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatalf("reparse %q: %v", output, err)
				}
				ast.ReleaseAST(again)
			}
			found := false
			ast.Inspect(tree.Statements[0], func(n ast.Node) bool {
				if fn, ok := n.(*ast.FunctionCall); ok && strings.HasSuffix(fn.Name, "get_items") {
					found = true
				}
				return true
			})
			if !found {
				t.Fatal("Inspect must visit the joined function")
			}
		})
	}
}

func TestJoinedTableFunctionInvalid(t *testing.T) {
	for _, query := range []string{
		`SELECT * FROM get_items(,) f`,
		`SELECT * FROM t CROSS JOIN LATERAL get_items(,) f`,
		`SELECT * FROM t CROSS JOIN LATERAL get_items(t.x f`,
		`SELECT * FROM t LEFT JOIN LATERAL get_items(t.x) f`,
	} {
		t.Run(query, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(query, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected malformed joined function to be rejected")
			}
		})
	}
	// Adding JOIN support must not bypass the existing table-function gate.
	tree, err := gosqlx.ParseWithDialect(
		`SELECT * FROM t CROSS JOIN get_items(t.x) f`, keywords.DialectGeneric,
	)
	if err == nil {
		ast.ReleaseAST(tree)
		t.Fatal("generic dialect must retain the existing table-function restriction")
	}
}

func BenchmarkCompositeFieldAccess(b *testing.B) {
	query := []byte(`SELECT (get_item(t.payload)).name, (get_item(t.payload)).price FROM items t`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tree, err := gosqlx.ParseBytes(query)
		if err != nil {
			b.Fatal(err)
		}
		ast.ReleaseAST(tree)
	}
}
