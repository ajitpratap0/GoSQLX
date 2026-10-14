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
	"reflect"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

var joinUsingSQLDialects = []keywords.SQLDialect{
	keywords.DialectGeneric,
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectMariaDB,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSQLite,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
}

// usingNames returns, per join of the first SELECT in tree, the names of its
// USING identifiers.
func usingNames(t *testing.T, tree *ast.AST) [][]string {
	t.Helper()
	if len(tree.Statements) == 0 {
		t.Fatal("no statements parsed")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	out := make([][]string, 0, len(sel.Joins))
	for i, j := range sel.Joins {
		if j.Condition != nil {
			t.Errorf("join %d: Condition = %T, want nil for USING", i, j.Condition)
		}
		names := make([]string, 0, len(j.Using))
		for k, u := range j.Using {
			id, ok := u.(*ast.Identifier)
			if !ok || id == nil {
				t.Fatalf("join %d Using[%d]: got %T, want *ast.Identifier", i, k, u)
			}
			names = append(names, id.Name)
		}
		out = append(out, names)
	}
	return out
}

// TestJoinUsing_SQLRoundTrip_Issue603 is the regression test for #603:
// JOIN ... USING (cols) used to render as "ON cols", which changes meaning
// for one column and does not re-parse for several.
func TestJoinUsing_SQLRoundTrip_Issue603(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"SELECT * FROM a JOIN b USING (id)", "SELECT * FROM a INNER JOIN b USING (id)"},
		{"SELECT * FROM a LEFT JOIN b USING (id, k)", "SELECT * FROM a LEFT JOIN b USING (id, k)"},
		{"SELECT * FROM a FULL OUTER JOIN b USING (id)", "SELECT * FROM a FULL JOIN b USING (id)"},
		{
			"SELECT * FROM a JOIN b USING (id) JOIN c USING (k) WHERE x = 1",
			"SELECT * FROM a INNER JOIN b USING (id) INNER JOIN c USING (k) WHERE x = 1",
		},
	}

	for _, d := range joinUsingSQLDialects {
		for _, tc := range cases {
			t.Run(string(d)+"/"+tc.in, func(t *testing.T) {
				tree, err := parser.ParseWithDialect(tc.in, d)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.in, err)
				}
				defer ast.ReleaseAST(tree)
				first := usingNames(t, tree)

				got := tree.SQL()
				if got != tc.want {
					t.Fatalf("SQL() mismatch\n got: %q\nwant: %q", got, tc.want)
				}

				tree2, err := parser.ParseWithDialect(got, d)
				if err != nil {
					t.Fatalf("re-parse of %q failed: %v", got, err)
				}
				defer ast.ReleaseAST(tree2)
				if again := tree2.SQL(); again != got {
					t.Fatalf("SQL() not idempotent\nfirst:  %q\nsecond: %q", got, again)
				}
				if second := usingNames(t, tree2); !reflect.DeepEqual(first, second) {
					t.Fatalf("USING columns changed across round trip: %v -> %v", first, second)
				}
			})
		}
	}
}

// TestJoinUsing_SQLDirectConstruction_Issue603 renders a hand-built USING join.
func TestJoinUsing_SQLDirectConstruction_Issue603(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "a"}},
		Joins: []ast.JoinClause{{
			Type:  "INNER",
			Left:  ast.TableReference{Name: "a"},
			Right: ast.TableReference{Name: "b"},
			Using: []ast.Expression{&ast.Identifier{Name: "id"}},
		}},
	}
	if got, want := stmt.SQL(), "SELECT * FROM a INNER JOIN b USING (id)"; got != want {
		t.Fatalf("SQL() = %q, want %q", got, want)
	}
}

// TestJoinClause_ChildrenIncludesUsing checks that the USING columns are
// exposed to Children(), Walk and Inspect.
func TestJoinClause_ChildrenIncludesUsing(t *testing.T) {
	id := &ast.Identifier{Name: "id"}
	k := &ast.Identifier{Name: "k"}
	j := ast.JoinClause{
		Type:  "LEFT",
		Left:  ast.TableReference{Name: "a"},
		Right: ast.TableReference{Name: "b"},
		Using: []ast.Expression{id, k},
	}

	children := j.Children()
	if len(children) != 4 {
		t.Fatalf("Children() returned %d nodes, want 4 (Left, Right, id, k)", len(children))
	}
	if l, ok := children[0].(*ast.TableReference); !ok || l.Name != "a" {
		t.Errorf("Children()[0] = %#v, want Left table a", children[0])
	}
	if r, ok := children[1].(*ast.TableReference); !ok || r.Name != "b" {
		t.Errorf("Children()[1] = %#v, want Right table b", children[1])
	}
	if children[2] != ast.Node(id) || children[3] != ast.Node(k) {
		t.Errorf("Children()[2:] = %v, want the USING identifiers in order", children[2:])
	}

	sel := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "a"}},
		Joins:   []ast.JoinClause{j},
	}
	seen := map[*ast.Identifier]bool{}
	ast.Inspect(sel, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Identifier); ok {
			seen[ident] = true
		}
		return true
	})
	if !seen[id] || !seen[k] {
		t.Errorf("Inspect did not visit both USING identifiers: id=%v k=%v", seen[id], seen[k])
	}

	tree, err := parser.ParseWithDialect("SELECT * FROM a LEFT JOIN b USING (id, k)", keywords.DialectGeneric)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	var names []string
	v := identCollector{names: &names}
	if err := ast.Walk(v, tree.Statements[0]); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"*", "id", "k"}) {
		t.Errorf("Walk visited identifiers %v, want [* id k]", names)
	}
}

type identCollector struct{ names *[]string }

func (c identCollector) Visit(n ast.Node) (ast.Visitor, error) {
	if ident, ok := n.(*ast.Identifier); ok {
		*c.names = append(*c.names, ident.Name)
	}
	return c, nil
}

// TestJoinUsing_PoolRelease_Issue603 parses and releases USING joins
// concurrently (run under -race) and checks pooled statements come back
// without stale joins.
func TestJoinUsing_PoolRelease_Issue603(t *testing.T) {
	const sql = "SELECT * FROM a LEFT JOIN b USING (id, k) JOIN c USING (z)"
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				tree, err := parser.ParseWithDialect(sql, keywords.DialectGeneric)
				if err != nil {
					errs <- err
					return
				}
				ast.ReleaseAST(tree)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("parse failed: %v", err)
	}

	for i := 0; i < 16; i++ {
		s := ast.GetSelectStatement()
		if len(s.Joins) != 0 {
			t.Fatalf("pooled SelectStatement has %d stale joins", len(s.Joins))
		}
		for _, j := range s.Joins[:cap(s.Joins)] {
			if len(j.Using) != 0 || j.Condition != nil {
				t.Fatalf("pooled SelectStatement retains join state: %+v", j)
			}
		}
		ast.PutSelectStatement(s)
	}
}
