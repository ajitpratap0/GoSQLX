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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// updateVisitOrder regenerates testdata/visit_order.golden. The golden file
// was generated from the Children() implementation that predates #557, so it
// pins the visit order that the allocation work must preserve.
var updateVisitOrder = flag.Bool("update-visit-order", false, "rewrite testdata/visit_order.golden")

const visitOrderGolden = "testdata/visit_order.golden"

type visitOrderCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
}

var visitOrderCorpus = []visitOrderCase{
	{"select_distinct_on_joins", keywords.DialectPostgreSQL,
		"SELECT DISTINCT ON (a) a, b FROM t1 JOIN t2 ON t1.id = t2.id LEFT JOIN (SELECT id FROM t3) d ON d.id = t1.id WHERE a > 1 GROUP BY a, b HAVING COUNT(*) > 1 ORDER BY a DESC NULLS LAST LIMIT 5"},
	{"window_aggregate_order", keywords.DialectPostgreSQL,
		"SELECT SUM(x) OVER (PARTITION BY g ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW), STRING_AGG(n, ',' ORDER BY n DESC), PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY v) FROM t WINDOW w AS (PARTITION BY g ORDER BY y)"},
	{"case_expressions", keywords.DialectGeneric,
		"SELECT CASE WHEN a = 1 THEN 'x' WHEN a = 2 THEN 'y' ELSE 'z' END, CASE b WHEN 1 THEN 2 END FROM t"},
	{"cte_union", keywords.DialectGeneric,
		"WITH c AS (SELECT 1 AS x) SELECT x FROM c UNION ALL SELECT 2"},
	{"update_returning", keywords.DialectGeneric,
		"UPDATE t SET a = 1, b = b + 1 WHERE id = 2 RETURNING a"},
	{"delete_returning", keywords.DialectGeneric,
		"DELETE FROM t WHERE id = 1 RETURNING id"},
	{"insert_on_conflict", keywords.DialectPostgreSQL,
		"INSERT INTO t (a, b) VALUES (1, 2), (3, 4) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b WHERE t.b < 10 RETURNING a"},
	{"insert_on_duplicate_key", keywords.DialectMySQL,
		"INSERT INTO t (a, b) VALUES (1, 2) ON DUPLICATE KEY UPDATE b = VALUES(b), a = a + 1"},
	{"create_table", keywords.DialectGeneric,
		"CREATE TABLE t (id INT PRIMARY KEY, name VARCHAR(10) NOT NULL DEFAULT 'x', CONSTRAINT ck CHECK (id > 0))"},
	{"create_index", keywords.DialectGeneric,
		"CREATE INDEX idx ON t (a, b) WHERE a > 0"},
	{"merge", keywords.DialectSQLServer,
		"MERGE INTO tgt AS t USING src AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.v = s.v WHEN NOT MATCHED THEN INSERT (id, v) VALUES (s.id, s.v);"},
	{"match_recognize", keywords.DialectSnowflake,
		"SELECT * FROM t MATCH_RECOGNIZE (PARTITION BY s ORDER BY ts MEASURES MATCH_NUMBER() AS m ALL ROWS PER MATCH PATTERN (UP+ DOWN+) DEFINE UP AS price > PREV(price), DOWN AS price < PREV(price))"},
	{"alter_table", keywords.DialectGeneric,
		"ALTER TABLE t ADD COLUMN c INT"},
}

func parseCorpus(t testing.TB, c visitOrderCase) *ast.AST {
	t.Helper()
	tree, err := parser.ParseWithDialect(c.sql, c.dialect)
	if err != nil {
		t.Fatalf("%s: parse %q (%s): %v", c.name, c.sql, c.dialect, err)
	}
	return tree
}

// orderRecorder is a depth-tracking Visitor. Walk calls Visit(nil) once a
// node's children are done, which pops one level.
type orderRecorder struct {
	b     *strings.Builder
	depth int
}

func (r *orderRecorder) Visit(n ast.Node) (ast.Visitor, error) {
	if n == nil {
		r.depth--
		return nil, nil
	}
	fmt.Fprintf(r.b, "%s%T %q\n", strings.Repeat("  ", r.depth), n, n.TokenLiteral())
	r.depth++
	return r, nil
}

func walkOrder(t testing.TB, tree *ast.AST) string {
	t.Helper()
	var b strings.Builder
	for _, stmt := range tree.Statements {
		r := &orderRecorder{b: &b}
		if err := ast.Walk(r, stmt); err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
	return b.String()
}

// childrenOrder walks the tree with nothing but the exported Node.Children,
// the way third-party walkers do, using the same line format as walkOrder.
func childrenOrder(tree *ast.AST) string {
	var b strings.Builder
	var rec func(n ast.Node, depth int)
	rec = func(n ast.Node, depth int) {
		if n == nil {
			return
		}
		fmt.Fprintf(&b, "%s%T %q\n", strings.Repeat("  ", depth), n, n.TokenLiteral())
		for _, c := range n.Children() {
			rec(c, depth+1)
		}
	}
	for _, stmt := range tree.Statements {
		rec(stmt, 0)
	}
	return b.String()
}

func TestWalk_VisitOrderGolden(t *testing.T) {
	var b strings.Builder
	for _, c := range visitOrderCorpus {
		tree := parseCorpus(t, c)
		fmt.Fprintf(&b, "== %s\n", c.name)
		b.WriteString(walkOrder(t, tree))
		ast.ReleaseAST(tree)
	}
	got := b.String()

	path := filepath.FromSlash(visitOrderGolden)
	if *updateVisitOrder {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update-visit-order): %v", err)
	}
	if got != string(want) {
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("visit order differs at line %d:\n got: %s\nwant: %s", i+1, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("visit order differs in length: got %d lines, want %d", len(gotLines), len(wantLines))
	}
}

// TestWalk_MatchesChildrenRecursion guards against Walk's in-place fast path
// drifting from the exported Children() methods.
func TestWalk_MatchesChildrenRecursion(t *testing.T) {
	for _, c := range visitOrderCorpus {
		t.Run(c.name, func(t *testing.T) {
			tree := parseCorpus(t, c)
			defer ast.ReleaseAST(tree)
			if w, r := walkOrder(t, tree), childrenOrder(tree); w != r {
				t.Fatalf("Walk and Children() recursion disagree\nwalk:\n%s\nchildren:\n%s", w, r)
			}
		})
	}
}
