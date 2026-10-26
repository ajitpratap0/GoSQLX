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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

type nestedCase struct {
	name string
	in   string
	want string
}

var nestedSemicolonCases = []nestedCase{
	{"cte", "WITH c AS (SELECT 1) SELECT * FROM c", "WITH c AS (SELECT 1)\nSELECT *\nFROM c;"},
	{"in subquery", "SELECT * FROM t WHERE a IN (SELECT 1)", "SELECT *\nFROM t\nWHERE a IN (SELECT 1);"},
	{"exists", "SELECT * FROM t WHERE EXISTS (SELECT 1)", "SELECT *\nFROM t\nWHERE EXISTS (SELECT 1);"},
	{"union", "SELECT 1 UNION SELECT 2", "SELECT 1\nUNION\nSELECT 2;"},
	{"insert select", "INSERT INTO t (a) SELECT a FROM u", "INSERT INTO t (a)\nSELECT a\nFROM u;"},
	{"create view", "CREATE VIEW v AS SELECT 1", "CREATE VIEW v AS\nSELECT 1;"},
	{"union chain", "SELECT 1 UNION SELECT 2 UNION ALL SELECT 3", "SELECT 1\nUNION\nSELECT 2\nUNION ALL\nSELECT 3;"},
	{"materialized view", "CREATE MATERIALIZED VIEW mv AS SELECT 1", "CREATE MATERIALIZED VIEW mv AS\nSELECT 1;"},
	{"view over union", "CREATE VIEW v AS SELECT 1 UNION SELECT 2", "CREATE VIEW v AS\nSELECT 1\nUNION\nSELECT 2;"},
	{"insert over union", "INSERT INTO t (a) SELECT 1 UNION SELECT 2", "INSERT INTO t (a)\nSELECT 1\nUNION\nSELECT 2;"},
	{"cte over union", "WITH c AS (SELECT 1 UNION SELECT 2) SELECT * FROM c", "WITH c AS (SELECT 1\nUNION\nSELECT 2)\nSELECT *\nFROM c;"},
	{"scalar subquery in where", "SELECT * FROM t WHERE (SELECT true)", "SELECT *\nFROM t\nWHERE (SELECT true);"},
	{"case when exists", "SELECT * FROM t WHERE CASE WHEN EXISTS (SELECT 1) THEN true END", "SELECT *\nFROM t\nWHERE CASE WHEN EXISTS (SELECT 1) THEN true END;"},
	{"between subquery", "SELECT * FROM t WHERE a BETWEEN (SELECT 1) AND 2", "SELECT *\nFROM t\nWHERE a BETWEEN (SELECT 1) AND 2;"},
	{"update in", "UPDATE t SET a = 1 WHERE b IN (SELECT 1)", "UPDATE t\nSET a = 1\nWHERE b IN (SELECT 1);"},
	{"delete exists", "DELETE FROM t WHERE EXISTS (SELECT 1)", "DELETE FROM t\nWHERE EXISTS (SELECT 1);"},
	{"with update", "WITH c AS (SELECT 1) UPDATE t SET a = 1", "WITH c AS (SELECT 1)\nUPDATE t\nSET a = 1;"},
	{"with insert", "WITH c AS (SELECT 1) INSERT INTO t SELECT * FROM c", "WITH c AS (SELECT 1)\nINSERT INTO t\nSELECT *\nFROM c;"},
	{"nested cte", "WITH a AS (WITH b AS (SELECT 1) SELECT * FROM b) SELECT * FROM a", "WITH a AS (WITH b AS (SELECT 1)\nSELECT *\nFROM b)\nSELECT *\nFROM a;"},
	{"with union", "WITH c AS (SELECT 1) SELECT * FROM c UNION SELECT 2", "WITH c AS (SELECT 1)\nSELECT *\nFROM c\nUNION\nSELECT 2;"},
	{"partial index", "CREATE INDEX i ON t (a) WHERE a IN (SELECT 1)", "CREATE INDEX i ON t (a)\nWHERE a IN (SELECT 1);"},
	{"multi statement", "SELECT 1; SELECT 2 UNION SELECT 3", "SELECT 1;\nSELECT 2\nUNION\nSELECT 3;"},
	{"control derived table", "SELECT * FROM (SELECT 1) s", "SELECT *\nFROM (SELECT 1) s;"},
	{"control select-list subquery", "SELECT (SELECT 1)", "SELECT (SELECT 1);"},
}

func mustParse(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse(%q): %v", sql, err)
	}
	return tree
}

func TestFormat_NestedStatementsNoInnerSemicolon(t *testing.T) {
	for _, tc := range nestedSemicolonCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := formatter.FormatString(tc.in)
			if err != nil {
				t.Fatalf("FormatString(%q): %v", tc.in, err)
			}
			if out != tc.want {
				t.Fatalf("FormatString(%q):\n got  %q\n want %q", tc.in, out, tc.want)
			}
			// Output must re-parse.
			outTree := mustParse(t, out)

			// Idempotent.
			again, err := formatter.FormatString(out)
			if err != nil {
				t.Fatalf("FormatString(output): %v", err)
			}
			if again != out {
				t.Errorf("not idempotent:\n first  %q\n second %q", out, again)
			}

			// Equivalent AST.
			inCompact := formatter.FormatAST(mustParse(t, tc.in), ast.CompactStyle())
			outCompact := formatter.FormatAST(outTree, ast.CompactStyle())
			if inCompact != outCompact {
				t.Errorf("AST differs after format:\n in  %q\n out %q", inCompact, outCompact)
			}
		})
	}
}

func TestFormat_NestedStatementsCompactUnchanged(t *testing.T) {
	for _, tc := range nestedSemicolonCases {
		t.Run(tc.name, func(t *testing.T) {
			tree := mustParse(t, tc.in)
			out := formatter.FormatAST(tree, ast.CompactStyle())
			// Compact style only uses ';' to separate top-level statements.
			if got, want := strings.Count(out, ";"), len(tree.Statements)-1; got != want {
				t.Errorf("compact output has %d ';', want %d: %q", got, want, out)
			}
			mustParse(t, out)
		})
	}
}

func TestFormatAST_ReadableSemicolonOnlyTerminatesStatements(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("testdata directory not available: %v", err)
	}
	noSemi := ast.ReadableStyle()
	noSemi.AddSemicolon = false

	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		content := strings.ReplaceAll(string(data), "\r\n", "\n")
		for i, stmt := range gosqlx.SplitStatements(content, "") {
			tree, perr := gosqlx.Parse(stmt)
			if perr != nil {
				continue
			}
			checked++
			withSemi := formatter.FormatAST(tree, ast.ReadableStyle())
			without := formatter.FormatAST(tree, noSemi)
			if strings.TrimSuffix(withSemi, ";") != without {
				t.Errorf("%s statement %d: ';' appears other than as the final terminator:\n with    %q\n without %q", path, i, withSemi, without)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking testdata: %v", err)
	}
	if checked < 50 {
		t.Fatalf("only %d statements checked; expected at least 50", checked)
	}
}

func TestFormatExpression_SubqueryNoSemicolon(t *testing.T) {
	sel := func() *ast.SelectStatement {
		return &ast.SelectStatement{Columns: []ast.Expression{&ast.LiteralValue{Value: 1, Type: "int"}}}
	}
	exprs := map[string]ast.Expression{
		"in":       &ast.InExpression{Expr: &ast.Identifier{Name: "a"}, Subquery: sel()},
		"exists":   &ast.ExistsExpression{Subquery: sel()},
		"subquery": &ast.SubqueryExpression{Subquery: sel()},
	}
	for name, e := range exprs {
		t.Run(name, func(t *testing.T) {
			out := formatter.FormatExpression(e, ast.ReadableStyle())
			if out == "" {
				t.Fatalf("empty output")
			}
			if strings.Contains(out, ";") {
				t.Errorf("output contains ';': %q", out)
			}
		})
	}
}
