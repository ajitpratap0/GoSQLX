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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestNestedRowLimitRenderingPreservesSourceAndCase(t *testing.T) {
	const sql = `SELECT 1 + (SELECT "Mixed" FROM t ORDER BY "Mixed" LIMIT 3) AS "Alias" FROM (SELECT a FROM t LIMIT 2) q`
	tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	before := formatter.FormatAST(tree, ast.CompactStyle())
	for _, lower := range []bool{false, true} {
		opts := ast.CompactStyle()
		opts.Dialect = "oracle"
		want := "FETCH FIRST 3 ROWS ONLY"
		if lower {
			opts.KeywordCase = ast.KeywordLower
			want = strings.ToLower(want)
		}
		got := formatter.FormatAST(tree, opts)
		if !strings.Contains(got, want) || !strings.Contains(got, `"Mixed"`) || !strings.Contains(got, `"Alias"`) {
			t.Fatalf("case or quoted alias lost: %s", got)
		}
		reparsed, err := parser.ParseWithDialect(got, keywords.DialectOracle)
		if err != nil {
			t.Fatalf("target SQL %q does not parse: %v", got, err)
		}
		ast.ReleaseAST(reparsed)
		if after := formatter.FormatAST(tree, ast.CompactStyle()); after != before {
			t.Fatalf("source AST changed: before %q; after %q", before, after)
		}
	}
}

func TestNestedSetTailRenderingPreservesSource(t *testing.T) {
	const sql = "SELECT * FROM (SELECT a FROM t UNION (SELECT b FROM u LIMIT 1) ORDER BY 1 LIMIT 5 OFFSET 2) x"
	tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	before := formatter.FormatAST(tree, ast.CompactStyle())
	for _, target := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectSQLServer} {
		opts := ast.CompactStyle()
		opts.Dialect = string(target)
		got := formatter.FormatAST(tree, opts)
		if strings.Contains(got, "LIMIT") || !strings.Contains(got, "FETCH") {
			t.Fatalf("set tail not normalized: %s", got)
		}
		reparsed, err := parser.ParseWithDialect(got, target)
		if err != nil {
			t.Fatalf("target SQL %q does not parse: %v", got, err)
		}
		ast.ReleaseAST(reparsed)
		if after := formatter.FormatAST(tree, ast.CompactStyle()); after != before {
			t.Fatalf("source set tail changed: before %q; after %q", before, after)
		}
	}
}

func TestSQLServerSetTailWithoutOrderDoesNotDropLimit(t *testing.T) {
	tree, err := parser.ParseWithDialect("SELECT a FROM t UNION (SELECT b FROM u LIMIT 1) LIMIT 5", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	set, ok := tree.Statements[0].(*ast.SetOperation)
	if !ok || set.Tail == nil {
		t.Fatal("regression requires an explicit set-operation tail")
	}
	opts := ast.CompactStyle()
	opts.Dialect = string(keywords.DialectSQLServer)
	got := formatter.FormatAST(tree, opts)
	// The formatter has no error surface for this unsupported set tail. Keep
	// its LIMIT visible; only Transpile may reject it rather than erase it.
	if !strings.HasSuffix(got, "LIMIT 5") {
		t.Fatalf("unsupported set limit silently dropped: %s", got)
	}
}
