// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestScalarSubqueryFreeze(t *testing.T) {
	var columns []string
	for _, d := range corpusDialects() {
		for _, style := range []string{"compact", "readable"} {
			columns = append(columns, d+"_"+style)
		}
	}
	g := goldens.New("scalar_subquery_freeze", "scalar select-list subqueries and caller ownership", columns...)
	for i, sql := range []string{
		"SELECT (SELECT max(x) FROM t) FROM u",
		"SELECT (SELECT (SELECT max(x) FROM t) FROM u) FROM v",
		"SELECT EXISTS (SELECT x FROM t) FROM u",
		"SELECT x IN (SELECT y FROM t) FROM u",
		"SELECT ((SELECT max(x) FROM t)) AS answer FROM u",
		"SELECT (SELECT a ^ b FROM t) AS bits FROM u",
	} {
		tree, err := gosqlx.Parse(sql)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		before, err := gosqlx.Parse(sql)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range corpusDialects() {
			for _, style := range []string{"compact", "readable"} {
				opts := ast.CompactStyle()
				if style == "readable" {
					opts = ast.ReadableStyle()
				}
				opts.Dialect = d
				out, err := formatter.FormatASTChecked(tree, opts)
				if err != nil {
					out = "ERR:" + err.Error()
				}
				g.Add("scalar_subqueries", d+"_"+style, i, sql, out)
				if !reflect.DeepEqual(tree, before) {
					t.Errorf("case %d %s/%s mutated caller's column tree", i, d, style)
				}
			}
		}
		ast.ReleaseAST(tree)
		ast.ReleaseAST(before)
	}
	if len(columns) != 16 {
		t.Fatalf("got %d target/style columns, want 16", len(columns))
	}
	g.Check(t)
}
