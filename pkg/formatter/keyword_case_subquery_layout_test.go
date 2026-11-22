// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestKeywordLowerCompactSubqueryOperands(t *testing.T) {
	opts := ast.ReadableStyle()
	opts.KeywordCase = ast.KeywordLower
	opts.AddSemicolon = false
	for _, tc := range []struct {
		name, input, want string
	}{
		{"binary operand", "SELECT a FROM t WHERE a = (SELECT b FROM u)", "select a\nfrom t\nwhere a = (select b from u)"},
		{"order expression", "SELECT a FROM t ORDER BY (SELECT b FROM u)", "select a\nfrom t\norder by (select b from u)"},
		{"function argument", "SELECT COALESCE((SELECT b FROM u), 0) FROM t", "select coalesce((select b from u), 0)\nfrom t"},
		{"nested exists", "SELECT a FROM t WHERE a = 1 AND EXISTS (SELECT b FROM u)", "select a\nfrom t\nwhere a = 1 and exists (select b from u)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.Parse(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if got := formatter.FormatAST(tree, opts); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}
