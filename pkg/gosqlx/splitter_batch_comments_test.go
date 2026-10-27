// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestSplitStatementsGOLineComments(t *testing.T) {
	for _, tc := range []struct {
		line  string
		split bool
	}{
		{"GO", true}, {"go", true}, {"GO 2", true}, {"GO 2 -- c", true},
		{"GO -- c", true}, {"GO /* c */", true}, {"GO 2 /* c */", true},
		{"GO /* multi\nline */", true}, {"GO 0", false}, {"GO x", false},
	} {
		for _, ending := range []string{"\n", "\r\n"} {
			t.Run(tc.line+ending, func(t *testing.T) {
				src := "SELECT 1" + ending + tc.line + ending + "SELECT 2"
				want := 1
				if tc.split {
					want = 2
				}
				if got := SplitStatements(src, "sqlserver"); len(got) != want {
					t.Fatalf("SplitStatements(%q) = %#v, want %d statements", src, got, want)
				}
				if tc.split {
					tree, err := ParseWithDialect(src, keywords.DialectSQLServer)
					if err != nil {
						t.Fatal(err)
					}
					defer ast.ReleaseAST(tree)
					if len(tree.Statements) != 3 {
						t.Fatalf("parser produced %d statements, want two SELECTs and a GO separator", len(tree.Statements))
					}
					if _, ok := tree.Statements[1].(*ast.BatchSeparator); !ok {
						t.Fatalf("expected GO separator, got %T", tree.Statements[1])
					}
				}
			})
		}
	}
}
