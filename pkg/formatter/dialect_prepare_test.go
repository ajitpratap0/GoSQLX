// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestPrepareDialectNodeOnlyCopiesChanges(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		expr         ast.Expression
	}{
		{"plain cast", "mysql", &ast.CastExpression{Expr: &ast.Identifier{Name: "x"}, Type: "INT"}},
		{"quoted cast", "postgresql", &ast.CastExpression{Expr: &ast.Identifier{Name: "x"}, Type: `"MyType"`}},
		{"power", "postgresql", &ast.BinaryExpression{Operator: "^", Left: &ast.Identifier{Name: "x"}, Right: &ast.Identifier{Name: "y"}}},
		{"xor", "mysql", &ast.BinaryExpression{Operator: "^", BitwiseXor: true, Left: &ast.Identifier{Name: "x"}, Right: &ast.Identifier{Name: "y"}}},
		{"prefix", "postgresql", &ast.UnaryExpression{Operator: ast.PGAbs, Expr: &ast.Identifier{Name: "x"}}},
		{"unicode", "postgresql", &ast.UnicodeEscapeExpression{RawSQL: `U&'d\0061t'`}},
		{"object", "snowflake", &ast.ObjectLiteral{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &ast.SelectStatement{Columns: []ast.Expression{tc.expr}}
			got, err := prepareDialectNode(n, tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Fatal("copied a tree that needs no target rewrite")
			}
			if allocs := testing.AllocsPerRun(100, func() {
				_, _ = prepareDialectNode(n, tc.target)
			}); allocs != 0 {
				t.Errorf("unchanged expression path allocated %g times", allocs)
			}
		})
	}
	for _, n := range []ast.Node{
		&ast.CreateTableStatement{Columns: []ast.ColumnDef{{Name: "x", Type: "INT"}}},
		&ast.CreateMaterializedViewStatement{},
		&ast.AlterStatement{},
	} {
		got, err := prepareDialectNode(n, "mysql")
		if err != nil {
			t.Fatal(err)
		}
		if got != n {
			t.Fatalf("copied %T without a differing type delimiter", n)
		}
	}
}
