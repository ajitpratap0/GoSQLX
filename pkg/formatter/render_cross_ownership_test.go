// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestRenderCrossOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		second       ast.Expression
		wantError    bool
	}{
		{"success", "postgresql", &ast.BinaryExpression{Operator: "^", BitwiseXor: true, Left: &ast.Identifier{Name: "a"}, Right: &ast.Identifier{Name: "b"}}, false},
		{"error", "sqlite", &ast.BinaryExpression{Operator: "^", BitwiseXor: true, Left: &ast.Identifier{Name: "a"}, Right: &ast.Identifier{Name: "b"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ast.AST{Statements: []ast.Statement{
				&ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}},
				&ast.SelectStatement{Columns: []ast.Expression{tc.second}},
			}}
			before, ok := copyRenderValue(reflect.ValueOf(tree), make(map[uintptr]reflect.Value)).Interface().(*ast.AST)
			if !ok {
				t.Fatalf("copied tree has unexpected type")
			}
			opts := ast.CompactStyle()
			opts.Dialect = tc.target
			_, err := FormatASTChecked(tree, opts)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
			if !reflect.DeepEqual(tree, before) {
				t.Fatal("render mutated caller's AST")
			}
		})
	}
}
