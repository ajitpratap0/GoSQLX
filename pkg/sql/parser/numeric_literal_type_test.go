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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestNumericLiteralType(t *testing.T) {
	tests := []struct {
		value, want string
	}{
		{"1", "int"},
		{"1.5", "float"},
		{"5.", "float"},
		{"1e3", "float"},
		{"1E-3", "float"},
		{"0x1F", "int"},
		{"0x1E", "int"},
		{"0X1e", "int"},
		{"0xE", "int"},
		{"0", "int"},
	}
	for _, tt := range tests {
		if got := numericLiteralType(tt.value); got != tt.want {
			t.Errorf("numericLiteralType(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

// TestHexLiteralTypedInt checks that a hex literal whose digits include E is
// typed int: the E is a hex digit, not an exponent.
func TestHexLiteralTypedInt(t *testing.T) {
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectClickHouse, keywords.DialectSQLite} {
		for _, sql := range []string{"SELECT 0x1E", "SELECT 0x1F", "SELECT 0xE5"} {
			t.Run(string(d)+"/"+sql, func(t *testing.T) {
				tree, err := ParseWithDialect(sql, d)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				defer ast.ReleaseAST(tree)
				sel, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("got %T, want *ast.SelectStatement", tree.Statements[0])
				}
				lit, ok := sel.Columns[0].(*ast.LiteralValue)
				if !ok {
					t.Fatalf("got %T, want *ast.LiteralValue", sel.Columns[0])
				}
				if lit.Type != "int" {
					t.Errorf("type = %q, want int", lit.Type)
				}
			})
		}
	}
}
