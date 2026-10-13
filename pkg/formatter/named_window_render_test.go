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
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestFormatAST_NamedWindowDefinitions locks in issue #608: a WINDOW
// definition renders as "name AS (base parts...)" without repeating its own
// name inside the parentheses, and a bare OVER w reference stays bare.
func TestFormatAST_NamedWindowDefinitions(t *testing.T) {
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{
			&ast.FunctionCall{Name: "sum", Arguments: []ast.Expression{&ast.Identifier{Name: "x"}}, Over: &ast.WindowSpec{Name: "w2"}},
		},
		From: []ast.TableReference{{Name: "t"}},
		Windows: []ast.WindowSpec{
			{Name: "w", PartitionBy: []ast.Expression{&ast.Identifier{Name: "y"}}},
			{Name: "w2", BaseWindow: "w", OrderBy: []ast.OrderByExpression{{Expression: &ast.Identifier{Name: "z"}, Ascending: true}}},
		},
	}
	tree := &ast.AST{Statements: []ast.Statement{stmt}}

	out := formatter.FormatAST(tree, ast.CompactStyle())
	for _, want := range []string{"OVER w2", "WINDOW w AS (PARTITION BY y), w2 AS (w ORDER BY z)"} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatAST() = %q, want it to contain %q", out, want)
		}
	}

	reparsed, err := gosqlx.Parse(out)
	if err != nil {
		t.Fatalf("re-Parse(FormatAST() = %q) error: %v", out, err)
	}
	defer ast.ReleaseAST(reparsed)
	if got, want := reparsed.SQL(), "SELECT sum(x) OVER w2 FROM t WINDOW w AS (PARTITION BY y), w2 AS (w ORDER BY z)"; got != want {
		t.Errorf("re-parsed SQL() = %q, want %q", got, want)
	}
}
