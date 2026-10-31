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
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/scaletest"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Sixteenfold expression growth must stay far below the 256-fold cost of
// repeatedly rendering or scanning every descendant: linear work grows ~16x,
// and the 64x allocation bound leaves room for noise. Measured running time
// of the deepest shapes grows 30-70x for 16x input (deep recursion touches
// more stack and cache), so its bound is 128x, still half the quadratic 256x. Build ASTs outside the measurement
// so parser limits and parsing time do not conceal formatter regressions.
//
// Two measures are used. Allocations per call are deterministic and checked
// everywhere, including under the race detector; they catch regressions that
// re-render subtrees. Running time (repeated, interleaved min-of-N, see
// scaletest) also catches allocation-free rescans, but race instrumentation
// inflates allocation-heavy paths unevenly across sizes, so it is skipped
// there.
func TestFormatASTExpressionLinearGrowth(t *testing.T) {
	for _, shape := range []struct {
		name  string
		small int
		build func(int, bool) (*ast.AST, string)
	}{
		{"left_deep_binary", 512, scalingBinaryExpression},
		{"nested_parentheses_case_function", 256, scalingNestedExpression},
		{"long_marker_identifier", 4096, scalingMarkerIdentifier},
		{"many_marker_literals", 256, scalingMarkerLiterals},
	} {
		t.Run(shape.name, func(t *testing.T) {
			for _, mode := range []struct {
				name  string
				lower bool
			}{
				{"upper", false},
				{"lower", true},
			} {
				t.Run(mode.name, func(t *testing.T) {
					opts := ast.CompactStyle()
					if mode.lower {
						opts.KeywordCase = ast.KeywordLower
					}
					small, smallWant := shape.build(shape.small, mode.lower)
					large, largeWant := shape.build(16*shape.small, mode.lower)
					for _, tc := range []struct {
						tree *ast.AST
						want string
					}{{small, smallWant}, {large, largeWant}} {
						if got := formatter.FormatAST(tc.tree, opts); got != tc.want {
							t.Fatalf("formatted expression differs: got length %d, want %d", len(got), len(tc.want))
						}
					}
					format := func(tree *ast.AST) func() {
						return func() { runtime.KeepAlive(formatter.FormatAST(tree, opts)) }
					}
					smallAllocs := testing.AllocsPerRun(5, format(small))
					largeAllocs := testing.AllocsPerRun(5, format(large))
					t.Logf("allocs/op n=%d: %.0f; n=%d: %.0f", shape.small, smallAllocs, 16*shape.small, largeAllocs)
					if largeAllocs > 64*smallAllocs {
						t.Errorf("sixteenfold expression growth went from %.0f to %.0f allocations, exceeding 64x", smallAllocs, largeAllocs)
					}
					if raceEnabled || testing.Short() {
						return
					}
					scaletest.AssertLinearGrowth(t, "FormatAST", 128, format(small), format(large))
				})
			}
		})
	}
}

func scalingBinaryExpression(n int, lower bool) (*ast.AST, string) {
	var expr ast.Expression = &ast.Identifier{Name: "a0"}
	var want strings.Builder
	if lower {
		want.WriteString("select ")
	} else {
		want.WriteString("SELECT ")
	}
	want.WriteString("a0")
	for i := 1; i < n; i++ {
		name := fmt.Sprintf("a%d", i)
		expr = &ast.BinaryExpression{Left: expr, Operator: "+", Right: &ast.Identifier{Name: name}}
		want.WriteString(" + ")
		want.WriteString(name)
	}
	return &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{expr}}}}, want.String()
}

func scalingNestedExpression(n int, lower bool) (*ast.AST, string) {
	var expr ast.Expression = &ast.Identifier{Name: "MixedName"}
	for i := 0; i < n; i++ {
		expr = &ast.ParenthesizedExpression{Expr: &ast.CaseExpression{
			WhenClauses: []ast.WhenClause{{Condition: &ast.Identifier{Name: "Flag"}, Result: &ast.FunctionCall{Name: "ABS", Arguments: []ast.Expression{expr}}}},
			ElseClause:  &ast.Identifier{Name: "Fallback"},
		}}
	}
	prefix, suffix, selectSQL := "(CASE WHEN Flag THEN ABS(", ") ELSE Fallback END)", "SELECT "
	if lower {
		prefix, suffix, selectSQL = "(case when Flag then abs(", ") else Fallback end)", "select "
	}
	want := selectSQL + strings.Repeat(prefix, n) + "MixedName" + strings.Repeat(suffix, n)
	return &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{expr}}}}, want
}

func scalingMarkerIdentifier(n int, lower bool) (*ast.AST, string) {
	name := "gosqlx_case_slot_" + strings.Repeat("_", n)
	prefix := "SELECT "
	if lower {
		prefix = "select "
	}
	return &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: name}}}}}, prefix + name
}

func scalingMarkerLiterals(n int, lower bool) (*ast.AST, string) {
	args := make([]ast.Expression, n)
	var want strings.Builder
	if lower {
		want.WriteString("select coalesce(")
	} else {
		want.WriteString("SELECT COALESCE(")
	}
	for i := range args {
		value := fmt.Sprintf("gosqlx_case_slot_%d_0_", i)
		args[i] = &ast.LiteralValue{Type: "string", Value: value}
		if i > 0 {
			want.WriteString(", ")
		}
		want.WriteString("'")
		want.WriteString(value)
		want.WriteString("'")
	}
	want.WriteString(")")
	expr := &ast.FunctionCall{Name: "COALESCE", Arguments: args}
	return &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{expr}}}}, want.String()
}
