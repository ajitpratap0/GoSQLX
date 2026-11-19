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
// repeatedly rendering or scanning every descendant: linear work grows ~16x.
// The allocation-count bound is 64x; the bytes bound is 128x because the deep
// nested shape legitimately measures up to ~58x bytes for 16x input (stack and
// builder growth) while the injected quadratic measures 233-287x. Build ASTs outside the measurement
// so parser limits and parsing time do not conceal formatter regressions.
//
// Two deterministic measures are used, both valid under the race detector
// (CI runs every test with -race). Allocations per call catch regressions
// that allocate per node. Bytes allocated per call catch regressions that
// re-render or copy subtrees: those keep the allocation count linear but
// make the bytes quadratic (a child rendered into a fresh builder and copied
// into its parent grew bytes 233-287x for 16x input, against 58x or less for
// the linear code, while allocs/op moved only 16x). No wall-clock check is
// made: deep recursion legitimately grows time 30-70x for 16x input, so a
// time bound loose enough to be stable would also let that regression through.
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
					scaletest.AssertLinearBytes(t, "FormatAST", 128, format(small), format(large))
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
