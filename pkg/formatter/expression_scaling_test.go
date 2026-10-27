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
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Fourfold expression growth must stay below the sixteenfold cost of repeatedly
// rendering or scanning every descendant. Build ASTs outside the measurement so
// parser limits and parsing time do not conceal formatter regressions.
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
					large, largeWant := shape.build(4*shape.small, mode.lower)
					for _, tc := range []struct {
						tree *ast.AST
						want string
					}{{small, smallWant}, {large, largeWant}} {
						if got := formatter.FormatAST(tc.tree, opts); got != tc.want {
							t.Fatalf("formatted expression differs: got length %d, want %d", len(got), len(tc.want))
						}
					}
					smallTime := expressionFormatDuration(small, opts)
					largeTime := expressionFormatDuration(large, opts)
					t.Logf("n=%d: %v; n=%d: %v; ratio %.2f", shape.small, smallTime, 4*shape.small, largeTime, float64(largeTime)/float64(smallTime))
					if largeTime > 10*smallTime {
						t.Fatalf("fourfold expression growth took %v -> %v, exceeding 10x", smallTime, largeTime)
					}
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

// Use the minimum of repeated equal-size batches to limit scheduler and GC
// noise. The assertion compares input sizes, never an absolute time budget.
func expressionFormatDuration(tree *ast.AST, opts ast.FormatOptions) time.Duration {
	var best time.Duration
	for sample := 0; sample < 3; sample++ {
		runtime.GC()
		start := time.Now()
		for batch := 0; batch < 2; batch++ {
			out := formatter.FormatAST(tree, opts)
			runtime.KeepAlive(out)
		}
		elapsed := time.Since(start)
		if best == 0 || elapsed < best {
			best = elapsed
		}
	}
	return best
}
