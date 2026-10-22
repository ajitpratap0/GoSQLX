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
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// setOpReference is the per-level definition of set operation rendering:
// render(Left) + sep + op + sep + render(Right), recursing on both sides with
// operands rendered without ";", and a single trailing ";" after the whole
// top-level set operation when AddSemicolon is set (#602). An operand is
// wrapped in parentheses when its Parenthesized flag is set or when it is a
// non-nil *SetOperation that standard precedence would not group as the
// tree does (#612); see ast.SetOperandNeedsParens.
func setOpReference(s *ast.SetOperation, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	inner := opts
	inner.AddSemicolon = false
	out := setOpReferenceBody(s, inner)
	if opts.AddSemicolon {
		out += ";"
	}
	return out
}

func setOpReferenceBody(s *ast.SetOperation, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	render := func(st ast.Statement) string {
		if so, ok := st.(*ast.SetOperation); ok {
			return setOpReferenceBody(so, opts)
		}
		return formatter.FormatStatement(st, opts)
	}
	operand := func(st ast.Statement, parens bool) string {
		if !parens {
			return render(st)
		}
		return "(" + render(st) + ")"
	}
	// A right set operation is parenthesized unless standard precedence
	// already groups it (A UNION B INTERSECT C).
	rightParens := ast.SetOperandNeedsParens(s, true, opts.Dialect)
	sep := " "
	if opts.NewlinePerClause {
		sep = "\n"
	}
	op := s.Operator
	if s.All {
		op += " ALL"
	}
	switch opts.KeywordCase {
	case ast.KeywordUpper:
		op = strings.ToUpper(op)
	case ast.KeywordLower:
		op = strings.ToLower(op)
	}
	var sb strings.Builder
	if s.Left != nil {
		sb.WriteString(operand(s.Left, ast.SetOperandNeedsParens(s, false, opts.Dialect)))
	}
	sb.WriteString(sep + op + sep)
	if s.Right != nil {
		sb.WriteString(operand(s.Right, rightParens))
	}
	return sb.String()
}

func randSetOp(rng *rand.Rand, depth int) *ast.SetOperation {
	leaf := func() ast.Statement {
		switch rng.Intn(8) {
		case 0:
			return nil
		case 1:
			return (*ast.SetOperation)(nil)
		default:
			return &ast.SelectStatement{
				Columns: []ast.Expression{&ast.Identifier{Name: string(rune('a' + rng.Intn(26)))}},
				From:    []ast.TableReference{{Name: "t"}},
			}
		}
	}
	// Hand-built operators in any case; MINUS is not one (the parser
	// stores it as EXCEPT, and the renderers do not write it, see
	// ast.SetOperatorText).
	ops := []string{"UNION", "Except", "intersect", "union"}
	s := &ast.SetOperation{
		Operator:           ops[rng.Intn(len(ops))],
		All:                rng.Intn(2) == 0,
		LeftParenthesized:  rng.Intn(6) == 0,
		RightParenthesized: rng.Intn(6) == 0,
	}
	if depth > 0 && rng.Intn(4) != 0 {
		s.Left = randSetOp(rng, depth-1)
	} else {
		s.Left = leaf()
	}
	if depth > 0 && rng.Intn(5) == 0 {
		s.Right = randSetOp(rng, depth-1)
	} else {
		s.Right = leaf()
	}
	return s
}

// TestFormatStatement_SetOperationMatchesReference checks the iterative
// rendering of set operation chains against setOpReference on generated
// trees (left- and right-nested, nil and typed-nil operands, parenthesized
// operands) for several option sets.
func TestFormatStatement_SetOperationMatchesReference(t *testing.T) {
	optSets := []ast.FormatOptions{
		ast.CompactStyle(),
		ast.ReadableStyle(),
		{KeywordCase: ast.KeywordLower, NewlinePerClause: true, IndentWidth: 4},
		{KeywordCase: ast.KeywordUpper, AddSemicolon: true},
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		s := randSetOp(rng, rng.Intn(8))
		for _, opts := range optSets {
			got := formatter.FormatStatement(s, opts)
			if want := setOpReference(s, opts); got != want {
				t.Fatalf("tree %d, opts %+v:\n got  %q\n want %q", i, opts, got, want)
			}
		}
	}
}

// TestFormatAST_SetOperationChainLinearGrowth catches repeated copying of
// the rendered prefix: four times as many UNIONs must allocate substantially
// less than the sixteen-fold growth of quadratic copying. Byte growth, rather
// than a wall-clock limit, also works under race and atomic coverage overhead.
// The full 80,000-UNION output must still match exactly. Allocation-free CPU
// regressions can be measured separately with BenchmarkFormatAST_SetOperationChain.
func TestFormatAST_SetOperationChainLinearGrowth(t *testing.T) {
	const small, large = 1024, 4096
	const noiseAllowance = 1 << 20
	var smallBytes uint64
	for _, n := range []int{small, large} {
		sql := "SELECT 1" + strings.Repeat(" UNION SELECT 1", n)
		tree, err := gosqlx.Parse(sql)
		if err != nil {
			t.Fatalf("Parse %d UNIONs: %v", n, err)
		}
		defer ast.ReleaseAST(tree)
		out, allocated := setOperationFormatBytes(tree)
		if out != sql {
			t.Fatalf("formatted %d UNIONs differ from input", n)
		}
		t.Logf("%d UNIONs: %d allocated bytes", n, allocated)
		// This permits well over the current per-node cost while rejecting
		// repeated prefix copies at these bounded sizes, before the big case.
		if budget := uint64(n)*2048 + noiseAllowance; allocated > budget {
			t.Fatalf("formatting %d UNIONs allocated %d bytes, limit %d", n, allocated, budget)
		}
		if n == small {
			smallBytes = allocated
		} else if budget := 8*smallBytes + noiseAllowance; allocated > budget {
			t.Fatalf("fourfold UNION growth allocated %d -> %d bytes, limit %d", smallBytes, allocated, budget)
		}
	}

	const n = 80000
	sql := "SELECT 1" + strings.Repeat(" UNION SELECT 1", n)
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	defer ast.ReleaseAST(tree)

	out := formatter.FormatAST(tree, ast.FormatOptions{})

	if out != sql {
		t.Fatalf("formatted output differs from input (len %d vs %d)", len(out), len(sql))
	}
}

// The caller runs sequentially: TotalAlloc includes every goroutine in this
// process. Parsing and a warm-up render are excluded from the measurement.
func setOperationFormatBytes(tree *ast.AST) (string, uint64) {
	opts := ast.FormatOptions{}
	_ = formatter.FormatAST(tree, opts)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out := formatter.FormatAST(tree, opts)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(out)
	return out, after.TotalAlloc - before.TotalAlloc
}

func BenchmarkFormatAST_SetOperationChain(b *testing.B) {
	for _, n := range []int{1024, 4096, 80000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			sql := "SELECT 1" + strings.Repeat(" UNION SELECT 1", n)
			tree, err := gosqlx.Parse(sql)
			if err != nil {
				b.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			b.SetBytes(int64(len(sql)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if out := formatter.FormatAST(tree, ast.FormatOptions{}); len(out) != len(sql) {
					b.Fatalf("formatted length %d, want %d", len(out), len(sql))
				}
			}
			b.StopTimer()
		})
	}
}
