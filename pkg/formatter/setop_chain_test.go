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
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// setOpReference is the per-level definition of set operation rendering:
// render(Left) + sep + op + sep + render(Right), plus ";" with AddSemicolon,
// recursing on both sides.
func setOpReference(s *ast.SetOperation, opts ast.FormatOptions) string {
	if s == nil {
		return ""
	}
	render := func(st ast.Statement) string {
		if so, ok := st.(*ast.SetOperation); ok {
			return setOpReference(so, opts)
		}
		return formatter.FormatStatement(st, opts)
	}
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
		sb.WriteString(render(s.Left))
	}
	sb.WriteString(sep + op + sep)
	if s.Right != nil {
		sb.WriteString(render(s.Right))
	}
	if opts.AddSemicolon {
		sb.WriteString(";")
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
	ops := []string{"UNION", "Except", "intersect", "MINUS"}
	s := &ast.SetOperation{Operator: ops[rng.Intn(len(ops))], All: rng.Intn(2) == 0}
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
// trees (left- and right-nested, nil and typed-nil operands) for several
// option sets.
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

// TestFormatAST_SetOperationChainLinearTime checks that a long UNION chain
// (a left-deep tree) is formatted in time linear in its length. Re-copying
// the rendered left side at every level takes seconds for this input; the
// linear rendering takes milliseconds, so the bound below is generous.
func TestFormatAST_SetOperationChainLinearTime(t *testing.T) {
	const n = 80000
	sql := "SELECT 1" + strings.Repeat(" UNION SELECT 1", n)
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	start := time.Now()
	out := formatter.FormatAST(tree, ast.FormatOptions{})
	elapsed := time.Since(start)

	if out != sql {
		t.Fatalf("formatted output differs from input (len %d vs %d)", len(out), len(sql))
	}
	if elapsed > 2*time.Second {
		t.Fatalf("formatting %d UNIONs took %v, want well under 2s", n, elapsed)
	}
}
