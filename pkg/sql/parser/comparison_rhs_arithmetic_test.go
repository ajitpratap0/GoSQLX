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

// Package parser - comparison_rhs_arithmetic_test.go
// Tests for arithmetic and concatenation on the right-hand side of a
// comparison, LIKE, or REGEXP operator (issue #596).

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// rhs596Dialects is every dialect the parser supports.
var rhs596Dialects = []keywords.SQLDialect{
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectMariaDB,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSQLite,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
}

// rhs596Shape renders an expression tree as a fully parenthesized
// s-expression so a test can assert operator binding: a = 1 + 2 renders as
// (= a (+ 1 2)). Leaves render through their own SQL().
func rhs596Shape(t *testing.T, e ast.Expression) string {
	t.Helper()
	switch n := e.(type) {
	case *ast.BinaryExpression:
		op := n.Operator
		if n.Not {
			op = "NOT " + op
		}
		return "(" + op + " " + rhs596Shape(t, n.Left) + " " + rhs596Shape(t, n.Right) + ")"
	case *ast.ParenthesizedExpression:
		return "(PAREN " + rhs596Shape(t, n.Expr) + ")"
	case *ast.UnaryExpression:
		return "(" + n.Operator.String() + " " + rhs596Shape(t, n.Expr) + ")"
	case *ast.BetweenExpression:
		return "(BETWEEN " + rhs596Shape(t, n.Expr) + " " + rhs596Shape(t, n.Lower) + " " + rhs596Shape(t, n.Upper) + ")"
	case *ast.InExpression:
		parts := make([]string, 0, len(n.List))
		for _, v := range n.List {
			parts = append(parts, rhs596Shape(t, v))
		}
		return "(IN " + rhs596Shape(t, n.Expr) + " [" + strings.Join(parts, " ") + "])"
	}
	s, ok := e.(interface{ SQL() string })
	if !ok {
		t.Fatalf("expression %T has no SQL() method", e)
	}
	return s.SQL()
}

// rhs596Case is one #596 parse case: sql parsed in each listed dialect must
// give a WHERE clause of the given shape and a SQL() that re-parses to itself.
type rhs596Case struct {
	name      string
	where     string // WHERE clause body appended to "SELECT * FROM t WHERE "
	wantShape string
	dialects  []keywords.SQLDialect // nil means every dialect
}

func runRHS596Cases(t *testing.T, cases []rhs596Case) {
	t.Helper()
	for _, tc := range cases {
		dialects := tc.dialects
		if dialects == nil {
			dialects = rhs596Dialects
		}
		for _, d := range dialects {
			t.Run(tc.name+"/"+string(d), func(t *testing.T) {
				sql := "SELECT * FROM t WHERE " + tc.where
				tree, err := ParseWithDialect(sql, d)
				if err != nil {
					t.Fatalf("ParseWithDialect(%q, %s): %v", sql, d, err)
				}
				defer ast.ReleaseAST(tree)
				if len(tree.Statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
				}
				stmt, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				if got := rhs596Shape(t, stmt.Where); got != tc.wantShape {
					t.Fatalf("WHERE shape = %s, want %s", got, tc.wantShape)
				}

				got := tree.SQL()
				if got != sql {
					t.Fatalf("SQL() = %q, want %q", got, sql)
				}
				tree2, err := ParseWithDialect(got, d)
				if err != nil {
					t.Fatalf("re-parse of SQL() %q: %v", got, err)
				}
				defer ast.ReleaseAST(tree2)
				if again := tree2.SQL(); again != got {
					t.Fatalf("re-parse SQL() = %q, want fixpoint %q", again, got)
				}
			})
		}
	}
}

func TestParser_ComparisonRHSArithmetic_Issue596(t *testing.T) {
	questionDialects := []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite}
	oracleOnly := []keywords.SQLDialect{keywords.DialectOracle}

	runRHS596Cases(t, []rhs596Case{
		// Repro rows from the issue.
		{name: "eq_plus_literals", where: "a = 1 + 2", wantShape: "(= a (+ 1 2))"},
		{name: "eq_mul", where: "a = b * 2", wantShape: "(= a (* b 2))"},
		{name: "gt_minus", where: "a > b - 1", wantShape: "(> a (- b 1))"},
		{name: "parenthesized", where: "(a = 1 + 2)", wantShape: "(PAREN (= a (+ 1 2)))"},
		{name: "lhs_arithmetic", where: "a + 1 = 2", wantShape: "(= (+ a 1) 2)"},
		{name: "rhs_parenthesized", where: "a = (1 + 2)", wantShape: "(= a (PAREN (+ 1 2)))"},
		{name: "both_sides", where: "a * 2 = b + 1", wantShape: "(= (* a 2) (+ b 1))"},
		{name: "dollar_placeholder", where: "a = $1 + 1", wantShape: "(= a (+ $1 1))"},
		{name: "question_placeholder", where: "a = ? + 1", wantShape: "(= a (+ ? 1))", dialects: questionDialects},
		{name: "oracle_bind", where: "a = :1 + :2", wantShape: "(= a (+ :1 :2))", dialects: oracleOnly},

		// Every comparison operator.
		{name: "op_eq", where: "a = b + 1", wantShape: "(= a (+ b 1))"},
		{name: "op_neq_ansi", where: "a <> b % 2", wantShape: "(<> a (% b 2))"},
		{name: "op_neq_bang", where: "a != b / 2", wantShape: "(!= a (/ b 2))"},
		{name: "op_lt", where: "a < b - 1", wantShape: "(< a (- b 1))"},
		{name: "op_lte", where: "a <= b * 3", wantShape: "(<= a (* b 3))"},
		{name: "op_gt", where: "a > b + c", wantShape: "(> a (+ b c))"},
		{name: "op_gte", where: "a >= -b + 1", wantShape: "(>= a (+ (- b) 1))"},

		// Precedence within the right operand.
		{name: "mul_binds_tighter_than_add", where: "a = 1 + 2 * 3", wantShape: "(= a (+ 1 (* 2 3)))"},
		{name: "additive_left_assoc", where: "a = b - 1 - 2", wantShape: "(= a (- (- b 1) 2))"},
		{name: "paren_group_then_mul", where: "a = (1 + 2) * 3", wantShape: "(= a (* (PAREN (+ 1 2)) 3))"},
		{name: "unary_minus_operand", where: "a = 1 - -2", wantShape: "(= a (- 1 (- 2)))"},
		{name: "concat_rhs", where: "a = b || 'x' || c", wantShape: "(= a (|| (|| b 'x') c))"},
		{name: "concat_of_sum", where: "a = b || c + 1", wantShape: "(= a (|| b (+ c 1)))"},

		// Boolean connectives still bind looser than comparison.
		{
			name:      "and_or_mix",
			where:     "a = 1 + 2 AND b = 3 * 4 OR c < d - 1",
			wantShape: "(OR (AND (= a (+ 1 2)) (= b (* 3 4))) (< c (- d 1)))",
		},
		{name: "not_comparison", where: "NOT a = b + 1", wantShape: "(NOT (= a (+ b 1)))"},
		{name: "rhs_then_is_null", where: "a = b - 1 AND c IS NULL", wantShape: "(AND (= a (- b 1)) (IS NULL c NULL))"},

		// Other predicates with arithmetic operands.
		{name: "between_arith", where: "a BETWEEN 1 + 1 AND 2 * 3", wantShape: "(BETWEEN a (+ 1 1) (* 2 3))"},
		{name: "in_arith", where: "a IN (1 + 1, 2)", wantShape: "(IN a [(+ 1 1) 2])"},
		{name: "like_concat", where: "a LIKE b || '%'", wantShape: "(LIKE a (|| b '%'))"},
		{name: "not_like_concat", where: "a NOT LIKE '%' || b || '%'", wantShape: "(NOT LIKE a (|| (|| '%' b) '%'))"},
		{name: "is_null", where: "a IS NULL", wantShape: "(IS NULL a NULL)"},
	})
}

func TestParser_ComparisonRHSArithmetic_DialectOperators_Issue596(t *testing.T) {
	runRHS596Cases(t, []rhs596Case{
		{
			name:      "regexp_concat",
			where:     "a REGEXP b || 'x'",
			wantShape: "(REGEXP a (|| b 'x'))",
			dialects:  []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB},
		},
		{
			name:      "ilike_concat",
			where:     "a ILIKE b || '%'",
			wantShape: "(ILIKE a (|| b '%'))",
			dialects:  []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectSnowflake, keywords.DialectClickHouse},
		},
	})
}

// TestParser_ComparisonNotChainable_Issue596 guards against the fix making
// comparisons chainable or right-associative: a second comparison operator
// after a complete comparison must still be rejected.
func TestParser_ComparisonNotChainable_Issue596(t *testing.T) {
	for _, where := range []string{
		"a = b = c",
		"a < b < c",
		"a = 1 + 2 = 3",
		"a <> b + 1 >= c",
	} {
		for _, d := range rhs596Dialects {
			t.Run(where+"/"+string(d), func(t *testing.T) {
				sql := "SELECT * FROM t WHERE " + where
				tree, err := ParseWithDialect(sql, d)
				if tree != nil {
					defer ast.ReleaseAST(tree)
				}
				if err == nil {
					t.Fatalf("ParseWithDialect(%q, %s) succeeded with SQL() %q; want an error", sql, d, tree.SQL())
				}
			})
		}
	}
}

// BenchmarkParser_ComparisonRHS measures expression parsing for comparisons
// with a plain and an arithmetic right operand (#596).
func BenchmarkParser_ComparisonRHS(b *testing.B) {
	queries := []struct {
		name string
		sql  string
	}{
		{"simple_rhs", "SELECT id, name FROM users WHERE a = 1 AND b > c AND d <> 'x'"},
		{"arith_rhs", "SELECT id, name FROM users WHERE a = 1 + 2 AND b > c * 2 AND d <> e - 1"},
	}
	for _, q := range queries {
		b.Run(q.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree, err := ParseWithDialect(q.sql, keywords.DialectPostgreSQL)
				if err != nil {
					b.Fatal(err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}
}
