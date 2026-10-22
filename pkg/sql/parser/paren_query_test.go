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
	"fmt"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Tests for issue #612: parenthesized set operations, WITH queries and
// doubly-parenthesized queries as derived tables, and parenthesized query
// expressions at statement level and as set-operation operands.

// parenDialects is the default parser (no dialect) plus every named dialect.
var parenDialects = []string{
	"", "generic", "postgresql", "mysql", "mariadb", "sqlserver",
	"oracle", "sqlite", "snowflake", "clickhouse",
}

// parenLimitDialects excludes SQL Server and Oracle, which reject LIMIT
// (they use TOP / FETCH FIRST instead).
var parenLimitDialects = []string{
	"", "generic", "postgresql", "mysql", "mariadb", "sqlite", "snowflake", "clickhouse",
}

func dialectName(d string) string {
	if d == "" {
		return "default"
	}
	return d
}

// parenParse parses sql with the default parser (d == "") or dialect d.
func parenParse(t *testing.T, d, sql string) (*ast.AST, error) {
	t.Helper()
	if d == "" {
		return parseSQLMayFail(t, sql)
	}
	return ParseWithDialect(sql, keywords.SQLDialect(d))
}

func parenOnlyStmt(t *testing.T, tree *ast.AST) ast.Statement {
	t.Helper()
	if tree == nil || len(tree.Statements) != 1 {
		t.Fatalf("want exactly one statement, got %v", tree)
	}
	return tree.Statements[0]
}

func parenSelect(t *testing.T, s ast.Statement) *ast.SelectStatement {
	t.Helper()
	sel, ok := s.(*ast.SelectStatement)
	if !ok {
		t.Fatalf("want *ast.SelectStatement, got %T", s)
	}
	return sel
}

func parenSetOp(t *testing.T, s ast.Statement) *ast.SetOperation {
	t.Helper()
	so, ok := s.(*ast.SetOperation)
	if !ok {
		t.Fatalf("want *ast.SetOperation, got %T", s)
	}
	return so
}

// parenShape describes the parts of a statement this fix touches: the kind of
// each derived table, set-operation operators and parenthesization flags, WITH
// clauses and ORDER BY / LIMIT placement. Two trees with equal shapes have the
// same structure for the purposes of the round-trip check.
func parenShape(s ast.Statement) string {
	var sb strings.Builder
	writeParenShape(&sb, s)
	return sb.String()
}

func writeParenShape(sb *strings.Builder, s ast.Statement) {
	switch v := s.(type) {
	case *ast.SelectStatement:
		sb.WriteString("S")
		if v.With != nil {
			fmt.Fprintf(sb, "w%d", len(v.With.CTEs))
			for _, cte := range v.With.CTEs {
				sb.WriteString("<")
				writeParenShape(sb, cte.Statement)
				sb.WriteString(">")
			}
		}
		for i := range v.From {
			writeRefShape(sb, &v.From[i])
		}
		for i := range v.Joins {
			sb.WriteString("j")
			writeRefShape(sb, &v.Joins[i].Right)
		}
		if len(v.OrderBy) > 0 {
			fmt.Fprintf(sb, "o%d", len(v.OrderBy))
		}
		if v.Limit != nil {
			fmt.Fprintf(sb, "l%d", *v.Limit)
		}
	case *ast.SetOperation:
		sb.WriteString("{")
		if v.LeftParenthesized {
			sb.WriteString("(")
		}
		writeParenShape(sb, v.Left)
		sb.WriteString(" " + v.Operator)
		if v.All {
			sb.WriteString(" ALL")
		}
		sb.WriteString(" ")
		if v.RightParenthesized {
			sb.WriteString("(")
		}
		writeParenShape(sb, v.Right)
		sb.WriteString("}")
	case *ast.InsertStatement:
		sb.WriteString("I")
		if v.Query != nil {
			writeParenShape(sb, v.Query)
		}
	default:
		fmt.Fprintf(sb, "%T", s)
	}
}

func writeRefShape(sb *strings.Builder, r *ast.TableReference) {
	switch {
	case r.Subquery != nil:
		sb.WriteString("[")
		writeParenShape(sb, r.Subquery)
		sb.WriteString("]")
	case r.SetSubquery != nil:
		sb.WriteString("[")
		writeParenShape(sb, r.SetSubquery)
		sb.WriteString("]")
	default:
		sb.WriteString("t")
	}
}

type parenCase struct {
	name     string
	sql      string
	want     string // expected tree.SQL(); "" means identical to sql
	dialects []string
	check    func(t *testing.T, s ast.Statement)
}

func (c parenCase) wantSQL() string {
	if c.want == "" {
		return c.sql
	}
	return c.want
}

func (c parenCase) dialectList() []string {
	if c.dialects == nil {
		return parenDialects
	}
	return c.dialects
}

// parenIssueCases are the shapes reported in #612.
var parenIssueCases = []parenCase{
	{
		name: "set op derived table",
		sql:  "SELECT * FROM (SELECT 1 UNION SELECT 2) t",
		check: func(t *testing.T, s ast.Statement) {
			ref := parenSelect(t, s).From[0]
			if ref.Subquery != nil || ref.SetSubquery == nil {
				t.Fatalf("want SetSubquery only, got Subquery=%v SetSubquery=%v", ref.Subquery, ref.SetSubquery)
			}
			if ref.SetSubquery.Operator != "UNION" || ref.Alias != "t" {
				t.Errorf("operator %q alias %q, want UNION t", ref.SetSubquery.Operator, ref.Alias)
			}
			if ref.SetSubquery.LeftParenthesized || ref.SetSubquery.RightParenthesized {
				t.Errorf("unexpected parenthesized flags on %+v", ref.SetSubquery)
			}
		},
	},
	{
		name: "set op derived table in JOIN",
		sql:  "SELECT * FROM t1 JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a",
		want: "SELECT * FROM t1 INNER JOIN (SELECT 1 UNION SELECT 2) t ON t1.a = t.a",
		check: func(t *testing.T, s ast.Statement) {
			sel := parenSelect(t, s)
			if len(sel.Joins) != 1 || sel.Joins[0].Right.SetSubquery == nil {
				t.Fatalf("want Joins[0].Right.SetSubquery, got %+v", sel.Joins)
			}
		},
	},
	{
		name: "parenthesized set op derived table",
		sql:  "SELECT * FROM ((SELECT 1) UNION (SELECT 2)) t",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSelect(t, s).From[0].SetSubquery
			if so == nil || !so.LeftParenthesized || !so.RightParenthesized {
				t.Fatalf("want SetSubquery with both operands parenthesized, got %+v", so)
			}
		},
	},
	{
		name: "doubly parenthesized derived table",
		sql:  "SELECT * FROM ((SELECT 1)) t",
		want: "SELECT * FROM (SELECT 1) t",
		check: func(t *testing.T, s ast.Statement) {
			ref := parenSelect(t, s).From[0]
			if ref.Subquery == nil || ref.SetSubquery != nil || ref.Alias != "t" {
				t.Fatalf("want Subquery with alias t, got %+v", ref)
			}
		},
	},
	{
		name: "WITH derived table",
		sql:  "SELECT * FROM (WITH c AS (SELECT 1 AS a) SELECT a FROM c) t",
		check: func(t *testing.T, s ast.Statement) {
			ref := parenSelect(t, s).From[0]
			if ref.Subquery == nil || ref.Subquery.With == nil {
				t.Fatalf("want Subquery with WITH, got %+v", ref)
			}
		},
	},
	{
		name: "parenthesized operands at statement level",
		sql:  "(SELECT 1) UNION (SELECT 2)",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if !so.LeftParenthesized || !so.RightParenthesized {
				t.Fatalf("want both operands parenthesized, got %+v", so)
			}
		},
	},
	{
		name: "parenthesized statement",
		sql:  "(SELECT 1)",
		want: "SELECT 1",
		check: func(t *testing.T, s ast.Statement) {
			parenSelect(t, s)
		},
	},
	{
		name: "parenthesized statement with ORDER BY",
		sql:  "(SELECT 1) ORDER BY 1",
		want: "SELECT 1 ORDER BY 1",
		check: func(t *testing.T, s ast.Statement) {
			if sel := parenSelect(t, s); len(sel.OrderBy) != 1 {
				t.Fatalf("want one ORDER BY item, got %d", len(sel.OrderBy))
			}
		},
	},
	{
		name: "parenthesized right operand",
		sql:  "SELECT 1 UNION (SELECT 2)",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if so.LeftParenthesized || !so.RightParenthesized {
				t.Fatalf("want only the right operand parenthesized, got %+v", so)
			}
		},
	},
}

// parenExtraCases cover related shapes the fix must handle.
var parenExtraCases = []parenCase{
	{
		name:     "operands with their own ORDER BY and LIMIT",
		sql:      "(SELECT a FROM t ORDER BY a LIMIT 1) UNION ALL (SELECT a FROM u ORDER BY a LIMIT 1)",
		dialects: parenLimitDialects,
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			for _, op := range []ast.Statement{so.Left, so.Right} {
				sel := parenSelect(t, op)
				if len(sel.OrderBy) != 1 || sel.Limit == nil {
					t.Errorf("operand lost ORDER BY/LIMIT: %s", sel.SQL())
				}
			}
		},
	},
	{
		name: "trailing ORDER BY merged into parenthesized right operand",
		sql:  "SELECT a FROM t UNION (SELECT a FROM u) ORDER BY a",
		want: "SELECT a FROM t UNION SELECT a FROM u ORDER BY a",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if so.RightParenthesized {
				t.Errorf("RightParenthesized should be cleared after merging the ORDER BY")
			}
			if sel := parenSelect(t, so.Right); len(sel.OrderBy) != 1 {
				t.Errorf("want ORDER BY on the right operand, got %d items", len(sel.OrderBy))
			}
		},
	},
	{
		name: "right operand is a set operation",
		sql:  "SELECT a FROM t EXCEPT (SELECT a FROM u UNION SELECT a FROM v)",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if so.Operator != "EXCEPT" || !so.RightParenthesized {
				t.Fatalf("got %+v", so)
			}
			if inner := parenSetOp(t, so.Right); inner.Operator != "UNION" {
				t.Errorf("inner operator %q, want UNION", inner.Operator)
			}
		},
	},
	{
		name: "parenthesized left set operation",
		sql:  "((SELECT 1) UNION (SELECT 2)) UNION SELECT 3",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if !so.LeftParenthesized || so.RightParenthesized {
				t.Fatalf("got %+v", so)
			}
			parenSetOp(t, so.Left)
		},
	},
	{
		name: "parenthesized WITH operand",
		sql:  "(WITH c AS (SELECT 1 AS a) SELECT a FROM c) UNION SELECT 2",
		check: func(t *testing.T, s ast.Statement) {
			so := parenSetOp(t, s)
			if !so.LeftParenthesized || parenSelect(t, so.Left).With == nil {
				t.Fatalf("want parenthesized left operand with WITH, got %+v", so)
			}
		},
	},
	{
		name: "CTE body with parenthesized operands",
		sql:  "WITH c AS ((SELECT 1) UNION (SELECT 2)) SELECT * FROM c",
		check: func(t *testing.T, s ast.Statement) {
			sel := parenSelect(t, s)
			if sel.With == nil || len(sel.With.CTEs) != 1 {
				t.Fatalf("want one CTE, got %+v", sel.With)
			}
			so := parenSetOp(t, sel.With.CTEs[0].Statement)
			if !so.LeftParenthesized || !so.RightParenthesized {
				t.Errorf("CTE body flags: %+v", so)
			}
		},
	},
	{
		name: "INSERT SELECT with parenthesized right operand",
		sql:  "INSERT INTO t SELECT 1 UNION (SELECT 2)",
	},
	{
		name:     "LATERAL set op derived table",
		sql:      "SELECT * FROM t, LATERAL (SELECT 1 UNION SELECT 2) s",
		dialects: []string{"postgresql"},
		check: func(t *testing.T, s ast.Statement) {
			sel := parenSelect(t, s)
			if len(sel.From) != 2 || !sel.From[1].Lateral || sel.From[1].SetSubquery == nil {
				t.Fatalf("want LATERAL SetSubquery as second FROM item, got %+v", sel.From)
			}
		},
	},
	{
		name:     "MINUS between parenthesized operands",
		sql:      "SELECT * FROM ((SELECT 1) MINUS (SELECT 2)) t",
		want:     "SELECT * FROM ((SELECT 1) MINUS (SELECT 2)) t",
		dialects: []string{"snowflake", "oracle"},
		check: func(t *testing.T, s ast.Statement) {
			so := parenSelect(t, s).From[0].SetSubquery
			if so == nil || so.Operator != "EXCEPT" || !so.Minus {
				t.Fatalf("want EXCEPT SetSubquery, got %+v", so)
			}
		},
	},
	{
		name:     "set op derived table with trailing ORDER BY and LIMIT",
		sql:      "SELECT * FROM (SELECT a FROM t UNION ALL SELECT a FROM u ORDER BY a LIMIT 5) x",
		dialects: parenLimitDialects,
	},
	{
		name: "FROM-less SELECT with ORDER BY",
		sql:  "SELECT 1 ORDER BY 1",
	},
	{
		name:     "FROM-less set operation with ORDER BY and LIMIT",
		sql:      "SELECT 1 UNION SELECT 2 ORDER BY 1 LIMIT 1",
		dialects: parenLimitDialects,
	},
	{
		name: "nested parenthesized derived table inside a join group",
		sql:  "SELECT * FROM (((SELECT 1)) t JOIN u ON t.a = u.a)",
		want: "SELECT * FROM (SELECT 1) t INNER JOIN u ON t.a = u.a",
	},
	{
		name: "doubly parenthesized derived table in a comma list",
		sql:  "SELECT * FROM a, ((SELECT 1) UNION (SELECT 2)) t",
	},
}

func runParenCases(t *testing.T, cases []parenCase) {
	for _, tc := range cases {
		for _, d := range tc.dialectList() {
			t.Run(tc.name+"/"+dialectName(d), func(t *testing.T) {
				tree, err := parenParse(t, d, tc.sql)
				if err != nil {
					t.Fatalf("%q: unexpected error: %v", tc.sql, err)
				}
				defer ast.ReleaseAST(tree)
				s := parenOnlyStmt(t, tree)
				if tc.check != nil {
					tc.check(t, s)
				}
				if got := tree.SQL(); got != tc.wantSQL() {
					t.Errorf("SQL() = %q, want %q", got, tc.wantSQL())
				}
			})
		}
	}
}

func TestParenQuery_IssueCases(t *testing.T) { runParenCases(t, parenIssueCases) }

func TestParenQuery_Extra(t *testing.T) { runParenCases(t, parenExtraCases) }

// TestParenQuery_RoundTrip checks parse -> SQL() -> parse: the second SQL()
// equals the first and the derived-table / flag shape is unchanged.
func TestParenQuery_RoundTrip(t *testing.T) {
	all := append(append([]parenCase{}, parenIssueCases...), parenExtraCases...)
	for _, tc := range all {
		for _, d := range tc.dialectList() {
			t.Run(tc.name+"/"+dialectName(d), func(t *testing.T) {
				tree, err := parenParse(t, d, tc.sql)
				if err != nil {
					t.Fatalf("first parse: %v", err)
				}
				sql1 := tree.SQL()
				shape1 := parenShape(parenOnlyStmt(t, tree))
				ast.ReleaseAST(tree)

				tree2, err := parenParse(t, d, sql1)
				if err != nil {
					t.Fatalf("re-parse of %q: %v", sql1, err)
				}
				defer ast.ReleaseAST(tree2)
				if sql2 := tree2.SQL(); sql2 != sql1 {
					t.Errorf("round trip changed SQL:\n first  %q\n second %q", sql1, sql2)
				}
				if shape2 := parenShape(parenOnlyStmt(t, tree2)); shape2 != shape1 {
					t.Errorf("round trip changed shape:\n first  %s\n second %s", shape1, shape2)
				}
			})
		}
	}
}

// TestParenQuery_Controls pins inputs whose result must not change.
func TestParenQuery_Controls(t *testing.T) {
	parses := []struct{ sql, want string }{
		{"SELECT * FROM (SELECT 1) t", "SELECT * FROM (SELECT 1) t"},
		{"SELECT * FROM ((SELECT 1) t)", "SELECT * FROM (SELECT 1) t"},
		{"SELECT * FROM t WHERE a IN (SELECT 1 UNION SELECT 2)", "SELECT * FROM t WHERE a IN (SELECT 1 UNION SELECT 2)"},
		{"SELECT (SELECT 1 UNION SELECT 2)", "SELECT (SELECT 1 UNION SELECT 2)"},
		{"WITH c AS (SELECT 1 UNION SELECT 2) SELECT * FROM c", "WITH c AS (SELECT 1 UNION SELECT 2) SELECT * FROM c"},
		{"SELECT * FROM ((SELECT a FROM x) t JOIN y ON t.a = y.a)", "SELECT * FROM (SELECT a FROM x) t INNER JOIN y ON t.a = y.a"},
		{"SELECT * FROM ((a JOIN b ON a.id = b.id))", "SELECT * FROM a INNER JOIN b ON a.id = b.id"},
		{"SELECT a FROM t ORDER BY a LIMIT 1 UNION SELECT b FROM u", "SELECT a FROM t ORDER BY a LIMIT 1 UNION SELECT b FROM u"},
		{"SELECT 1 UNION SELECT 2 UNION SELECT 3", "SELECT 1 UNION SELECT 2 UNION SELECT 3"},
	}
	for _, d := range []string{"", "postgresql", "mysql"} {
		for _, tc := range parses {
			tree, err := parenParse(t, d, tc.sql)
			if err != nil {
				t.Errorf("%s: %q: unexpected error: %v", dialectName(d), tc.sql, err)
				continue
			}
			if got := tree.SQL(); got != tc.want {
				t.Errorf("%s: %q: SQL() = %q, want %q", dialectName(d), tc.sql, got, tc.want)
			}
			if tc.sql == "SELECT * FROM (SELECT 1) t" {
				ref := parenSelect(t, parenOnlyStmt(t, tree)).From[0]
				if ref.Subquery == nil || ref.SetSubquery != nil {
					t.Errorf("%s: plain derived table must stay in Subquery, got %+v", dialectName(d), ref)
				}
			}
			if so, ok := parenOnlyStmt(t, tree).(*ast.SetOperation); ok && (so.LeftParenthesized || so.RightParenthesized) {
				t.Errorf("%s: %q: unexpected parenthesized flags %+v", dialectName(d), tc.sql, so)
			}
			ast.ReleaseAST(tree)
		}
	}

	errs := []struct {
		sql, code, msg string
		pos            string // "line:col" or ""
	}{
		{"SELECT * FROM (a) x", "E4001", "alias after a parenthesized join group", ""},
		{"SELECT * FROM (t JOIN u ON true) x", "E4001", "alias after a parenthesized join group", ""},
		{"SELECT * FROM ((SELECT a FROM x), y)", "E4001", "comma-separated table list inside a parenthesized join", ""},
		{"SELECT * FROM (1) t", "E2002", "expected SELECT in derived table, got NUMBER", "1:16"},
		{"(1)", "E2002", "expected statement, got LPAREN", "1:1"},
		{"SELECT 1 UNION 2", "E2002", "expected SELECT after set operation, got NUMBER", "1:16"},
	}
	for _, d := range []string{"", "postgresql", "mysql"} {
		for _, tc := range errs {
			_, err := parenParse(t, d, tc.sql)
			if err == nil {
				t.Errorf("%s: %q: expected an error", dialectName(d), tc.sql)
				continue
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.code) || !strings.Contains(msg, tc.msg) {
				t.Errorf("%s: %q: error %q, want %s %q", dialectName(d), tc.sql, msg, tc.code, tc.msg)
			}
			if tc.pos != "" {
				line, col, _ := strings.Cut(tc.pos, ":")
				if want := "line " + line + ", column " + col; !strings.Contains(msg, want) {
					t.Errorf("%s: %q: error %q, want position %s", dialectName(d), tc.sql, msg, want)
				}
			}
		}
	}
}

// TestParenQuery_UnsupportedTail checks that a tail clause that cannot be
// represented without changing meaning returns E4001, and that a derived
// table whose WITH body is not a query fails cleanly.
func TestParenQuery_UnsupportedTail(t *testing.T) {
	tests := []struct {
		sql      string
		dialects []string
		code     string
	}{
		{"(SELECT a FROM t ORDER BY a LIMIT 1) ORDER BY a", parenLimitDialects, string(goerrors.ErrCodeUnsupportedFeature)},
		{"SELECT 1 UNION (SELECT 2 UNION SELECT 3) ORDER BY 1", parenDialects, string(goerrors.ErrCodeUnsupportedFeature)},
		{"((SELECT 1) UNION (SELECT 2 ORDER BY 1)) ORDER BY 1", parenDialects, string(goerrors.ErrCodeUnsupportedFeature)},
		{"SELECT * FROM (WITH c AS (SELECT 1) INSERT INTO t VALUES (1)) x", parenDialects, ""},
	}
	for _, tc := range tests {
		for _, d := range tc.dialects {
			tree, err := parenParse(t, d, tc.sql)
			if err == nil {
				t.Errorf("%s: %q: expected an error, got SQL %q", dialectName(d), tc.sql, tree.SQL())
				continue
			}
			if tc.code != "" && !strings.Contains(err.Error(), tc.code) {
				t.Errorf("%s: %q: error %q does not carry %s", dialectName(d), tc.sql, err.Error(), tc.code)
			}
		}
	}
}

// TestParenQuery_DepthLimit checks that nested parentheses in FROM, at
// statement level and as right operands are bounded by MaxRecursionDepth and
// leave the depth counter at zero.
func TestParenQuery_DepthLimit(t *testing.T) {
	forms := []struct {
		name  string
		build func(n int) string
	}{
		{"from", func(n int) string {
			return "SELECT * FROM " + strings.Repeat("(", n) + "SELECT 1" + strings.Repeat(")", n) + " t"
		}},
		{"statement", func(n int) string {
			return strings.Repeat("(", n) + "SELECT 1" + strings.Repeat(")", n)
		}},
		{"right_operand", func(n int) string {
			return "SELECT 1" + strings.Repeat(" UNION (SELECT 1", n) + strings.Repeat(")", n)
		}},
	}
	deep := []int{500}
	if !testing.Short() {
		deep = append(deep, 50_000)
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			p := NewParser()
			defer p.Release()

			tree, err := parseWith(t, p, f.build(40))
			if err != nil {
				t.Fatalf("40 levels: unexpected error: %v", err)
			}
			ast.ReleaseAST(tree)
			if p.depth != 0 {
				t.Fatalf("depth = %d after a successful parse, want 0", p.depth)
			}

			for _, n := range deep {
				_, err := parseWith(t, p, f.build(n))
				if err == nil {
					t.Fatalf("%d levels: expected a recursion depth error", n)
				}
				if !strings.Contains(err.Error(), "E2007") {
					t.Fatalf("%d levels: expected E2007, got %v", n, err)
				}
				if p.depth != 0 {
					t.Fatalf("%d levels: depth = %d after error, want 0", n, p.depth)
				}
			}
		})
	}
}

// TestParenQuery_ClassifierNoAlloc checks that the FROM lookahead that tells a
// parenthesized query from a join group does not allocate.
func TestParenQuery_ClassifierNoAlloc(t *testing.T) {
	for _, sql := range []string{
		"((SELECT 1) UNION (SELECT 2)) t",
		"((SELECT a FROM x) t JOIN y ON t.a = y.a)",
	} {
		p := NewParser()
		tkz := tokenizer.GetTokenizer()
		raw, err := tkz.Tokenize([]byte(sql))
		tokenizer.PutTokenizer(tkz)
		if err != nil {
			t.Fatalf("tokenize: %v", err)
		}
		toks := p.preprocess(raw)
		p.tokens = toks
		p.currentPos = 0
		p.currentToken = toks[0]
		if allocs := testing.AllocsPerRun(10, func() { _ = p.parenOpensQueryExpression() }); allocs != 0 {
			t.Errorf("%q: parenOpensQueryExpression allocated %.0f times", sql, allocs)
		}
		p.tokens = nil
		p.Release()
	}
}
