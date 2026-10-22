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

// Package parser - operators_c1_test.go
// Tests for operators and predicates: IS forms, ANY/ALL/SOME over arrays,
// AT TIME ZONE, COLLATE, bitwise and other binary operators, word operators,
// LIKE ... ESCAPE, predicate chaining, IN variants, the ClickHouse ternary
// operator and multi-word / array CAST types.

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// c1Parse tokenizes and parses sql in dialect d, returning the tree.
func c1Parse(sql string, d keywords.SQLDialect) (*ast.AST, error) {
	tkz, err := tokenizer.NewWithDialect(d)
	if err != nil {
		return nil, err
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, err
	}
	p := NewParser(WithDialect(string(d)))
	defer p.Release()
	return p.ParseFromModelTokens(tokens)
}

// c1Select parses sql as one SELECT and fails the test otherwise.
func c1Select(t *testing.T, sql string, d keywords.SQLDialect) (*ast.SelectStatement, *ast.AST) {
	t.Helper()
	tree, err := c1Parse(sql, d)
	if err != nil {
		t.Fatalf("[%s] parse %q: %v", d, sql, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("[%s] %q: got %d statements, want 1", d, sql, len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("[%s] %q: got %T, want *ast.SelectStatement", d, sql, tree.Statements[0])
	}
	return stmt, tree
}

// c1Shape renders an expression as a fully parenthesized s-expression so a
// test can assert how operators bind: a | b & c is (| a (& b c)).
func c1Shape(e ast.Expression) string {
	switch n := e.(type) {
	case *ast.BinaryExpression:
		op := n.Operator
		if n.Not {
			op = "NOT " + op
		}
		if n.Right == nil {
			return "(" + op + " " + c1Shape(n.Left) + ")"
		}
		s := "(" + op + " " + c1Shape(n.Left) + " " + c1Shape(n.Right)
		if n.Escape != nil {
			s += " ESCAPE " + c1Shape(n.Escape)
		}
		return s + ")"
	case *ast.AssignmentExpression:
		return "(:= " + c1Shape(n.Target) + " " + c1Shape(n.Value) + ")"
	case *ast.UnaryExpression:
		return "(" + n.Operator.String() + " " + c1Shape(n.Expr) + ")"
	case *ast.BetweenExpression:
		return "(BETWEEN " + c1Shape(n.Expr) + " " + c1Shape(n.Lower) + " " + c1Shape(n.Upper) + ")"
	case *ast.InExpression:
		parts := make([]string, 0, len(n.List))
		for _, v := range n.List {
			parts = append(parts, c1Shape(v))
		}
		return "(IN " + c1Shape(n.Expr) + " [" + strings.Join(parts, " ") + "])"
	case *ast.AtTimeZoneExpression:
		return "(AT " + c1Shape(n.Expr) + " " + c1Shape(n.Zone) + ")"
	case *ast.CollateExpression:
		name := n.Collation
		if n.Schema != "" {
			name = n.Schema + "." + name
		}
		return "(COLLATE " + c1Shape(n.Expr) + " " + name + ")"
	case *ast.CastExpression:
		return "(CAST " + c1Shape(n.Expr) + " " + n.Type + ")"
	case *ast.TernaryExpression:
		return "(? " + c1Shape(n.Cond) + " " + c1Shape(n.Then) + " " + c1Shape(n.Else) + ")"
	}
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}

// TestOperatorsC1_Shapes pins how each new operator parses (operator text and
// binding) and that SQL() writes it back. wantShape describes the first
// select-list item, or the WHERE clause when where is set.
func TestOperatorsC1_Shapes(t *testing.T) {
	const (
		pg  = keywords.DialectPostgreSQL
		my  = keywords.DialectMySQL
		sl  = keywords.DialectSQLite
		ms  = keywords.DialectSQLServer
		ch  = keywords.DialectClickHouse
		sf  = keywords.DialectSnowflake
		ora = keywords.DialectOracle
	)
	tests := []struct {
		name      string
		d         keywords.SQLDialect
		sql       string
		where     bool
		wantShape string
		wantSQL   string // expression SQL(); empty skips the SQL and shape checks
	}{
		// IS forms
		{"is true", pg, "SELECT x IS TRUE FROM t", false, "(IS x TRUE)", "x IS TRUE"},
		{"is not false", pg, "SELECT x IS NOT FALSE FROM t", false, "(IS NOT x FALSE)", "x IS NOT FALSE"},
		{"is unknown", my, "SELECT x IS UNKNOWN FROM t", false, "(IS x UNKNOWN)", "x IS UNKNOWN"},
		{"is not unknown", pg, "SELECT x IS NOT UNKNOWN FROM t", false, "(IS NOT x UNKNOWN)", "x IS NOT UNKNOWN"},
		{"is distinct from", pg, "SELECT u.id FROM u WHERE u.id IS DISTINCT FROM 5", true, "(IS DISTINCT FROM u.id 5)", "u.id IS DISTINCT FROM 5"},
		{"is not distinct from", sf, "SELECT u.id FROM u WHERE u.id IS NOT DISTINCT FROM 5", true, "(IS NOT DISTINCT FROM u.id 5)", "u.id IS NOT DISTINCT FROM 5"},
		{"is not null stays", pg, "SELECT 1 FROM t WHERE a IS NOT NULL", true, "(NOT IS NULL a NULL)", "a IS NOT NULL"},
		{"sqlite is expr", sl, "SELECT * FROM t WHERE a IS b", true, "(IS a b)", "a IS b"},
		{"sqlite is not expr", sl, "SELECT * FROM t WHERE a IS NOT b", true, "(IS NOT a b)", "a IS NOT b"},
		{"isnull", pg, "SELECT 1 FROM t WHERE a ISNULL", true, "(IS NULL a NULL)", "a IS NULL"},
		{"notnull sqlite", sl, "SELECT 1 FROM t WHERE a NOTNULL", true, "(NOT IS NULL a NULL)", "a IS NOT NULL"},

		// ANY / ALL / SOME over arrays
		{"any placeholder", pg, "SELECT 1 FROM t WHERE id = ANY($1)", true, "id = ANY ($1)", "id = ANY ($1)"},
		{"any array constructor", pg, "SELECT 1 FROM t WHERE id = ANY(ARRAY[1, 2])", true, "id = ANY (ARRAY[1, 2])", "id = ANY (ARRAY[1, 2])"},
		{"any column", pg, "SELECT 1 FROM t WHERE 'x' = ANY(tags)", true, "'x' = ANY (tags)", "'x' = ANY (tags)"},
		{"all column", pg, "SELECT 1 FROM t WHERE id <> ALL(tags)", true, "id <> ALL (tags)", "id <> ALL (tags)"},
		{"some column keeps spelling", pg, "SELECT 1 FROM t WHERE id = SOME(tags)", true, "id = SOME (tags)", "id = SOME (tags)"},
		{"some subquery", pg, "SELECT 1 FROM t WHERE id = SOME(SELECT id FROM u)", true, "id = SOME (SELECT id FROM u)", "id = SOME (SELECT id FROM u)"},
		{"any subquery unchanged", pg, "SELECT 1 FROM t WHERE id = ANY(SELECT id FROM u)", true, "id = ANY (SELECT id FROM u)", "id = ANY (SELECT id FROM u)"},

		// AT TIME ZONE and COLLATE
		{"at time zone", pg, "SELECT created_at AT TIME ZONE 'UTC' FROM t", false, "(AT created_at 'UTC')", "created_at AT TIME ZONE 'UTC'"},
		{"at time zone chained", pg, "SELECT c AT TIME ZONE 'UTC' AT TIME ZONE 'PST' FROM t", false, "(AT (AT c 'UTC') 'PST')", "c AT TIME ZONE 'UTC' AT TIME ZONE 'PST'"},
		{"at time zone binds tighter than +", pg, "SELECT a + b AT TIME ZONE 'UTC' FROM t", false, "(+ a (AT b 'UTC'))", "a + b AT TIME ZONE 'UTC'"},
		{"at time zone cast zone", pg, "SELECT c AT TIME ZONE 'UTC'::text FROM t", false, "(AT c (CAST 'UTC' text))", "c AT TIME ZONE CAST('UTC' AS text)"},
		{"collate quoted keeps quotes", pg, `SELECT col COLLATE "C" FROM t`, false, "(COLLATE col C)", `col COLLATE "C"`},
		{"collate bare mysql", my, "SELECT x FROM t WHERE x COLLATE utf8mb4_bin = 'a'", true, "(= (COLLATE x utf8mb4_bin) 'a')", "x COLLATE utf8mb4_bin = 'a'"},
		{"collate qualified", pg, `SELECT a COLLATE pg_catalog."default" FROM t`, false, "(COLLATE a pg_catalog.default)", `a COLLATE pg_catalog."default"`},
		{"collate quoted name with a dot", pg, `SELECT a COLLATE "en_US.utf8" FROM t`, false, "(COLLATE a en_US.utf8)", `a COLLATE "en_US.utf8"`},
		{"collate qualified quoted name with a dot", pg, `SELECT a COLLATE pg_catalog."en_US.UTF-8" FROM t`, false, "(COLLATE a pg_catalog.en_US.UTF-8)", `a COLLATE pg_catalog."en_US.UTF-8"`},
		{"collate string literal clickhouse", ch, "SELECT x FROM t ORDER BY y COLLATE 'en'", false, "(COLLATE y en)", "y COLLATE 'en'"},

		// Bitwise and other binary operators
		{"tsvector match", pg, "SELECT x FROM t WHERE tsv @@ to_tsquery('a')", true, "(@@ tsv to_tsquery('a'))", "tsv @@ to_tsquery('a')"},
		{"array overlap", pg, "SELECT a && b FROM t", false, "(&& a b)", "a && b"},
		{"mysql && is AND", my, "SELECT 1 FROM t WHERE a && b", true, "(AND a b)", "a AND b"},
		{"bitwise and sqlserver", ms, "SELECT a & b FROM t", false, "(& a b)", "a & b"},
		{"bitwise or sqlserver binds like plus", ms, "SELECT a | b + 1 FROM t", false, "(+ (| a b) 1)", "a | b + 1"},
		{"pg xor operator", pg, "SELECT a # b FROM t", false, "(# a b)", "a # b"},
		{"bitwise precedence mysql", my, "SELECT a | b & c FROM t", false, "(| a (& b c))", "a | b & c"},
		{"shift binds tighter than &", my, "SELECT a & b << 1 FROM t", false, "(& a (<< b 1))", "a & b << 1"},
		{"plus binds tighter than shift", my, "SELECT 1 << 2 + 3 FROM t", false, "(<< 1 (+ 2 3))", "1 << 2 + 3"},
		{"comparison looser than bitwise", my, "SELECT 1 FROM t WHERE a & 1 = 1", true, "(= (& a 1) 1)", "a & 1 = 1"},
		{"right shift", sl, "SELECT a >> 2 FROM t", false, "(>> a 2)", "a >> 2"},
		{"bitwise not", my, "SELECT ~a FROM t", false, "(~ a)", "~a"},
		{"bang not mysql", my, "SELECT !0", false, "(! 0)", "!0"},
		{"null safe equals mysql", my, "SELECT * FROM t WHERE a <=> NULL", true, "(<=> a NULL)", "a <=> NULL"},
		{"pg distance", pg, "SELECT a <-> b FROM t", false, "(<-> a b)", "a <-> b"},
		{"pgvector cosine distance", pg, "SELECT a <=> b FROM t", false, "(<=> a b)", "a <=> b"},
		{"double equals sqlite", sl, "SELECT * FROM t WHERE a == 1", true, "(== a 1)", "a == 1"},

		// Word operators
		{"div", my, "SELECT a DIV 3 FROM t", false, "(DIV a 3)", "a DIV 3"},
		{"mod word", my, "SELECT a mod 3 FROM t", false, "(MOD a 3)", "a MOD 3"},
		{"div binds like *", my, "SELECT 1 + a DIV 3 FROM t", false, "(+ 1 (DIV a 3))", "1 + a DIV 3"},
		{"xor between and/or", my, "SELECT 1 FROM t WHERE a OR b XOR c AND d", true, "(OR a (XOR b (AND c d)))", "a OR b XOR c AND d"},
		{"not regexp", my, "SELECT * FROM t WHERE x NOT REGEXP 'a'", true, "(NOT REGEXP x 'a')", "x NOT REGEXP 'a'"},
		{"not rlike", my, "SELECT * FROM t WHERE x NOT RLIKE 'a'", true, "(NOT RLIKE x 'a')", "x NOT RLIKE 'a'"},
		{"sounds like", my, "SELECT * FROM t WHERE a SOUNDS LIKE b", true, "(SOUNDS LIKE a b)", "a SOUNDS LIKE b"},
		{"glob", sl, "SELECT * FROM t WHERE p GLOB '*.txt'", true, "(GLOB p '*.txt')", "p GLOB '*.txt'"},
		{"not glob", sl, "SELECT * FROM t WHERE p NOT GLOB '*.txt'", true, "(NOT GLOB p '*.txt')", "p NOT GLOB '*.txt'"},
		{"match", sl, "SELECT * FROM t WHERE a MATCH 'foo'", true, "(MATCH a 'foo')", "a MATCH 'foo'"},
		{"similar to", pg, "SELECT a FROM t WHERE n SIMILAR TO 'x%'", true, "(SIMILAR TO n 'x%')", "n SIMILAR TO 'x%'"},
		{"not similar to", pg, "SELECT a FROM t WHERE n NOT SIMILAR TO 'x%'", true, "(NOT SIMILAR TO n 'x%')", "n NOT SIMILAR TO 'x%'"},

		// LIKE ... ESCAPE
		{"like escape", ora, "SELECT a FROM t WHERE a LIKE 'x' ESCAPE 'y'", true, "(LIKE a 'x' ESCAPE 'y')", "a LIKE 'x' ESCAPE 'y'"},
		{"not ilike escape", pg, "SELECT a FROM t WHERE a NOT ILIKE 'x' ESCAPE 'y'", true, "(NOT ILIKE a 'x' ESCAPE 'y')", "a NOT ILIKE 'x' ESCAPE 'y'"},
		{"similar escape", pg, "SELECT a FROM t WHERE a SIMILAR TO 'x' ESCAPE '#'", true, "(SIMILAR TO a 'x' ESCAPE '#')", "a SIMILAR TO 'x' ESCAPE '#'"},
		{"like concat then escape", pg, "SELECT a FROM t WHERE a LIKE b || '%' ESCAPE '!'", true, "(LIKE a (|| b '%') ESCAPE '!')", "a LIKE b || '%' ESCAPE '!'"},

		// Predicate chaining
		{"in then equals", sl, "SELECT a IN (1, 2) = 1 FROM t", false, "(= (IN a [1 2]) 1)", "a IN (1, 2) = 1"},
		{"between then equals", pg, "SELECT a BETWEEN 1 AND 2 = TRUE FROM t", false, "(= (BETWEEN a 1 2) TRUE)", "a BETWEEN 1 AND 2 = TRUE"},
		{"like then is", pg, "SELECT a LIKE 'x' IS TRUE FROM t", false, "(IS (LIKE a 'x') TRUE)", "a LIKE 'x' IS TRUE"},
		{"comparison then is null", pg, "SELECT 1 FROM t WHERE a = b IS NULL", true, "(IS NULL (= a b) NULL)", "a = b IS NULL"},

		// IN variants
		{"sqlite empty in", sl, "SELECT a FROM t WHERE a IN ()", true, "(IN a [])", "a IN ()"},
		{"sqlite not in empty", sl, "SELECT a FROM t WHERE a NOT IN ()", true, "(IN a [])", "a NOT IN ()"},
		{"sqlite in table", sl, "SELECT a FROM t WHERE a IN u", true, "(IN a [u])", "a IN u"},
		{"clickhouse global in", ch, "SELECT a FROM t WHERE a GLOBAL IN (SELECT 1)", true, "(IN a [])", "a GLOBAL IN (SELECT 1)"},
		{"clickhouse global not in", ch, "SELECT a FROM t WHERE a GLOBAL NOT IN (1, 2)", true, "(IN a [1 2])", "a GLOBAL NOT IN (1, 2)"},

		// ClickHouse ternary
		{"ternary", ch, "SELECT a ? 1 : 2", false, "(? a 1 2)", "a ? 1 : 2"},
		{"ternary right associative", ch, "SELECT a ? 1 : b ? 2 : 3", false, "(? a 1 (? b 2 3))", "a ? 1 : b ? 2 : 3"},
		{"ternary condition is a comparison", ch, "SELECT a > 1 ? 'x' : 'y'", false, "(? (> a 1) 'x' 'y')", "a > 1 ? 'x' : 'y'"},

		// MySQL user-variable assignment
		{"assignment", my, "SELECT @a := 1", false, "(:= @a 1)", "@a := 1"},
		{"assignment right associative", my, "SELECT @a := @b := 2", false, "(:= @a (:= @b 2))", "@a := @b := 2"},
		{"assignment value is a full expression", my, "SELECT @a := b + 1 AND c", false, "(:= @a (AND (+ b 1) c))", "@a := b + 1 AND c"},

		// Canonical AND / OR
		{"and or upper-cased", pg, "select a from t where a = 1 and b = 2 or c = 3", true, "(OR (AND (= a 1) (= b 2)) (= c 3))", "a = 1 AND b = 2 OR c = 3"},

		// Cast types
		{"cast array", pg, "SELECT x::int[] FROM t", false, "(CAST x int[])", "CAST(x AS int[])"},
		{"cast text array func", pg, "SELECT CAST(a AS text[]) FROM t", false, "(CAST a text[])", "CAST(a AS text[])"},
		{"cast sized array", pg, "SELECT x::int[3][4] FROM t", false, "(CAST x int[3][4])", "CAST(x AS int[3][4])"},
		{"cast double precision", pg, "SELECT x::double precision FROM t", false, "(CAST x double precision)", "CAST(x AS double precision)"},
		{"cast character varying", pg, "SELECT x::character varying(10) FROM t", false, "(CAST x character varying(10))", "CAST(x AS character varying(10))"},
		{"cast timestamp with time zone", pg, "SELECT x::timestamp with time zone FROM t", false, "(CAST x timestamp with time zone)", "CAST(x AS timestamp with time zone)"},
		{"cast timestamp precision without tz", pg, "SELECT CAST(x AS timestamp(3) without time zone) FROM t", false, "(CAST x timestamp(3) without time zone)", "CAST(x AS timestamp(3) without time zone)"},
		{"cast qualified type", pg, "SELECT x::public.mood FROM t", false, "(CAST x public.mood)", "CAST(x AS public.mood)"},
		{"cast signed integer", my, "SELECT CAST(x AS SIGNED INTEGER) FROM t", false, "(CAST x SIGNED INTEGER)", "CAST(x AS SIGNED INTEGER)"},
		{"cast unsigned", my, "SELECT CAST(x AS UNSIGNED) FROM t", false, "(CAST x UNSIGNED)", "CAST(x AS UNSIGNED)"},
		{"cast char character set", my, "SELECT CAST(x AS CHAR CHARACTER SET utf8mb4) FROM t", false, "(CAST x CHAR CHARACTER SET utf8mb4)", "CAST(x AS CHAR CHARACTER SET utf8mb4)"},
		{"cast char length character set", my, "SELECT CAST(x AS CHAR(10) CHARACTER SET utf8mb4) FROM t", false, "(CAST x CHAR(10) CHARACTER SET utf8mb4)", "CAST(x AS CHAR(10) CHARACTER SET utf8mb4)"},
		{"cast decimal unchanged", my, "SELECT CAST(x AS DECIMAL(10,2)) FROM t", false, "(CAST x DECIMAL(10,2))", "CAST(x AS DECIMAL(10,2))"},
	}

	for _, tc := range tests {
		t.Run(string(tc.d)+"/"+tc.name, func(t *testing.T) {
			stmt, tree := c1Select(t, tc.sql, tc.d)
			defer ast.ReleaseAST(tree)

			var expr ast.Expression
			switch {
			case tc.where:
				expr = stmt.Where
			case len(stmt.OrderBy) > 0:
				expr = stmt.OrderBy[0].Expression
			default:
				expr = stmt.Columns[0]
			}
			if expr == nil {
				t.Fatalf("no expression to inspect in %q", tc.sql)
			}
			if tc.wantSQL == "" {
				return
			}
			if got := exprSQLForC1(expr); got != tc.wantSQL {
				t.Errorf("SQL() = %q, want %q", got, tc.wantSQL)
			}
			// SQL() must re-parse in the same dialect to the same SQL().
			re, err := c1Parse("SELECT "+exprSQLForC1(expr)+" FROM t", tc.d)
			if err != nil {
				t.Fatalf("re-parse of %q: %v", exprSQLForC1(expr), err)
			}
			defer ast.ReleaseAST(re)
			rs, ok := re.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("re-parse produced %T", re.Statements[0])
			}
			if got := exprSQLForC1(rs.Columns[0]); got != tc.wantSQL {
				t.Errorf("re-parsed SQL() = %q, want %q", got, tc.wantSQL)
			}
			if tc.wantShape != "" {
				if shape := c1Shape(expr); shape != tc.wantShape {
					t.Errorf("shape = %s, want %s", shape, tc.wantShape)
				}
			}
		})
	}
}

// exprSQLForC1 returns the SQL() text of e.
func exprSQLForC1(e ast.Expression) string {
	if s, ok := e.(interface{ SQL() string }); ok {
		return s.SQL()
	}
	return e.TokenLiteral()
}
