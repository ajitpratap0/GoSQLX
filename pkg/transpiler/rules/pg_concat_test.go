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

package rules_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// TestPgConcat_ToMySQLConcat_Issue781 checks that PostgreSQL || becomes
// CONCAT() for MySQL, where || would otherwise mean logical OR.
func TestPgConcat_ToMySQLConcat_Issue781(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"select_list_chain", "SELECT fname || ' ' || lname FROM users",
			"SELECT CONCAT(fname, ' ', lname) FROM users"},
		{"where_rhs", "SELECT * FROM t WHERE code = 'a' || b",
			"SELECT * FROM t WHERE code = CONCAT('a', b)"},
		{"concat_with_or", "SELECT * FROM t WHERE a = b || c OR d = 1",
			"SELECT * FROM t WHERE a = CONCAT(b, c) OR d = 1"},
		{"nested_in_function", "SELECT UPPER(a || b) FROM t",
			"SELECT UPPER(CONCAT(a, b)) FROM t"},
		{"operand_contains_concat", "SELECT a || LOWER(b || c) FROM t",
			"SELECT CONCAT(a, LOWER(CONCAT(b, c))) FROM t"},
		{"join_condition", "SELECT * FROM t JOIN u ON t.k = u.a || u.b",
			"SELECT * FROM t INNER JOIN u ON t.k = CONCAT(u.a, u.b)"},
		{"subquery", "SELECT * FROM t WHERE x IN (SELECT a || b FROM u)",
			"SELECT * FROM t WHERE x IN (SELECT CONCAT(a, b) FROM u)"},
		{"update_set", "UPDATE t SET name = fname || lname WHERE id = 1",
			"UPDATE t SET name = CONCAT(fname, lname) WHERE id = 1"},
		{"no_concat_unchanged", "SELECT a + b FROM t WHERE a = 1 OR b = 2",
			"SELECT a + b FROM t WHERE a = 1 OR b = 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := transpiler.Transpile(tc.in, keywords.DialectPostgreSQL, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if out != tc.want {
				t.Fatalf("Transpile(%q) = %q, want %q", tc.in, out, tc.want)
			}
			// The MySQL output must not contain a || that MySQL reads as OR.
			if strings.Contains(out, "||") {
				t.Fatalf("output still contains ||: %q", out)
			}
			assertMySQLReparse(t, tc.in, out)
		})
	}
}

// countOr counts OR binary expressions and CONCAT calls in tree.
func countOr(tree *ast.AST) (ors, concats int) {
	for _, stmt := range tree.Statements {
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BinaryExpression:
				if strings.EqualFold(e.Operator, "OR") {
					ors++
				}
			case *ast.FunctionCall:
				if strings.EqualFold(e.Name, "CONCAT") {
					concats++
				}
			}
			return true
		})
	}
	return ors, concats
}

// assertMySQLReparse checks the AST shape of out re-parsed as MySQL: it has
// exactly as many ORs as the input has OR keywords (no || turned into an OR),
// and at least one CONCAT call when the input had a ||.
func assertMySQLReparse(t *testing.T, in, out string) {
	t.Helper()
	inTree, err := parser.ParseWithDialect(in, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("PostgreSQL parse of %q: %v", in, err)
	}
	wantOrs, _ := countOr(inTree)
	ast.ReleaseAST(inTree)

	tree, err := parser.ParseWithDialect(out, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("MySQL re-parse of %q: %v", out, err)
	}
	defer ast.ReleaseAST(tree)
	ors, concats := countOr(tree)
	if ors != wantOrs {
		t.Fatalf("MySQL re-parse of %q has %d ORs, want %d", out, ors, wantOrs)
	}
	if strings.Contains(in, "||") && concats == 0 {
		t.Fatalf("MySQL re-parse of %q has no CONCAT call", out)
	}
}

// TestConcat_ToMySQLFamily_AllSources_Issue781 checks that || becomes CONCAT()
// for every source dialect that reads || as concatenation, going to either
// MySQL or MariaDB, where || would otherwise mean logical OR.
func TestConcat_ToMySQLFamily_AllSources_Issue781(t *testing.T) {
	const in = "SELECT a || b FROM t"
	const want = "SELECT CONCAT(a, b) FROM t"
	sources := []keywords.SQLDialect{
		keywords.DialectPostgreSQL, keywords.DialectSQLite, keywords.DialectOracle,
		keywords.DialectSnowflake, keywords.DialectSQLServer, keywords.DialectClickHouse,
		keywords.DialectGeneric,
	}
	for _, from := range sources {
		for _, to := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
			t.Run(string(from)+"_to_"+string(to), func(t *testing.T) {
				out, err := transpiler.Transpile(in, from, to)
				if err != nil {
					t.Fatalf("Transpile: %v", err)
				}
				if out != want {
					t.Fatalf("Transpile(%q, %s, %s) = %q, want %q", in, from, to, out, want)
				}
			})
		}
	}
}

// TestConcat_ParenthesisedChainFlattened_Issue781 checks that parenthesised
// || operands are flattened into a single CONCAT call.
func TestConcat_ParenthesisedChainFlattened_Issue781(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT (a || b) || c FROM t", "SELECT CONCAT(a, b, c) FROM t"},
		{"SELECT a || (b || c) FROM t", "SELECT CONCAT(a, b, c) FROM t"},
		{"SELECT (a || b) FROM t", "SELECT (CONCAT(a, b)) FROM t"},
		{"SELECT (a + 1) || b FROM t", "SELECT CONCAT((a + 1), b) FROM t"},
	}
	for _, tc := range cases {
		out, err := transpiler.Transpile(tc.in, keywords.DialectPostgreSQL, keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("Transpile(%q): %v", tc.in, err)
		}
		if out != tc.want {
			t.Errorf("Transpile(%q) = %q, want %q", tc.in, out, tc.want)
		}
	}
}

// TestPipesOr_BetweenMySQLFamily_Issue781 checks that a || OR keeps its
// spelling between MySQL and MariaDB (both read it the same way, and
// PIPES_AS_CONCAT users keep their meaning), and is written as OR for any
// target that reads || as concatenation.
func TestPipesOr_BetweenMySQLFamily_Issue781(t *testing.T) {
	const in = "SELECT * FROM t WHERE a = 1 || b = 2"
	cases := []struct {
		from, to keywords.SQLDialect
		want     string
	}{
		{keywords.DialectMySQL, keywords.DialectMariaDB, in},
		{keywords.DialectMariaDB, keywords.DialectMySQL, in},
		{keywords.DialectMySQL, keywords.DialectMySQL, in},
		{keywords.DialectMySQL, keywords.DialectSQLite, "SELECT * FROM t WHERE a = 1 OR b = 2"},
		{keywords.DialectMariaDB, keywords.DialectPostgreSQL, "SELECT * FROM t WHERE a = 1 OR b = 2"},
		{keywords.DialectMySQL, keywords.DialectOracle, "SELECT * FROM t WHERE a = 1 OR b = 2"},
	}
	for _, tc := range cases {
		out, err := transpiler.Transpile(in, tc.from, tc.to)
		if err != nil {
			t.Fatalf("Transpile(%s -> %s): %v", tc.from, tc.to, err)
		}
		if out != tc.want {
			t.Errorf("Transpile(%s -> %s) = %q, want %q", tc.from, tc.to, out, tc.want)
		}
	}
}

// TestMySQLPipesOr_ToPostgres_Issue781 checks that a MySQL || (logical OR) is
// emitted as OR for PostgreSQL, never as concatenation.
func TestMySQLPipesOr_ToPostgres_Issue781(t *testing.T) {
	cases := []struct {
		from     keywords.SQLDialect
		in, want string
	}{
		{keywords.DialectMySQL, "SELECT * FROM t WHERE a = 1 || b = 2",
			"SELECT * FROM t WHERE a = 1 OR b = 2"},
		{keywords.DialectMySQL, "SELECT * FROM t WHERE a = 1 AND b = 2 || c = 3",
			"SELECT * FROM t WHERE a = 1 AND b = 2 OR c = 3"},
		{keywords.DialectMySQL, "SELECT CONCAT(a, b) FROM t WHERE x || y",
			"SELECT CONCAT(a, b) FROM t WHERE x OR y"},
		{keywords.DialectMySQL, "SELECT * FROM t JOIN u ON t.a = u.a || t.b = u.b",
			"SELECT * FROM t INNER JOIN u ON t.a = u.a OR t.b = u.b"},
		{keywords.DialectMySQL, "SELECT * FROM t WHERE x IN (SELECT a FROM u WHERE p || q)",
			"SELECT * FROM t WHERE x IN (SELECT a FROM u WHERE p OR q)"},
	}
	for _, tc := range cases {
		out, err := transpiler.Transpile(tc.in, tc.from, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("Transpile(%q): %v", tc.in, err)
		}
		if out != tc.want {
			t.Errorf("Transpile(%q) = %q, want %q", tc.in, out, tc.want)
		}
	}
}
