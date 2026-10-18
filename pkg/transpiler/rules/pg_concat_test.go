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
			tree, err := parser.ParseWithDialect(out, keywords.DialectMySQL)
			if err != nil {
				t.Fatalf("MySQL re-parse of %q: %v", out, err)
			}
			ast.ReleaseAST(tree)
		})
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
