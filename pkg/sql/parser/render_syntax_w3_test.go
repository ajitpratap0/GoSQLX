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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// syntaxCase is one statement that parses under a dialect and renders (via
// SQL()) to want, which must itself parse to the same text.
type syntaxCase struct {
	name    string
	dialect keywords.SQLDialect
	sql     string
	want    string
}

func runSyntaxCases(t *testing.T, cases []syntaxCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Fatalf("SQL() of %q\n got: %s\nwant: %s", tc.sql, got, tc.want)
			}
			tree2, err := ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("rendered %q does not re-parse: %v", got, err)
			}
			defer ast.ReleaseAST(tree2)
			if again := tree2.SQL(); again != got {
				t.Fatalf("re-render differs\n first: %s\nsecond: %s", got, again)
			}
		})
	}
}

func TestParseStandaloneValues(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"postgresql", keywords.DialectPostgreSQL, "VALUES (1, 'a'), (2, 'b')", "VALUES (1, 'a'), (2, 'b')"},
		{"sqlite", keywords.DialectSQLite, "VALUES (1)", "VALUES (1)"},
		{"mariadb", keywords.DialectMariaDB, "VALUES (1, 'a'), (2, 'b')", "VALUES (1, 'a'), (2, 'b')"},
		{"mysql row constructor", keywords.DialectMySQL, "VALUES ROW(1, 2), ROW(3, 4)", "VALUES ROW(1, 2), ROW(3, 4)"},
		{"set operation", keywords.DialectPostgreSQL, "VALUES (1) UNION SELECT 2", "VALUES (1) UNION SELECT 2"},
	})
	tree, err := ParseWithDialect("VALUES (1), (2)", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(tree.Statements))
	}
	v, ok := tree.Statements[0].(*ast.Values)
	if !ok {
		t.Fatalf("statement is %T, want *ast.Values", tree.Statements[0])
	}
	if len(v.Rows) != 2 {
		t.Errorf("got %d rows, want 2", len(v.Rows))
	}
}

func TestParseCaretOperator(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"postgresql power", keywords.DialectPostgreSQL, "SELECT 2 ^ 10", "SELECT 2 ^ 10"},
		{"mysql xor", keywords.DialectMySQL, "SELECT a ^ b, 5 ^ 3", "SELECT a ^ b, 5 ^ 3"},
		{"mariadb xor", keywords.DialectMariaDB, "SELECT a ^ b", "SELECT a ^ b"},
		{"sqlserver xor", keywords.DialectSQLServer, "SELECT a ^ b FROM dbo.T", "SELECT a ^ b FROM dbo.T"},
	})

	// ^ binds tighter than * in PostgreSQL and MySQL: 2 * 3 ^ 2 is 2 * (3 ^ 2).
	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		tree, err := ParseWithDialect("SELECT 2 * 3 ^ 2", d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("%s: statement is %T", d, tree.Statements[0])
		}
		top, ok := sel.Columns[0].(*ast.BinaryExpression)
		if !ok || top.Operator != "*" {
			t.Fatalf("%s: top expression is %#v, want *", d, sel.Columns[0])
		}
		if r, ok := top.Right.(*ast.BinaryExpression); !ok || r.Operator != "^" {
			t.Errorf("%s: right operand of * is %#v, want ^", d, top.Right)
		}
		ast.ReleaseAST(tree)
	}

	// Oracle has no ^ operator.
	if tree, err := ParseWithDialect("SELECT 2 ^ 3 FROM dual", keywords.DialectOracle); err == nil {
		ast.ReleaseAST(tree)
		t.Error("oracle: ^ was accepted")
	}
}

func TestParsePostgresPrefixOperators(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"square root", keywords.DialectPostgreSQL, "SELECT |/ 25", "SELECT |/25"},
		{"cube root", keywords.DialectPostgreSQL, "SELECT ||/ 27", "SELECT ||/27"},
		{"abs", keywords.DialectPostgreSQL, "SELECT @ -5", "SELECT @ -5"},
		{"prefix factorial", keywords.DialectPostgreSQL, "SELECT !! 5", "SELECT !!5"},
		{"operand starting with an operator character", keywords.DialectPostgreSQL, "SELECT ~ -5, |/ -x FROM t", "SELECT ~ -5, |/ -x FROM t"},
		{"in an expression", keywords.DialectPostgreSQL, "SELECT |/ a + 1 FROM t", "SELECT |/a + 1 FROM t"},
	})
}

// TestParsePostgresPrefixOperatorPrecedence checks that |/ and friends take a
// whole additive expression as their operand, as "any other operator" does in
// PostgreSQL.
func TestParsePostgresPrefixOperatorPrecedence(t *testing.T) {
	tree, err := ParseWithDialect("SELECT |/ a + 1, (|/ a) + 1", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok || len(sel.Columns) != 2 {
		t.Fatalf("unexpected statement %T", tree.Statements[0])
	}
	u, ok := sel.Columns[0].(*ast.UnaryExpression)
	if !ok || u.Operator != ast.PGSquareRoot {
		t.Fatalf("first column is %#v, want a square-root unary expression", sel.Columns[0])
	}
	if b, ok := u.Expr.(*ast.BinaryExpression); !ok || b.Operator != "+" {
		t.Errorf("operand is %#v, want a + 1", u.Expr)
	}
	b, ok := sel.Columns[1].(*ast.BinaryExpression)
	if !ok || b.Operator != "+" {
		t.Fatalf("second column is %#v, want (|/ a) + 1", sel.Columns[1])
	}
}

func TestParseMySQLBinaryOperator(t *testing.T) {
	for _, d := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		runSyntaxCases(t, []syntaxCase{
			{string(d) + " column", d, "SELECT BINARY name FROM t", "SELECT BINARY name FROM t"},
			{string(d) + " literal", d, "SELECT 1 FROM t WHERE x = BINARY 'a@b.c'", "SELECT 1 FROM t WHERE x = BINARY 'a@b.c'"},
			{string(d) + " after REGEXP", d, "SELECT x FROM t WHERE x REGEXP BINARY 'A'", "SELECT x FROM t WHERE x REGEXP BINARY 'A'"},
			{string(d) + " function form", d, "SELECT BINARY(a) FROM t", "SELECT BINARY(a) FROM t"},
		})
	}
	tree, err := ParseWithDialect("SELECT BINARY name FROM t", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("statement is %T", tree.Statements[0])
	}
	u, ok := sel.Columns[0].(*ast.UnaryExpression)
	if !ok || u.Operator != ast.MySQLBinary {
		t.Fatalf("column is %#v, want a MySQLBinary unary expression", sel.Columns[0])
	}
}

func TestParseDistinctrow(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"mysql", keywords.DialectMySQL, "SELECT DISTINCTROW a FROM t1", "SELECT DISTINCT a FROM t1"},
		{"mariadb", keywords.DialectMariaDB, "SELECT DISTINCTROW a FROM t1", "SELECT DISTINCT a FROM t1"},
	})
}

func TestParseQualifiedReferences(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"table constraint", keywords.DialectSQLServer,
			"CREATE TABLE dbo.O (a INT, CONSTRAINT FK FOREIGN KEY (a) REFERENCES dbo.C (Id) ON DELETE CASCADE)",
			"CREATE TABLE dbo.O (a INT, CONSTRAINT FK FOREIGN KEY (a) REFERENCES dbo.C (Id) ON DELETE CASCADE)"},
		{"column constraint", keywords.DialectPostgreSQL,
			"CREATE TABLE o (a INT REFERENCES public.c (id))",
			"CREATE TABLE o (a INT REFERENCES public.c (id))"},
		{"quoted parts", keywords.DialectPostgreSQL,
			`CREATE TABLE o (a INT, FOREIGN KEY (a) REFERENCES "Sch"."Tbl" (id))`,
			`CREATE TABLE o (a INT, FOREIGN KEY (a) REFERENCES "Sch"."Tbl" (id))`},
		{"alter table", keywords.DialectSQLServer,
			"ALTER TABLE dbo.Orders WITH CHECK ADD CONSTRAINT FK FOREIGN KEY (CustomerId) REFERENCES dbo.Customers (Id)",
			"ALTER TABLE dbo.Orders WITH CHECK ADD CONSTRAINT FK FOREIGN KEY (CustomerId) REFERENCES dbo.Customers (Id)"},
	})
}

func TestParseOrderByAll(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"plain", keywords.DialectClickHouse, "SELECT a, b FROM t ORDER BY ALL", "SELECT a, b FROM t ORDER BY ALL"},
		{"with direction and limit", keywords.DialectClickHouse,
			"SELECT a, b FROM t ORDER BY ALL DESC NULLS LAST LIMIT 3",
			"SELECT a, b FROM t ORDER BY ALL DESC NULLS LAST LIMIT 3"},
	})
	if tree, err := ParseWithDialect("SELECT a FROM t ORDER BY ALL", keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("postgresql: ORDER BY ALL was accepted")
	}
}

func TestParseStringAlias(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"mysql with space", keywords.DialectMySQL, "SELECT a AS 'alias with space' FROM t", "SELECT a AS `alias with space` FROM t"},
		{"mysql plain", keywords.DialectMySQL, "SELECT a AS 'plain' FROM t", "SELECT a AS plain FROM t"},
		{"mariadb", keywords.DialectMariaDB, "SELECT a AS 'x y' FROM t", "SELECT a AS `x y` FROM t"},
		{"sqlite with space", keywords.DialectSQLite, "SELECT a AS 'alias with space' FROM t", `SELECT a AS "alias with space" FROM t`},
	})
	if tree, err := ParseWithDialect("SELECT a AS 'x' FROM t", keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("postgresql: a string alias was accepted")
	}
}

func TestParseOracleVersionsBetweenArithmetic(t *testing.T) {
	const q = "SELECT a FROM employees VERSIONS BETWEEN TIMESTAMP SYSTIMESTAMP - INTERVAL '1' DAY AND SYSTIMESTAMP WHERE employee_id = 100"
	runSyntaxCases(t, []syntaxCase{
		{"timestamp arithmetic", keywords.DialectOracle, q, q},
		{"scn bounds", keywords.DialectOracle, "SELECT a FROM e VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE", "SELECT a FROM e VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE"},
	})
}

func TestParseSQLServerUpdateStatisticsAndMoney(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"update statistics", keywords.DialectSQLServer, "UPDATE STATISTICS dbo.Orders", "UPDATE STATISTICS dbo.Orders"},
		{"update statistics with options", keywords.DialectSQLServer,
			"UPDATE STATISTICS dbo.Orders IX_a WITH FULLSCAN", "UPDATE STATISTICS dbo.Orders IX_a WITH FULLSCAN"},
		{"update is still DML", keywords.DialectSQLServer, "UPDATE t SET a = 1", "UPDATE t SET a = 1"},
		{"money literal", keywords.DialectSQLServer, "SELECT $5.00 AS Money, $7", "SELECT $5.00 AS Money, $7"},
	})
}
