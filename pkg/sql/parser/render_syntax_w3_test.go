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

func TestParseJoinGroupOperand(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"group with join", keywords.DialectMySQL,
			"SELECT * FROM a LEFT JOIN (b JOIN c ON b.id = c.b_id) ON a.id = b.a_id",
			"SELECT * FROM a LEFT JOIN (b INNER JOIN c ON b.id = c.b_id) ON a.id = b.a_id"},
		{"comma list", keywords.DialectMySQL,
			"SELECT * FROM t1 LEFT JOIN (t2, t3) ON t1.id = t2.id AND t2.id = t3.id",
			"SELECT * FROM t1 LEFT JOIN (t2, t3) ON t1.id = t2.id AND t2.id = t3.id"},
		{"nested groups", keywords.DialectMySQL,
			"SELECT * FROM t1 JOIN (t2 LEFT JOIN (t3 JOIN t4 ON t3.a = t4.a) ON t2.b = t3.b) ON t1.c = t2.c",
			"SELECT * FROM t1 INNER JOIN (t2 LEFT JOIN (t3 INNER JOIN t4 ON t3.a = t4.a) ON t2.b = t3.b) ON t1.c = t2.c"},
		{"sqlite", keywords.DialectSQLite,
			"SELECT * FROM a LEFT JOIN (b JOIN c ON b.id = c.id) ON a.id = b.id",
			"SELECT * FROM a LEFT JOIN (b INNER JOIN c ON b.id = c.id) ON a.id = b.id"},
		{"derived table is not a group", keywords.DialectPostgreSQL,
			"SELECT * FROM a JOIN (SELECT 1 AS x) s ON a.x = s.x",
			"SELECT * FROM a INNER JOIN (SELECT 1 AS x) s ON a.x = s.x"},
	})

	tree, err := ParseWithDialect("SELECT * FROM a LEFT JOIN (b JOIN c ON b.id = c.b_id) ON a.id = b.a_id", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("statement is %T", tree.Statements[0])
	}
	if len(sel.From) != 1 || len(sel.Joins) != 1 {
		t.Fatalf("From = %d, Joins = %d; want 1 and 1", len(sel.From), len(sel.Joins))
	}
	g := ast.TableRefJoinGroup(&sel.Joins[0].Right)
	if g == nil {
		t.Fatal("the right side of the join is not a join group")
	}
	if len(g.Tables) != 1 || g.Tables[0].Name != "b" || len(g.Joins) != 1 || g.Joins[0].Right.Name != "c" {
		t.Errorf("group = %+v, want b JOIN c", g)
	}
	if sel.Joins[0].Condition == nil {
		t.Error("the ON condition after the group was lost")
	}
	// The walker reaches the tables inside the group.
	var names []string
	_ = ast.Walk(ast.Inspector(func(n ast.Node) bool {
		if r, ok := n.(*ast.TableReference); ok && r.Name != "" {
			names = append(names, r.Name)
		}
		return true
	}), sel)
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !found[want] {
			t.Errorf("Walk did not visit table %q (visited %v)", want, names)
		}
	}

	// An alias after the group is refused, not attached to the wrong table.
	if tree2, err := ParseWithDialect("SELECT * FROM a JOIN (b JOIN c ON b.id = c.id) g ON a.id = g.id", keywords.DialectMySQL); err == nil {
		ast.ReleaseAST(tree2)
		t.Error("an alias after a join group was accepted")
	}
}

func TestParseJSONTable(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"mysql", keywords.DialectMySQL,
			"SELECT jt.* FROM events, JSON_TABLE(payload, '$.items[*]' COLUMNS (id INT PATH '$.id', name VARCHAR(50) PATH '$.name')) AS jt",
			"SELECT jt.* FROM events, JSON_TABLE(payload, '$.items[*]' COLUMNS (id INT PATH '$.id', name VARCHAR(50) PATH '$.name')) jt"},
		{"mariadb ordinality and default", keywords.DialectMariaDB,
			"SELECT o.id FROM orders o, JSON_TABLE(o.items, '$[*]' COLUMNS (rn FOR ORDINALITY, qty INT PATH '$.qty' DEFAULT '1' ON EMPTY)) AS jt",
			"SELECT o.id FROM orders o, JSON_TABLE(o.items, '$[*]' COLUMNS (rn FOR ORDINALITY, qty INT PATH '$.qty' DEFAULT '1' ON EMPTY)) jt"},
		{"oracle", keywords.DialectOracle,
			"SELECT * FROM JSON_TABLE(:doc, '$.items[*]' COLUMNS (id NUMBER PATH '$.id')) jt",
			"SELECT * FROM JSON_TABLE(:doc, '$.items[*]' COLUMNS (id NUMBER PATH '$.id')) jt"},
	})
	tree, err := ParseWithDialect("SELECT * FROM JSON_TABLE(d, '$' COLUMNS (a INT PATH '$.a')) jt", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok || len(sel.From) != 1 || sel.From[0].TableFunc == nil {
		t.Fatalf("unexpected tree: %#v", tree.Statements[0])
	}
	args := sel.From[0].TableFunc.Arguments
	if len(args) != 2 {
		t.Fatalf("JSON_TABLE has %d arguments, want 2 (document, path with COLUMNS)", len(args))
	}
	cols, ok := args[1].(*ast.ClauseArgument)
	if !ok {
		t.Fatalf("second argument is %T, want *ast.ClauseArgument", args[1])
	}
	if cols.Clause != "COLUMNS (a INT PATH '$.a')" {
		t.Errorf("Clause = %q", cols.Clause)
	}
}

func TestParseMariaDBHistoryAndRowsExamined(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"delete history", keywords.DialectMariaDB,
			"DELETE HISTORY FROM accounts BEFORE SYSTEM_TIME '2024-01-01 00:00:00'",
			"DELETE HISTORY FROM accounts BEFORE SYSTEM_TIME '2024-01-01 00:00:00'"},
		{"delete history all", keywords.DialectMariaDB, "DELETE HISTORY FROM accounts", "DELETE HISTORY FROM accounts"},
		{"delete from a table named history", keywords.DialectMariaDB, "DELETE FROM history WHERE a = 1", "DELETE FROM history WHERE a = 1"},
		{"rows examined", keywords.DialectMariaDB,
			"SELECT * FROM orders ORDER BY id LIMIT 10 OFFSET 5 ROWS EXAMINED 1000",
			"SELECT * FROM orders ORDER BY id LIMIT 10 OFFSET 5 ROWS EXAMINED 1000"},
		{"rows examined without offset", keywords.DialectMariaDB,
			"SELECT * FROM orders LIMIT 10 ROWS EXAMINED 1000", "SELECT * FROM orders LIMIT 10 ROWS EXAMINED 1000"},
		{"offset rows still parses", keywords.DialectMariaDB,
			"SELECT * FROM orders OFFSET 5 ROWS FETCH NEXT 3 ROWS ONLY", "SELECT * FROM orders OFFSET 5 ROWS FETCH NEXT 3 ROWS ONLY"},
		{"system versioning column", keywords.DialectMariaDB,
			"ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash CHAR(32) WITHOUT SYSTEM VERSIONING",
			"ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash CHAR(32) WITHOUT SYSTEM VERSIONING"},
		{"system versioning in create", keywords.DialectMariaDB,
			"CREATE TABLE t (a INT WITH SYSTEM VERSIONING, b INT WITHOUT SYSTEM VERSIONING NOT NULL)",
			"CREATE TABLE t (a INT WITH SYSTEM VERSIONING, b INT WITHOUT SYSTEM VERSIONING NOT NULL)"},
	})
	tree, err := ParseWithDialect("DELETE HISTORY FROM accounts BEFORE SYSTEM_TIME '2024-01-01'", keywords.DialectMariaDB)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	del, ok := tree.Statements[0].(*ast.DeleteStatement)
	if !ok {
		t.Fatalf("statement is %T", tree.Statements[0])
	}
	if del.TableName != "accounts" || del.BeforeSystemTime == nil {
		t.Errorf("delete = %+v, want table accounts with a BEFORE SYSTEM_TIME point", del)
	}
}

func TestParseClickHouseColumnsApply(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"columns apply", keywords.DialectClickHouse, "SELECT COLUMNS('a|b') APPLY (sum) FROM t", "SELECT COLUMNS('a|b') APPLY (sum) FROM t"},
		{"star apply chain", keywords.DialectClickHouse,
			"SELECT * APPLY(sum) APPLY(x -> x + 1) FROM t", "SELECT * APPLY (sum) APPLY (x -> x + 1) FROM t"},
		{"columns except apply", keywords.DialectClickHouse,
			"SELECT COLUMNS('a') EXCEPT (b) APPLY(avg) FROM t", "SELECT COLUMNS('a') EXCEPT (b) APPLY (avg) FROM t"},
	})
}

func TestParseSnowflakeObjectLiteral(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"object and array", keywords.DialectSnowflake,
			"SELECT {'a': 1, 'b': 'two'} AS obj, [1, 2, 3] AS arr", "SELECT {'a': 1, 'b': 'two'} AS obj, [1, 2, 3] AS arr"},
		{"empty", keywords.DialectSnowflake, "SELECT {}", "SELECT {}"},
		{"nested with expressions", keywords.DialectSnowflake,
			"SELECT {'k': {'n': [1, 2]}, 'f': f(x) + 1} FROM t", "SELECT {'k': {'n': [1, 2]}, 'f': f(x) + 1} FROM t"},
	})
	tree, err := ParseWithDialect("SELECT {'a': 1, 'b': 2}", keywords.DialectSnowflake)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok || len(sel.Columns) != 1 {
		t.Fatalf("unexpected statement %T", tree.Statements[0])
	}
	obj, ok := sel.Columns[0].(*ast.ObjectLiteral)
	if !ok || len(obj.Entries) != 2 {
		t.Fatalf("column is %#v, want an object literal with 2 entries", sel.Columns[0])
	}
}

func TestParseSQLServerOpenrowsetAndMethodCall(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"openrowset bulk", keywords.DialectSQLServer,
			`SELECT * FROM OPENROWSET(BULK 'C:\data\file.csv', SINGLE_CLOB) AS x`,
			`SELECT * FROM OPENROWSET(BULK 'C:\data\file.csv', SINGLE_CLOB) x`},
		{"xml method on a subquery", keywords.DialectSQLServer,
			"SELECT STUFF((SELECT N',' + Name FROM dbo.Customers FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 1, N'')",
			"SELECT STUFF((SELECT N',' + Name FROM dbo.Customers FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 1, N'')"},
		{"chained methods", keywords.DialectSQLServer,
			"SELECT (SELECT 1 FOR XML PATH, TYPE).query('a').exist('b')",
			"SELECT (SELECT 1 FOR XML PATH, TYPE).query('a').exist('b')"},
		{"method without arguments", keywords.DialectSQLServer, "SELECT (x).f()", "SELECT (x).f()"},
	})
	tree, err := ParseWithDialect("SELECT (x).value('.', 'int')", keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok || len(sel.Columns) != 1 {
		t.Fatalf("unexpected statement %T", tree.Statements[0])
	}
	fa, ok := sel.Columns[0].(*ast.FieldAccessExpression)
	if !ok || !fa.IsCall || fa.Field != "value" || len(fa.Args) != 2 {
		t.Fatalf("column is %#v, want a method call value with 2 arguments", sel.Columns[0])
	}
	// Other dialects keep refusing a method call on a parenthesized value.
	if tree2, err := ParseWithDialect("SELECT (x).f(1)", keywords.DialectMySQL); err == nil {
		ast.ReleaseAST(tree2)
		t.Error("mysql: a method call on a parenthesized value was accepted")
	}
}

func TestParseOracleLogErrors(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"insert select", keywords.DialectOracle,
			"INSERT INTO dest SELECT * FROM src LOG ERRORS INTO err$_dest ('nightly load') REJECT LIMIT UNLIMITED",
			"INSERT INTO dest SELECT * FROM src LOG ERRORS INTO err$_dest ('nightly load') REJECT LIMIT UNLIMITED"},
		{"insert values with limit", keywords.DialectOracle,
			"INSERT INTO dest (a) VALUES (1) LOG ERRORS REJECT LIMIT 10",
			"INSERT INTO dest (a) VALUES (1) LOG ERRORS REJECT LIMIT 10"},
		{"after returning", keywords.DialectOracle,
			"INSERT INTO dest (a) VALUES (1) RETURNING a INTO :x LOG ERRORS INTO s.e",
			"INSERT INTO dest (a) VALUES (1) RETURNING a INTO :x LOG ERRORS INTO s.e"},
		{"log as a table alias", keywords.DialectOracle, "SELECT log FROM errors log", "SELECT log FROM errors log"},
	})
	tree, err := ParseWithDialect("INSERT INTO d SELECT * FROM s LOG ERRORS INTO e REJECT LIMIT 5", keywords.DialectOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok || ins.LogErrors == nil {
		t.Fatalf("statement = %#v, want an INSERT with LOG ERRORS", tree.Statements[0])
	}
	if ins.LogErrors.Into != "e" || ins.LogErrors.RejectLimit != "5" {
		t.Errorf("LogErrors = %+v", ins.LogErrors)
	}
}

func TestParseSetOperationQueryTail(t *testing.T) {
	const q = "SELECT a FROM t1 UNION ALL SELECT b FROM t2 UNION ALL (SELECT c FROM t3 ORDER BY c LIMIT 1) ORDER BY 1"
	for _, d := range []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		runSyntaxCases(t, []syntaxCase{
			{string(d) + " parenthesized last operand with its own clauses", d, q, q},
			{string(d) + " both operands parenthesized", d,
				"(SELECT a FROM t ORDER BY a LIMIT 5) UNION ALL (SELECT b FROM u LIMIT 5) ORDER BY 1 LIMIT 3 OFFSET 1",
				"(SELECT a FROM t ORDER BY a LIMIT 5) UNION ALL (SELECT b FROM u LIMIT 5) ORDER BY 1 LIMIT 3 OFFSET 1"},
			{string(d) + " last operand is a set operation", d,
				"SELECT 1 UNION (SELECT 2 UNION SELECT 3) ORDER BY 1", "SELECT 1 UNION (SELECT 2 UNION SELECT 3) ORDER BY 1"},
		})
	}

	tree, err := ParseWithDialect(q, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	op, ok := tree.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("statement is %T", tree.Statements[0])
	}
	if op.Tail == nil || len(op.Tail.OrderBy) != 1 {
		t.Fatalf("Tail = %+v, want one ORDER BY item", op.Tail)
	}
	last, ok := op.Right.(*ast.SelectStatement)
	if !ok || !op.RightParenthesized || len(last.OrderBy) != 1 || last.Limit == nil {
		t.Errorf("the parenthesized operand lost its own ORDER BY / LIMIT: %#v", op.Right)
	}

	// The merge into the last SELECT still happens when nothing conflicts.
	merged, err := ParseWithDialect("SELECT 1 UNION (SELECT 2) ORDER BY 1", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(merged)
	if mop, ok := merged.Statements[0].(*ast.SetOperation); !ok || mop.Tail != nil {
		t.Errorf("a clause without conflict was kept as a tail: %#v", merged.Statements[0])
	}

	// A LIMIT already applying to the whole operation cannot take a second one.
	for _, in := range []string{
		"(SELECT 1 UNION SELECT 2 LIMIT 5) ORDER BY 1",
		"(SELECT 1 ORDER BY 1 LIMIT 5) ORDER BY 1",
	} {
		if tree2, err := ParseWithDialect(in, keywords.DialectPostgreSQL); err == nil {
			ast.ReleaseAST(tree2)
			t.Errorf("parse %q: expected an error", in)
		}
	}
}

func TestParseOracleSyntaxW3(t *testing.T) {
	runSyntaxCases(t, []syntaxCase{
		{"select unique", keywords.DialectOracle, "SELECT UNIQUE job_id FROM employees", "SELECT DISTINCT job_id FROM employees"},
		{"cursor and multiset subqueries", keywords.DialectOracle,
			"SELECT CURSOR(SELECT 1 FROM dual), CAST(MULTISET(SELECT order_id FROM orders WHERE customer_id = c.customer_id) AS id_list_t) FROM customers c",
			"SELECT CURSOR(SELECT 1 FROM dual), CAST(MULTISET(SELECT order_id FROM orders WHERE customer_id = c.customer_id) AS id_list_t) FROM customers c"},
		{"json_object value form", keywords.DialectOracle,
			"SELECT JSON_OBJECT('id' VALUE employee_id, KEY 'name' VALUE last_name, 'x': 1, 'p', 2) FROM employees",
			"SELECT JSON_OBJECT('id' VALUE employee_id, KEY 'name' VALUE last_name, 'x': 1, 'p', 2) FROM employees"},
		{"xmlattributes with names", keywords.DialectOracle,
			`SELECT XMLELEMENT("emp", XMLATTRIBUTES(employee_id AS "id", x AS y), last_name), XMLFOREST(a AS b) FROM employees`,
			`SELECT XMLELEMENT("emp", XMLATTRIBUTES(employee_id AS "id", x AS y), last_name), XMLFOREST(a AS b) FROM employees`},
		{"xmltable", keywords.DialectOracle,
			"SELECT * FROM XMLTABLE('/rows/row' PASSING XMLTYPE(:x) COLUMNS id NUMBER PATH 'id', nm VARCHAR2(50) PATH 'name')",
			"SELECT * FROM XMLTABLE('/rows/row' PASSING XMLTYPE(:x) COLUMNS id NUMBER PATH 'id', nm VARCHAR2(50) PATH 'name')"},
		{"xmltable in postgresql", keywords.DialectPostgreSQL,
			"SELECT * FROM XMLTABLE('/rows/row' PASSING data COLUMNS id int PATH '@id') AS t",
			"SELECT * FROM XMLTABLE('/rows/row' PASSING data COLUMNS id int PATH '@id') t"},
		{"partition for", keywords.DialectOracle,
			"SELECT * FROM sales_hist PARTITION FOR (TO_DATE('2024-05-01', 'YYYY-MM-DD')) s",
			"SELECT * FROM sales_hist PARTITION FOR (TO_DATE('2024-05-01', 'YYYY-MM-DD')) s"},
		{"partition names still parse", keywords.DialectOracle,
			"SELECT * FROM sales PARTITION (p1) s", "SELECT * FROM sales PARTITION (p1) s"},
	})
	tree, err := ParseWithDialect("SELECT CURSOR(SELECT 1 FROM dual) FROM dual", keywords.DialectOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("statement is %T", tree.Statements[0])
	}
	fn, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok || len(fn.Arguments) != 1 {
		t.Fatalf("column is %#v, want CURSOR(...) with one argument", sel.Columns[0])
	}
	if sq, ok := fn.Arguments[0].(*ast.SubqueryExpression); !ok || !sq.Bare {
		t.Errorf("argument is %#v, want a bare subquery", fn.Arguments[0])
	}
	// CURSOR is only special in Oracle.
	if tree2, err := ParseWithDialect("SELECT CURSOR(SELECT 1)", keywords.DialectMySQL); err == nil {
		ast.ReleaseAST(tree2)
		t.Error("mysql: CURSOR(SELECT ...) was accepted")
	}
}
