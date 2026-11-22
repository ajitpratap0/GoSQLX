package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestSQLServerTopReserved(t *testing.T) {
	for _, sql := range []string{
		"INSERT INTO top (a) VALUES (1)", "INSERT INTO TOP (a) VALUES (1)", "INSERT INTO Top (a) VALUES (1)",
		"SELECT * FROM top", "SELECT * FROM TOP", "DELETE FROM top", "UPDATE top SET a = 1",
		"SELECT * FROM t AS top", "SELECT * FROM t top", "SELECT a AS top FROM t", "SELECT 1 top FROM t", "SELECT a top FROM t",
		"CREATE TABLE top (a INT)", "SELECT * FROM dbo.top", "MERGE INTO top USING s ON s.a = top.a WHEN MATCHED THEN DELETE",
		"SELECT * FROM t PIVOT (SUM(a) FOR q IN ([Q1])) AS top",
		"SELECT * FROM t PIVOT (SUM(a) FOR q IN ([Q1])) top",
		"SELECT * FROM t JOIN s AS top ON t.a = s.a", "SELECT * FROM t JOIN s top ON t.a = s.a",
		"UPDATE t AS top SET a = 1", "DELETE FROM t AS top",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectSQLServer)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Fatal("expected syntax error")
			}
		})
	}
}

func TestSQLServerTopQuotedRoundTrip(t *testing.T) {
	for _, tc := range []struct{ sql, want string }{
		{"SELECT * FROM [top]", "SELECT * FROM [top]"}, {`SELECT * FROM "top"`, `SELECT * FROM "top"`},
		{"SELECT [top] FROM t", "SELECT [top] FROM t"}, {`SELECT "top" FROM t`, `SELECT "top" FROM t`},
		{"SELECT a AS [top] FROM t", "SELECT a AS [top] FROM t"}, {"SELECT * FROM t AS [top]", "SELECT * FROM t [top]"},
		{"INSERT INTO [top] (a) VALUES (1)", "INSERT INTO [top] (a) VALUES (1)"}, {"UPDATE [top] SET a = 1", "UPDATE [top] SET a = 1"},
		{"SELECT top 5 * FROM t", "SELECT TOP 5 * FROM t"}, {"INSERT top (5) INTO t SELECT * FROM s", "INSERT TOP (5) INTO t SELECT * FROM s"},
		{"INSERT Top (5) t (a) VALUES (1)", "INSERT TOP (5) INTO t (a) VALUES (1)"}, {"UPDATE top (5) t SET a = 1", "UPDATE TOP (5) t SET a = 1"},
		{"DELETE top (5) FROM t", "DELETE TOP (5) FROM t"}, {"SELECT t.top FROM t", "SELECT t.top FROM t"}, {"SELECT * FROM [select]", "SELECT * FROM [select]"},
		{"CREATE TABLE t (top INT)", "CREATE TABLE t (top INT)"},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			again, err := gosqlx.ParseWithDialect(got, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(again)
			if again.SQL() != got {
				t.Fatal("unstable SQL")
			}
			formatted, err := gosqlx.FormatWithDialect(tc.sql, gosqlx.DefaultFormatOptions(), keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tc.sql, "[top]") && !strings.Contains(formatted, "[top]") {
				t.Fatalf("lost brackets: %s", formatted)
			}
			ft, err := gosqlx.ParseWithDialect(formatted, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(ft)
			if ft.SQL() != got {
				t.Fatalf("formatter changed SQL: %s", ft.SQL())
			}
		})
	}
}

func TestTopNamesOtherDialects(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectOracle, keywords.DialectClickHouse, keywords.DialectGeneric, keywords.DialectSnowflake} {
		for _, sql := range []string{"INSERT INTO top (a) VALUES (1)", "SELECT * FROM top"} {
			t.Run(string(dialect)+sql, func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(sql, dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				if tree.SQL() != sql {
					t.Fatalf("SQL() = %q, want %q", tree.SQL(), sql)
				}
				again, err := gosqlx.ParseWithDialect(tree.SQL(), dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(again)
				if tree.SQL() != again.SQL() {
					t.Fatal("unstable SQL")
				}
				formatted, err := gosqlx.FormatWithDialect(sql, gosqlx.DefaultFormatOptions(), dialect)
				if err != nil {
					t.Fatal(err)
				}
				ft, err := gosqlx.ParseWithDialect(formatted, dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(ft)
				if ft.SQL() != sql {
					t.Fatalf("formatter changed SQL: %s", ft.SQL())
				}
			})
		}
	}
}

// Quoted TOP must be an expression even in dialects that reject the TOP clause.
func TestDelimitedTopIsNotClause(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectOracle, keywords.DialectClickHouse, keywords.DialectSnowflake} {
		for _, sql := range []string{`SELECT "top" FROM t`} {
			t.Run(string(dialect)+sql, func(t *testing.T) {
				tree, err := gosqlx.ParseWithDialect(sql, dialect)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
			})
		}
	}
}
