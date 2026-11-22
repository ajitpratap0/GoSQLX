package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestMariaDBDeleteHistoryRoundTrip(t *testing.T) {
	cases := []string{
		`DELETE HISTORY FROM t`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2020-01-01 00:00:00'`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME TIMESTAMP '2020-01-01 00:00:00'`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME NOW() - INTERVAL 1 DAY`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME CURRENT_TIMESTAMP - INTERVAL 1 DAY`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2020-01-01' + INTERVAL 1 DAY`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME TIMESTAMP NOW() - INTERVAL 1 DAY`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME TIMESTAMP '2020-01-01' + INTERVAL 1 DAY`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME TRANSACTION 42`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME @ts`,
		`DELETE HISTORY FROM db.t BEFORE SYSTEM_TIME '2020-01-01'`,
		`DELETE HISTORY FROM t PARTITION (p0, p1)`,
		`DELETE HISTORY FROM t PARTITION (p0) BEFORE SYSTEM_TIME '2020-01-01'`,
		"DELETE HISTORY FROM t PARTITION (`select`)",
		`delete history from t before system_time transaction 7`,
		`DELETE FROM history WHERE a = 1`,
		`SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP '2020-01-01'`,
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) {
			want := sql
			if strings.HasPrefix(sql, "delete ") {
				want = `DELETE HISTORY FROM t BEFORE SYSTEM_TIME TRANSACTION 7`
			}
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if got := tree.SQL(); got != want {
				t.Fatalf("SQL() = %q, want %q", got, want)
			}
			formatted, err := gosqlx.FormatWithDialect(sql, gosqlx.DefaultFormatOptions(), keywords.DialectMariaDB)
			if err != nil {
				t.Fatal(err)
			}
			for _, output := range []string{tree.SQL(), formatted} {
				again, err := gosqlx.ParseWithDialect(output, keywords.DialectMariaDB)
				if err != nil {
					t.Fatalf("reparse %q: %v", output, err)
				}
				defer ast.ReleaseAST(again)
				if got := again.SQL(); got != want {
					t.Fatalf("round trip = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestMariaDBDeleteHistoryRejectsInvalid(t *testing.T) {
	for _, sql := range []string{
		`DELETE HISTORY FROM t WHERE a = 1`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2020-01-01' WHERE a = 1`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME '2020-01-01' LIMIT 5`,
		`DELETE HISTORY FROM t LIMIT 5`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME`,
		`DELETE HISTORY FROM t BEFORE '2020-01-01'`,
		`DELETE HISTORY FROM t PARTITION ()`,
		`DELETE HISTORY FROM t PARTITION (p0,)`,
		`DELETE HISTORY FROM t BEFORE SYSTEM_TIME TRANSACTION`,
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			if err == nil {
				t.Fatal("expected syntax error")
			}
		})
	}
}

func TestMySQLDeleteHistoryRemainsTarget(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(`DELETE HISTORY FROM t`, keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.DeleteStatement)
	if !ok {
		t.Fatalf("got %T", tree.Statements[0])
	}
	if !strings.EqualFold(stmt.TableName, "history") || len(stmt.From) != 1 {
		t.Fatalf("expected multi-table DELETE: %#v", stmt)
	}
}
