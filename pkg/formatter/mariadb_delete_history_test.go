package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestMariaDBDeleteHistoryFormatterRoundTrip(t *testing.T) {
	for _, sql := range []string{
		`DELETE HISTORY FROM t PARTITION (p0, p1) BEFORE SYSTEM_TIME TRANSACTION 42`,
		`DELETE HISTORY FROM t PARTITION (p0) BEFORE SYSTEM_TIME TIMESTAMP NOW() - INTERVAL 1 DAY`,
		"DELETE HISTORY FROM t PARTITION (`select`) BEFORE SYSTEM_TIME '2020-01-01' + INTERVAL 1 DAY",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			lower := ast.CompactStyle()
			lower.KeywordCase = ast.KeywordLower
			formatted, err := gosqlx.FormatWithDialect(sql, gosqlx.DefaultFormatOptions(), keywords.DialectMariaDB)
			if err != nil {
				t.Fatal(err)
			}
			for _, output := range []string{formatted, formatter.FormatAST(tree, ast.CompactStyle()), formatter.FormatAST(tree, ast.ReadableStyle()), formatter.FormatAST(tree, lower)} {
				again, err := gosqlx.ParseWithDialect(output, keywords.DialectMariaDB)
				if err != nil {
					t.Fatalf("reparse %q: %v", output, err)
				}
				defer ast.ReleaseAST(again)
				if got := again.SQL(); got != sql {
					t.Fatalf("formatted %q reparsed to %q, want %q", output, got, sql)
				}
			}
		})
	}
}
