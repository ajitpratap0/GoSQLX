package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestSplitDialectBoundaries(t *testing.T) {
	for _, dialect := range []string{"mysql", "mariadb", "clickhouse", "snowflake", "bigquery", "redshift"} {
		t.Run(dialect, func(t *testing.T) {
			sql := `SELECT 'a\';b' ; SELECT 3`
			if got := nonEmpty(SplitStatements(sql, dialect)); got != 2 {
				t.Fatalf("split count = %d", got)
			}
			tree, err := ParseWithDialect(sql, keywords.SQLDialect(dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 2 {
				t.Fatalf("parser count = %d", len(tree.Statements))
			}
		})
	}
	for _, dialect := range []string{"postgresql", "sqlite", "sqlserver", "oracle", "generic"} {
		t.Run(dialect, func(t *testing.T) {
			sql := `SELECT 'a\'; SELECT 3`
			if got := nonEmpty(SplitStatements(sql, dialect)); got != 2 {
				t.Fatalf("split count = %d", got)
			}
			tree, err := ParseWithDialect(sql, keywords.SQLDialect(dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 2 {
				t.Fatalf("parser count = %d", len(tree.Statements))
			}
		})
	}
}

func TestSplitParenthesisBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      int
	}{
		{"rule", `CREATE RULE r AS ON INSERT TO t DO ALSO (INSERT INTO u VALUES (1); INSERT INTO v VALUES (2)); SELECT 3`, 2},
		{"quoted", `SELECT '('; SELECT 3`, 2},
		{"comments", `SELECT 1 /* ( */; SELECT 3`, 2},
		{"unclosed", `SELECT (1; SELECT 2; SELECT 3`, 3},
		{"extra close", `SELECT )1; SELECT 2`, 2},
		{"nested", `SELECT ((1;2)); SELECT 3`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nonEmpty(SplitStatements(tc.sql, "postgresql")); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
			if tc.name == "rule" {
				tree, err := ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				if len(tree.Statements) != tc.want {
					t.Fatalf("parser count=%d", len(tree.Statements))
				}
			}
		})
	}
	// A malformed script gets one fallback pass, including many unmatched opens.
	for _, n := range []int{100, 400, 1600} {
		sql := strings.Repeat("SELECT (1;", n)
		if got := nonEmpty(SplitStatements(sql, "postgresql")); got != n {
			t.Fatalf("n=%d: got %d", n, got)
		}
	}
}

func TestOracleExecuteLine(t *testing.T) {
	for _, tc := range []struct {
		name, sql, dialect string
		want               int
	}{
		{"execute", "SELECT 4\n/\nSELECT (SELECT 1 FROM dual) FROM dual", "oracle", 2},
		{"crlf", "SELECT 4\r\n / \r\nSELECT 3 FROM dual", "oracle", 2},
		{"right operand", "SELECT 4\n/ 2 FROM dual", "oracle", 1},
		{"line comment", "SELECT 4\n/ -- comment\n2 FROM dual", "oracle", 1},
		{"block comment", "SELECT 4\n/ /* c */\n2 FROM dual", "oracle", 1},
		{"leading comment", "SELECT 4\n/* c */ /\n2 FROM dual", "oracle", 1},
		{"multiline comment", "SELECT 4\n/ /* c\nmore */\n2 FROM dual", "oracle", 1},
		{"comment before execute", "SELECT 4 /* c */\n/\nSELECT 2 FROM dual", "oracle", 2},
		{"quoted slash", "SELECT '/' FROM dual; SELECT 3 FROM dual", "oracle", 2},
		{"left operand", "SELECT 4 /\n2 FROM dual", "oracle", 1},
		{"other dialect", "SELECT 4\n/\n2", "postgresql", 1},
		{"trailing execute", "SELECT 4 FROM dual\n/", "oracle", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nonEmpty(SplitStatements(tc.sql, tc.dialect)); got != tc.want {
				t.Fatalf("split count=%d", got)
			}
			tree, err := ParseWithDialect(tc.sql, keywords.SQLDialect(tc.dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != tc.want {
				t.Fatalf("parser count=%d", len(tree.Statements))
			}
		})
	}
	// The second fragment in the reported example is not a complete query.
	// SQL*Plus ends SELECT 4 at '/', so reject that fragment instead of
	// silently reading the slash as division in a single valid expression.
	sql := "SELECT 4\n/\n(SELECT 1 FROM dual) FROM dual"
	if got := nonEmpty(SplitStatements(sql, "oracle")); got != 2 {
		t.Fatalf("split count=%d", got)
	}
	tree, err := ParseWithDialect(sql, keywords.DialectOracle)
	if tree != nil {
		defer ast.ReleaseAST(tree)
	}
	if err == nil {
		t.Fatal("expected invalid statement after SQL*Plus execute command")
	}
}

func TestOracleExecuteBlockFormatting(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		t.Run(ending, func(t *testing.T) {
			sql := strings.ReplaceAll("BEGIN NULL; END;\n/\nBEGIN NULL; END;\n/\nSELECT 3 FROM dual;", "\n", ending)
			original, err := ParseWithDialect(sql, keywords.DialectOracle)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(original)
			if len(original.Statements) != 3 {
				t.Fatalf("original count=%d", len(original.Statements))
			}
			formatted, err := FormatWithDialect(sql, DefaultFormatOptions(), keywords.DialectOracle)
			if err != nil {
				t.Fatal(err)
			}
			reparsed, err := ParseWithDialect(formatted, keywords.DialectOracle)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(reparsed)
			if len(reparsed.Statements) != 3 || original.SQL() != reparsed.SQL() {
				t.Fatalf("format changed statements:\n%s", formatted)
			}
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(keywords.DialectOracle)
			tokens, err := tkz.TokenizeString(sql)
			if err != nil {
				t.Fatal(err)
			}
			p := parser.NewParser(parser.WithDialect("oracle"), parser.WithStrictMode())
			tree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("strict block parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 3 {
				t.Fatalf("strict count=%d", len(tree.Statements))
			}
		})
	}
}

// TestOracleExecuteLineFormat checks that SQL*Plus '/' lines after PL/SQL
// blocks and queries neither fail formatting nor drop statements.
func TestOracleExecuteLineFormat(t *testing.T) {
	sql := "BEGIN\n  NULL;\nEND;\n/\nSELECT 1 FROM dual\n/\nCREATE OR REPLACE PROCEDURE p AS\nBEGIN\n  NULL;\nEND;\n/\n"
	out, err := FormatWithDialect(sql, DefaultFormatOptions(), keywords.DialectOracle)
	if err != nil {
		t.Fatalf("FormatWithDialect: %v", err)
	}
	for _, want := range []string{"BEGIN NULL; END", "SELECT 1", "CREATE OR REPLACE PROCEDURE p"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lost %q:\n%s", want, out)
		}
	}
	tree, err := ParseWithDialect(sql, keywords.DialectOracle)
	if err != nil {
		t.Fatalf("ParseWithDialect: %v", err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 3 {
		t.Errorf("statements = %d, want 3", len(tree.Statements))
	}
}
