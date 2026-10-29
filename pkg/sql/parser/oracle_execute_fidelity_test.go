package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestOracleExecuteSlashExcludesSQL(t *testing.T) {
	for _, input := range []string{
		"SELECT 10 /\n2 FROM dual",
		"SELECT 10\n/ -- comment\n2 FROM dual",
		"SELECT 10\n/* comment */ /\n2 FROM dual",
	} {
		tree, err := gosqlx.ParseWithDialect(input, keywords.DialectOracle)
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if len(tree.Statements) != 1 || tree.ExecuteSlash != nil {
			t.Errorf("%q: statements=%d execute=%v", input, len(tree.Statements), tree.ExecuteSlash)
		}
		ast.ReleaseAST(tree)
	}
}
