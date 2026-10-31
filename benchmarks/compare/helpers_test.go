package compare

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func parseTree(sql string) (*ast.AST, error) { return gosqlx.Parse(sql) }

func formatRow(r AcceptRow) string {
	return fmt.Sprintf("%-12s %-22s %5d/%-8d %5.1f%%\n", r.Dialect, r.Parser, r.Accepted, r.Total, r.Rate*100)
}
