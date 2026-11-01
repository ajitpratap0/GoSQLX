package compare

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// formatCompact renders tree through the same formatter path as the
// gosqlx_compact Render cell.
func formatCompact(tree *ast.AST) (string, error) {
	return formatter.FormatASTChecked(tree, ast.CompactStyle())
}

func parseTree(sql string) (*ast.AST, error) { return gosqlx.Parse(sql) }

func formatRow(r AcceptRow) string {
	return fmt.Sprintf("%-12s %-22s %5d/%-8d %5.1f%%\n", r.Dialect, r.Parser, r.Accepted, r.Total, r.Rate*100)
}
