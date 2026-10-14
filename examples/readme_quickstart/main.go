package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
	ctx := context.Background()

	// ParseTree is the recommended entry point. It returns an
	// opaque handle with built-in helpers.
	tree, err := gosqlx.ParseTree(ctx, "SELECT id, name FROM users WHERE active = true",
		gosqlx.WithDialect("postgresql"))
	if err != nil {
		// Sentinel errors work with errors.Is
		if errors.Is(err, gosqlx.ErrSyntax) {
			log.Fatalf("syntax error: %v", err)
		}
		log.Fatal(err)
	}
	fmt.Println("Tables:", tree.Tables())
	fmt.Println(tree.Format(gosqlx.WithIndent(2), gosqlx.WithUppercaseKeywords(true)))

	// Walk the AST - typed walkers avoid the type-assertion dance:
	tree.WalkSelects(func(s *ast.SelectStatement) bool {
		fmt.Printf("  SELECT with %d columns\n", len(s.Columns))
		return true
	})

	// The legacy Parse/Format/Validate API still works for v1.x code.
	// See docs/MIGRATION.md for the Tree migration guide.
}
