# Parse PostgreSQL in Go

This guide shows how to parse PostgreSQL queries in Go with GoSQLX: turn SQL text into an AST, read what the query touches, handle syntax errors with line and column positions, and validate `.sql` files from the command line. GoSQLX is written in pure Go, so there is no cgo, no `libpg_query` and no C toolchain in your build.

## Install

```bash
go get github.com/ajitpratap0/GoSQLX
```

GoSQLX needs Go 1.26 or later.

## Parse a query with the PostgreSQL dialect

`gosqlx.ParseTree` is the recommended entry point. Pass `gosqlx.WithDialect("postgresql")` so PostgreSQL-only syntax such as `DISTINCT ON`, JSONB operators, `::` casts and `LATERAL` joins is recognised.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

const query = `
SELECT DISTINCT ON (o.customer_id)
       o.customer_id,
       o.payload->>'status' AS status,
       o.created_at::date AS day
FROM orders o
JOIN LATERAL (
    SELECT count(*) AS n FROM order_items i WHERE i.order_id = o.id
) items ON true
WHERE o.payload @> '{"paid": true}'
ORDER BY o.customer_id, o.created_at DESC`

func main() {
	tree, err := gosqlx.ParseTree(context.Background(), query, gosqlx.WithDialect("postgresql"))
	if err != nil {
		log.Fatal(err)
	}
	defer tree.Release()

	fmt.Println("statements:", len(tree.Statements()))
	fmt.Println("tables:", tree.Tables())
}
```

Output:

```text
statements: 1
tables: [order_items orders]
```

`tree.Release()` returns the pooled AST nodes. Call it (usually with `defer`) when you are done with the tree. The dialect name is `postgresql`; the shorter `postgres` is rejected with `gosqlx.ErrUnsupportedDialect`.

## PostgreSQL syntax GoSQLX understands

With the PostgreSQL dialect enabled the parser handles, among others:

- `DISTINCT ON (...)`
- JSON and JSONB operators: `->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`, `#-`
- `::` type casts
- `LATERAL` subqueries in `FROM` and `JOIN`
- `RETURNING` on `INSERT`, `UPDATE` and `DELETE`
- `INSERT ... ON CONFLICT ... DO NOTHING` and `DO UPDATE`
- `FILTER (WHERE ...)` on aggregates and `ORDER BY` inside aggregates
- Positional parameters such as `$1`

The [SQL Compatibility](../SQL_COMPATIBILITY.md) page lists the full PostgreSQL matrix, including what is not supported yet.

## Inspect the AST

The `Tree` type has typed walkers, so you rarely need to type-switch on nodes yourself. Each callback returns `true` to keep walking.

```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

tree.WalkSelects(func(s *ast.SelectStatement) bool {
	fmt.Println("DISTINCT ON columns:", len(s.DistinctOnColumns))
	return true
})
```

Walkers visit nested statements too, so the `LATERAL` subquery above is reported as a second `SelectStatement`.

The same approach works for writes. Here the `RETURNING` clause is available on the insert node:

```go
ins, err := gosqlx.ParseTree(ctx,
	`INSERT INTO users (email) VALUES ('a@example.com')
	 ON CONFLICT (email) DO NOTHING
	 RETURNING id`,
	gosqlx.WithDialect("postgresql"))
if err != nil {
	log.Fatal(err)
}
defer ins.Release()

ins.WalkInserts(func(i *ast.InsertStatement) bool {
	fmt.Println("insert into", i.TableName, "returning", len(i.Returning), "column(s)")
	return true
})
// insert into users returning 1 column(s)
```

Other walkers include `WalkUpdates`, `WalkDeletes`, `WalkJoins`, `WalkCTEs`, `WalkFunctionCalls`, `WalkIdentifiers` and the generic `Walk`. For node-level access use `tree.Raw()`, which returns the underlying `*ast.AST`. The [ast package reference](../api/ast.md) documents every node type.

## Handle syntax errors

Parse errors wrap sentinel errors, so you can branch with `errors.Is`, and they carry a stable error code and a source position.

```go
_, err := gosqlx.ParseTree(ctx, "SELECT * FROM WHERE id = 1", gosqlx.WithDialect("postgresql"))
if errors.Is(err, gosqlx.ErrSyntax) {
	loc := gosqlx.ErrorLocation(err)
	fmt.Printf("%s at line %d, column %d\n", gosqlx.ErrorCode(err), loc.Line, loc.Column)
	fmt.Println(gosqlx.ErrorHint(err))
}
```

Output:

```text
E2002 at line 1, column 15
expected identifier here
```

The other sentinels are `gosqlx.ErrTokenize`, `gosqlx.ErrTimeout` and `gosqlx.ErrUnsupportedDialect`. Every code is described in [Error Codes](../ERROR_CODES.md).

## Parse untrusted or very large input

When SQL comes from users or from files you do not control, bound the work. `WithTimeout` caps parse time, and `ParseTree` also honours cancellation of `ctx`:

```go
tree, err := gosqlx.ParseTree(ctx, sql,
	gosqlx.WithDialect("postgresql"),
	gosqlx.WithTimeout(2*time.Second),
)
```

To read from a file, request body or other stream, use `gosqlx.ParseReader`. With `WithMaxBytes` it refuses oversized input before doing any parsing work:

```go
tree, err := gosqlx.ParseReader(ctx, r,
	gosqlx.WithDialect("postgresql"),
	gosqlx.WithMaxBytes(1<<20), // 1 MiB
)
if errors.Is(err, gosqlx.ErrTooLarge) {
	// reject the input
}
```

## Parse several statements

A script with several statements separated by semicolons parses into one tree with several statements:

```go
tree, err := gosqlx.ParseTree(ctx, "SELECT a FROM t; SELECT b FROM u", gosqlx.WithDialect("postgresql"))
// len(tree.Statements()) == 2
```

To parse a batch of independent queries, `gosqlx.ParseMultiple` reuses pooled objects across the batch.

## The older function API

`ParseTree` arrived in v1.15.0. Code written against earlier releases uses `gosqlx.ParseWithDialect`, which returns a raw `*ast.AST` and is still supported:

```go
import "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"

astTree, err := gosqlx.ParseWithDialect(sql, keywords.DialectPostgreSQL)
```

## Validate PostgreSQL files from the CLI

The `gosqlx` command validates files without writing any Go:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

gosqlx validate --dialect postgresql migrations/*.sql
gosqlx validate --dialect postgresql -r ./sql/
```

The command exits with a non-zero status when a file does not parse, so it can gate a CI job. See [Lint SQL in CI](lint-sql-in-ci.md) for a full workflow.

## Coming from pg_query_go

`pg_query_go` wraps the real PostgreSQL parser through cgo. GoSQLX is a separate pure Go parser: builds are simpler and cross-compile cleanly, the same code handles seven other dialects, and coverage of rarely used PostgreSQL grammar is narrower. The [migration guide from pg_query](../migration/FROM_PG_QUERY.md) maps the APIs side by side.

## Next steps

- [Extract table names from SQL in Go](extract-table-names-from-sql-in-go.md)
- [Format SQL in Go](format-sql-in-go.md)
- [Detect SQL injection in Go](detect-sql-injection-in-go.md)
- [gosqlx package reference](../api/gosqlx.md)
