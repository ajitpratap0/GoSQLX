# Extract table names from SQL in Go

This guide shows how to extract table names, column names and function calls from SQL in Go with GoSQLX. Typical uses are query auditing, access control checks, data lineage, cache invalidation and routing queries to the right shard. Because GoSQLX parses the query instead of matching it with regular expressions, it finds tables inside joins, subqueries and CTEs and ignores names that only appear in strings or comments.

## Install

```bash
go get github.com/ajitpratap0/GoSQLX
```

## List the tables in a query

Parse the query into a `Tree` and call `Tables()`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

const query = `
WITH recent AS (
    SELECT customer_id, total FROM sales.orders WHERE created_at > $1
)
SELECT c.name, r.total
FROM public.customers c
JOIN recent r ON r.customer_id = c.id
WHERE c.region_id IN (SELECT id FROM regions WHERE active)`

func main() {
	tree, err := gosqlx.ParseTree(context.Background(), query, gosqlx.WithDialect("postgresql"))
	if err != nil {
		log.Fatal(err)
	}
	defer tree.Release()

	fmt.Println("tables:   ", tree.Tables())
	fmt.Println("columns:  ", tree.Columns())
	fmt.Println("functions:", tree.Functions())
}
```

Output:

```text
tables:    [public.customers recent regions sales.orders]
columns:   [active created_at customer_id id name region_id total]
functions: []
```

A few things to notice:

- Results are de-duplicated and sorted, so the output is stable across runs.
- Schema-qualified names keep their schema (`sales.orders`, `public.customers`).
- The table in the `IN (SELECT ...)` subquery is found.
- Aliases (`c`, `r`) are not reported as tables.
- The CTE name `recent` is reported, because the query reads from it. The next section shows how to drop it.

## Exclude CTE names

For lineage or permission checks you usually want only physical tables. Collect the CTE names with `WalkCTEs` and filter them out:

```go
import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// physicalTables returns the tables a query reads or writes, without CTE names.
func physicalTables(tree *gosqlx.Tree) []string {
	ctes := map[string]bool{}
	tree.WalkCTEs(func(c *ast.CommonTableExpr) bool {
		ctes[strings.ToLower(c.Name)] = true
		return true
	})
	var out []string
	for _, t := range tree.Tables() {
		if !ctes[strings.ToLower(t)] {
			out = append(out, t)
		}
	}
	return out
}
```

For the query above this returns `[public.customers regions sales.orders]`.

## Get schema and table separately

`Tables()` returns display strings. When you need the parts, use `gosqlx.ExtractTablesQualified` on the raw AST:

```go
for _, t := range gosqlx.ExtractTablesQualified(tree.Raw()) {
	fmt.Printf("schema=%q table=%q\n", t.Schema, t.Name)
}
```

Output:

```text
schema="" table="recent"
schema="" table="regions"
schema="public" table="customers"
schema="sales" table="orders"
```

`QualifiedName` also has `String()` for the full dotted name and `FullName()` for the name without the schema. `gosqlx.ExtractColumnsQualified` does the same for columns, keeping the table or alias qualifier (`c.name`).

## Tables written by INSERT, UPDATE and DELETE

Extraction covers data-modifying statements as well, including the source tables of `INSERT ... SELECT`. With the function API:

```go
a, err := gosqlx.Parse("INSERT INTO audit_log (id) SELECT id FROM users; UPDATE accounts SET x = 1; DELETE FROM sessions")
if err != nil {
	log.Fatal(err)
}
fmt.Println(gosqlx.ExtractTables(a))
// [accounts audit_log sessions users]
```

To tell reads from writes, walk the statements by kind: `tree.WalkInserts`, `tree.WalkUpdates` and `tree.WalkDeletes` hand you the statement node, whose `TableName` field is the target table.

DDL statements such as `CREATE TABLE` are not part of table extraction; inspect them with `tree.WalkCreateTables`.

## Everything at once

`gosqlx.ExtractMetadata` returns tables, columns and functions in one call:

```go
md := gosqlx.ExtractMetadata(tree.Raw())
fmt.Println(md.Tables, md.Columns, md.Functions)
```

## Use it as a guard

A common pattern is to reject queries that touch tables a caller is not allowed to read:

```go
func checkAccess(ctx context.Context, sql string, allowed map[string]bool) error {
	tree, err := gosqlx.ParseTree(ctx, sql, gosqlx.WithDialect("postgresql"))
	if err != nil {
		return fmt.Errorf("parse query: %w", err)
	}
	defer tree.Release()

	for _, t := range physicalTables(tree) {
		if !allowed[t] {
			return fmt.Errorf("access to table %q is not allowed", t)
		}
	}
	return nil
}
```

Treat this as one layer of defence: database permissions remain the real boundary.

## From an AI assistant

The GoSQLX MCP server exposes the same extraction as its `extract_metadata` tool, so Claude, Cursor and other MCP clients can list the tables in a query. See the [MCP guide](../MCP_GUIDE.md).

## Next steps

- [Parse PostgreSQL in Go](parse-postgresql-in-go.md): dialects, walkers and error handling
- [Detect SQL injection in Go](detect-sql-injection-in-go.md)
- [gosqlx package reference](../api/gosqlx.md)
