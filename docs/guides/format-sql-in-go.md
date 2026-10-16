# Format SQL in Go

This guide shows how to format SQL in Go with GoSQLX: pretty-print a query from your code, choose indentation and keyword style, format dialect-specific SQL, and check or rewrite `.sql` files from the command line. The formatter works on the parsed AST, so its output is consistent no matter how the input was laid out.

## Install

```bash
go get github.com/ajitpratap0/GoSQLX
```

## Format a string

`gosqlx.Format` takes SQL text and a `FormatOptions` value and returns the formatted SQL.

```go
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	messy := "select u.id, u.email, count(o.id) as orders from users u left join orders o on o.user_id = u.id where u.active = true group by u.id, u.email order by orders desc limit 10"

	opts := gosqlx.DefaultFormatOptions()
	opts.AddSemicolon = true

	out, err := gosqlx.Format(messy, opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
```

Output:

```sql
SELECT u.id, u.email, count(o.id) AS orders
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
WHERE u.active = true
GROUP BY u.id, u.email
ORDER BY orders DESC
LIMIT 10;
```

Each clause starts on its own line, keywords are upper case and identifiers keep their original spelling.

## Formatting options

`gosqlx.DefaultFormatOptions()` returns sensible defaults. The fields you can change are:

| Field | Default | Effect |
|---|---|---|
| `IndentSize` | `2` | Spaces per indentation level |
| `AddSemicolon` | `false` | Append a trailing `;` when the statement has none |
| `UppercaseKeywords` | `false` | Request upper-case keywords. The current formatter emits upper-case keywords either way, so setting it to `false` does not lower-case them |
| `SingleLineLimit` | `80` | Deprecated and currently ignored; kept so existing callers compile |

Create the options once and reuse them. A `FormatOptions` value is safe to share between goroutines as long as nobody modifies it.

## Invalid SQL is an error, not a guess

The formatter parses before it prints, so it never reshuffles text it does not understand:

```go
_, err := gosqlx.Format("select from where", gosqlx.DefaultFormatOptions())
fmt.Println(err)
// cannot format invalid SQL: gosqlx: syntax error: Error E2002 at line 1, column 8: expected column expression, got FROM
```

Use `errors.Is(err, gosqlx.ErrSyntax)` and `gosqlx.ErrorLocation(err)` to report the position, as shown in [Parse PostgreSQL in Go](parse-postgresql-in-go.md#handle-syntax-errors).

## Comments are not preserved

Because the output is generated from the AST, SQL comments (`-- ...` and `/* ... */`) are dropped:

```go
out, _ := gosqlx.Format("-- top users\nselect id /* pk */ from users where id = 1", gosqlx.DefaultFormatOptions())
// SELECT id
// FROM users
// WHERE id = 1
```

If your files carry important comments, run the formatter in check mode in CI rather than rewriting files automatically, or keep comments outside the statements you format.

## Format dialect-specific SQL

`gosqlx.Format` parses with the default dialect. To format SQL that only parses under a specific dialect, parse it into a `Tree` with that dialect and call `Format` on the tree:

```go
tree, err := gosqlx.ParseTree(ctx,
	`select payload->>'status' as s from orders where payload @> '{"a":1}'`,
	gosqlx.WithDialect("postgresql"))
if err != nil {
	log.Fatal(err)
}
defer tree.Release()

fmt.Println(tree.Format(gosqlx.WithIndent(4), gosqlx.WithUppercaseKeywords(true)))
```

Output:

```sql
SELECT payload ->> 'status' AS s
FROM orders
WHERE payload @> '{"a":1}'
```

`tree.Format` takes functional options (`gosqlx.WithIndent`, `gosqlx.WithUppercaseKeywords`). If you already hold a raw `*ast.AST`, `gosqlx.FormatAST` does the same.

## Several statements

Input with several statements is formatted statement by statement, separated by semicolons:

```go
out, _ := gosqlx.Format("select 1; select 2", gosqlx.DefaultFormatOptions())
// SELECT 1;
// SELECT 2
```

## Format files from the CLI

The `gosqlx` command formats files without writing Go:

```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest

gosqlx format query.sql              # print the formatted SQL
gosqlx format -i queries/*.sql       # rewrite files in place
gosqlx format --check queries/*.sql  # exit 1 if any file would change
gosqlx format --indent 4 --dialect mysql report.sql
```

`--check` prints the files that need formatting and exits with status 1, which makes it a good CI gate. Defaults can be set in a `.gosqlx.yml` file; see [Configuration](../CONFIGURATION.md).

## Next steps

- [Lint SQL in CI](lint-sql-in-ci.md): enforce formatting and style on every pull request
- [Build a custom SQL formatter](../tutorials/02-custom-sql-formatter.md): walk the AST yourself for full control over output
- [gosqlx package reference](../api/gosqlx.md)
