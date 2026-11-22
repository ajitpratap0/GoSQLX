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

## Comments and optimizer hints

`gosqlx.Format` keeps comments. A comment between statements stays between them, a trailing comment stays after its statement, and a comment inside a statement moves to the line above that statement:

```go
sql := "-- top users\nselect id, /* pk */ email from users where id = 1; -- one user\nselect 2"
out, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
if err != nil {
	log.Fatal(err)
}
fmt.Println(out)
```

Output:

```sql
-- top users
/* pk */
SELECT id, email
FROM users
WHERE id = 1; -- one user
SELECT 2
```

An optimizer hint (`/*+ ... */`) directly after the first keyword of a statement stays where it is, because moving it would change what the database does:

```go
out, _ := gosqlx.Format("select /*+ FULL(t) */ a from t", gosqlx.DefaultFormatOptions())
// SELECT /*+ FULL(t) */ a
// FROM t
```

When a hint or a MySQL `/*! ... */` comment cannot be put back faithfully, `Format` returns an error wrapping `formatter.ErrUnplaceableComment` (from `github.com/ajitpratap0/GoSQLX/pkg/formatter`) instead of rewriting the SQL without it. Leave such input unformatted:

```go
_, err := gosqlx.Format("select a from /*+ FULL(t) */ t", gosqlx.DefaultFormatOptions())
if errors.Is(err, formatter.ErrUnplaceableComment) {
	// keep the original text
}
fmt.Println(err)
// cannot format SQL: formatter: cannot preserve comment: /*+ FULL(t) */
```

If you work with a parsed tree instead of text, pass `gosqlx.WithComments()` to `gosqlx.ParseTree` so that `gosqlx.FormatTree` writes the comments back. A tree does not record where each comment stood, so comments on their own line go in front of the query and comments that shared a line with SQL go after it. Use `Format` or `FormatWithDialect` on the text when the placement matters.

## Format dialect-specific SQL

`gosqlx.Format` parses with the default dialect. To format SQL that only parses under a specific dialect, call `gosqlx.FormatWithDialect`, which tokenizes and parses with that dialect's rules and keeps comments and hints the same way as `Format`. Use it as follows:

```go
out, err := gosqlx.FormatWithDialect(
	"select top 10 [order id] from dbo.orders -- latest\nwhere total > 100",
	gosqlx.DefaultFormatOptions(),
	keywords.DialectSQLServer, // github.com/ajitpratap0/GoSQLX/pkg/sql/keywords
)
if err != nil {
	log.Fatal(err)
}
fmt.Println(out)
```

Output:

```sql
-- latest
SELECT TOP 10 [order id]
FROM dbo.orders
WHERE total > 100
```

An empty dialect behaves like `Format`, and an unknown dialect returns an error wrapping `gosqlx.ErrUnsupportedDialect`.

If you already hold a parsed tree, `tree.Format` takes functional options instead of `FormatOptions`:

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

The CLI keeps comments and a leading byte order mark. Before it writes a file with `-i`, it checks that the formatted output holds exactly the comments of the input, and it leaves the file unchanged when it does not. `--no-uppercase` writes every keyword in lower case, including keyword operators such as `AND`, `IN` and `IS NULL`, data types and built-in function keywords such as `CAST`; identifiers, quoted names and literals keep their spelling:

```bash
echo "SELECT a FROM t WHERE b IS NULL AND c IN (1,2) ORDER BY CAST(a AS INTEGER) DESC" | gosqlx format --no-uppercase
```

Output:

```sql
select a
from t
where b is null and c in (1, 2)
order by cast(a as integer) desc
```

## Next steps

- [Lint SQL in CI](lint-sql-in-ci.md): enforce formatting and style on every pull request
- [Build a custom SQL formatter](../tutorials/02-custom-sql-formatter.md): walk the AST yourself for full control over output
- [gosqlx package reference](../api/gosqlx.md)
