# gosqlx package (high-level API)

The recommended entry point: parse, validate, format, lint and extract metadata with pooling handled for you.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/gosqlx` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/gosqlx))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

The high-level API provides convenient functions with automatic object pool management.

## Parsing Functions

### `Parse(sql string) (*ast.AST, error)`
Parse SQL in a single call.

```go
astNode, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
if err != nil {
    log.Fatal(err)
}
defer ast.ReleaseAST(astNode)
```

### `ParseWithContext(ctx context.Context, sql string) (*ast.AST, error)`
Parse with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

astNode, err := gosqlx.ParseWithContext(ctx, sql)
if err == context.DeadlineExceeded {
    log.Println("Parsing timed out")
}
defer ast.ReleaseAST(astNode)
```

### `ParseWithTimeout(sql string, timeout time.Duration) (*ast.AST, error)`
Convenience wrapper with automatic timeout.

```go
astNode, err := gosqlx.ParseWithTimeout(sql, 10*time.Second)
defer ast.ReleaseAST(astNode)
```

### `ParseBytes(sql []byte) (*ast.AST, error)`
Parse from byte slice (zero-copy when already in bytes).

```go
sqlBytes, _ := os.ReadFile("query.sql")
astNode, err := gosqlx.ParseBytes(sqlBytes)
defer ast.ReleaseAST(astNode)
```

### `MustParse(sql string) *ast.AST`
Parse SQL, panicking on error (for tests and initialization).

```go
ast := gosqlx.MustParse("SELECT 1")
defer ast.ReleaseAST(ast)
```

### `ParseMultiple(queries []string) ([]*ast.AST, error)`
Parse multiple SQL statements in one call (see [benchmarks](/benchmarks/) for measured numbers).

```go
queries := []string{
    "SELECT * FROM users",
    "SELECT * FROM orders",
}
asts, err := gosqlx.ParseMultiple(queries)
for _, ast := range asts {
    defer ast.ReleaseAST(ast)
}
```

## Validation Functions

### `Validate(sql string) error`
Check if SQL is syntactically valid.

```go
if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
    fmt.Printf("Invalid SQL: %v\n", err)
}
```

### `ValidateMultiple(queries []string) error`
Validate multiple queries efficiently.

```go
queries := []string{"SELECT * FROM users", "INSERT INTO logs (msg) VALUES ('test')"}
if err := gosqlx.ValidateMultiple(queries); err != nil {
    log.Fatal("Validation failed:", err)
}
```

## Formatting Functions

### `Format(sql string, options FormatOptions) (string, error)`
Parse SQL with the default dialect and render it back as consistently styled text. `DefaultFormatOptions()` returns the defaults (`IndentSize` 2, `UppercaseKeywords` false, `AddSemicolon` false). Invalid SQL returns an error wrapping `ErrTokenize` or `ErrSyntax`.

```go
opts := gosqlx.DefaultFormatOptions()
opts.AddSemicolon = true
out, err := gosqlx.Format("select id from users where id = 1", opts)
// SELECT id
// FROM users
// WHERE id = 1;
```

On the main branch (unreleased, next release), `Format` keeps comments and optimizer hints. A comment inside a statement moves to the line above it, and a `/*+ ... */` hint directly after a statement's first keyword stays there. SQL whose hints or MySQL `/*! ... */` comments cannot be put back faithfully returns an error wrapping `formatter.ErrUnplaceableComment` (package `pkg/formatter`) instead of being rewritten without them:

```go
_, err := gosqlx.Format("select a from /*+ FULL(t) */ t", gosqlx.DefaultFormatOptions())
errors.Is(err, formatter.ErrUnplaceableComment) // true
```

See [Format SQL in Go](../guides/format-sql-in-go.md#comments-and-optimizer-hints) for examples.

### `FormatWithDialect(sql string, options FormatOptions, dialect keywords.SQLDialect) (string, error)`
`Format` for SQL in a specific dialect: the SQL is tokenized and parsed with that dialect's rules, and comments and hints are kept as in `Format`. An empty dialect behaves like `Format`; an unknown dialect returns an error wrapping `ErrUnsupportedDialect`. This function is unreleased and available on the main branch.

```go
out, err := gosqlx.FormatWithDialect(
    "select top 10 [order id] from dbo.orders -- latest\nwhere total > 100",
    gosqlx.DefaultFormatOptions(),
    keywords.DialectSQLServer,
)
// -- latest
// SELECT TOP 10 [order id]
// FROM dbo.orders
// WHERE total > 100
```

### `WithComments() Option`
A `ParseTree` option that keeps the comments of the input on the tree so that `FormatTree` and `FormatAST` write them back. Without it comments are discarded. A tree does not record where each comment stood: comments on their own line go in front of the query and comments that shared a line with SQL go after it, so use `Format` on the text when placement matters. This option is unreleased and available on the main branch.

```go
tree, err := gosqlx.ParseTree(ctx, "SELECT 1 -- one", gosqlx.WithComments())
out := gosqlx.FormatTree(tree) // "SELECT 1 -- one"
```

## Linting Functions

### `Lint(sql string) (*LintResult, error)`
Run all 30 built-in rules (L001-L030) and return the violations in `LintResult.Violations`.

### `LintWithDialect(sql string, dialect keywords.SQLDialect) (*LintResult, error)`
`Lint` with the SQL tokenized and parsed in the given dialect, so the AST-based rules (L011-L030) also run on dialect-specific syntax. An empty dialect behaves like `Lint`; an unknown dialect returns an error wrapping `ErrUnsupportedDialect`.

On the main branch (unreleased, next release), both functions report SQL that does not tokenize or parse as an error: the error wraps `ErrTokenize` or `ErrSyntax`, and the returned `*LintResult` still holds the violations of the text and token rules. Code that ignored the error and treated an empty result as clean must check it:

```go
res, err := gosqlx.LintWithDialect("SELEC 1", keywords.DialectPostgreSQL)
if errors.Is(err, gosqlx.ErrSyntax) {
    // invalid SQL; res is not nil and may still list text-rule violations
}
_ = res
```

The lower-level `linter.FileResult` (package `pkg/linter`) gains the fields `TokenizeError` and `ParseError` and the method `SyntaxError()`, which returns whichever of the two is set.

## Script Splitting

### `SplitStatements(sql, dialect string) []string`
Split a script into statements at top-level semicolons, ignoring semicolons inside strings, quoted identifiers and comments. The dialect selects the quoting rules, such as PostgreSQL dollar quotes, MySQL backticks and SQL Server brackets; an unknown dialect falls back to ANSI quoting. The terminating `;` is removed and empty segments are kept, so trim and skip them. Segments are substrings of the input, so no bytes are copied.

On the main branch (unreleased, next release), the splitter also:

- keeps compound statements whole: `BEGIN ... END` bodies of triggers, procedures and functions, T-SQL `BEGIN TRY` and `IF ... BEGIN`, PostgreSQL `BEGIN ATOMIC`, `CASE ... END`, `IF`/`LOOP`/`WHILE`/`REPEAT` inside a block, and Oracle `DECLARE` sections. Transaction statements such as `BEGIN;` are not blocks, and a script whose blocks do not balance falls back to plain `;` splitting;
- honours client batch separators and removes them from the output: a line holding only `GO [n]` for SQL Server, `DELIMITER` for MySQL and MariaDB, and a line holding only `/` for Oracle;
- follows each dialect's backslash escapes in strings, and does not end a statement at a `;` inside parentheses.

```go
parts := gosqlx.SplitStatements("DELIMITER //\nCREATE PROCEDURE p() BEGIN SELECT 1; END//\nDELIMITER ;\nSELECT 2;", "mysql")
// ["CREATE PROCEDURE p() BEGIN SELECT 1; END", "SELECT 2"]

parts = gosqlx.SplitStatements("SELECT 1\nGO\nSELECT 2\nGO 3\n", "sqlserver")
// ["SELECT 1\n", "SELECT 2\n"]
```

## Transpilation

### `Transpile(sql string, from, to keywords.SQLDialect) (string, error)`
Parse SQL in the `from` dialect and render it for the `to` dialect, applying the rewrite rules registered for that pair.

```go
out, err := gosqlx.Transpile(
    "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
    keywords.DialectMySQL,
    keywords.DialectPostgreSQL,
)
// CREATE TABLE t (id SERIAL PRIMARY KEY)
```

On the main branch (unreleased, next release), string literals and quoted identifiers are written with the target dialect's escape rules and delimiters, and dialect-specific operators are mapped for the target: `^` is exponentiation in PostgreSQL and bitwise XOR in MySQL, MariaDB and SQL Server, and PostgreSQL `@`, `|/` and `||/` become `ABS()`, `SQRT()` and `CBRT()`. A literal, operator or SQL Server `GO` script the target cannot represent returns an error instead of SQL with a different meaning:

```go
gosqlx.Transpile("SELECT `Order Id` FROM t WHERE n = 'it\\'s'", keywords.DialectMySQL, keywords.DialectPostgreSQL)
// SELECT "Order Id" FROM t WHERE n = 'it''s'

gosqlx.Transpile("SELECT 2 ^ 3", keywords.DialectPostgreSQL, keywords.DialectMySQL)
// SELECT POWER(2, 3)

gosqlx.Transpile("SELECT a ^ b FROM t", keywords.DialectMySQL, keywords.DialectOracle)
// error: rewrite: the bitwise XOR operator ^ has no equivalent in oracle
```

## Metadata Extraction

### `ExtractColumns(astNode *ast.AST) []string`
Return the deduplicated, sorted column names referenced in SELECT lists, WHERE, GROUP BY, ORDER BY, JOIN conditions and HAVING, without table qualifiers.

On the main branch (unreleased, next release; issue #849), an unqualified name in `ORDER BY` or `HAVING` that matches a SELECT-list alias of the same query block is treated as the alias, not reported as a column. Qualified references stay columns, and aliases never cross subquery, CTE or UNION boundaries. `ExtractColumnsQualified` follows the same rule.

```go
tree, _ := gosqlx.Parse("SELECT count(*) AS orders FROM t GROUP BY customer_id ORDER BY orders")
cols := gosqlx.ExtractColumns(tree)
// [customer_id]
```
