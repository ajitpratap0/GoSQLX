# parser package

The recursive descent parser that turns tokens into an AST.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/sql/parser` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/sql/parser))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Functions

### `NewParser() *Parser`
Create parser from pool.

```go
p := parser.NewParser()
defer p.Release() // ALWAYS defer
```

## Type: `Parser`

### `ParseFromModelTokens(tokens []models.TokenWithSpan) (*ast.AST, error)`
Parse tokenizer output directly into an AST. This is the preferred entry point and the one used in the documented pipeline: the tokenizer returns `[]models.TokenWithSpan`, which you pass straight to the parser. Span information is preserved for error reporting.

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

tokens, err := tkz.Tokenize([]byte("SELECT id FROM users"))
if err != nil {
    return err
}

p := parser.NewParser()
defer p.Release()

astNode, err := p.ParseFromModelTokens(tokens)
if err != nil {
    return err
}
defer ast.ReleaseAST(astNode)
```

### `ParseContextFromModelTokens(ctx context.Context, tokens []models.TokenWithSpan) (*ast.AST, error)`
Parse tokenizer output with context support for cancellation and timeouts.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
astNode, err := p.ParseContextFromModelTokens(ctx, tokens)
```

### `ParseFromModelTokensWithPositions(tokens []models.TokenWithSpan) (*ast.AST, error)`
Deprecated. It is identical to `ParseFromModelTokens`, because every `models.TokenWithSpan` already carries its position. Use `ParseFromModelTokens` instead.

### `Parse(tokens []token.Token) (*ast.AST, error)`
Parse a `[]token.Token` slice into an AST. Kept for backward compatibility; prefer `ParseFromModelTokens`, which accepts the tokenizer output directly and keeps span information.

```go
astNode, err := p.Parse(tokens)
```

**Supported Statements:**

**DML (Data Manipulation Language):**
- SELECT (with DISTINCT, DISTINCT ON)
- INSERT (with RETURNING clause)
- UPDATE (with RETURNING clause)
- DELETE (with RETURNING clause)
- MERGE (SQL:2003 F312)
- TRUNCATE TABLE (SQL:2008)

**DDL (Data Definition Language):**
- CREATE TABLE/INDEX/VIEW/MATERIALIZED VIEW
- ALTER TABLE
- DROP TABLE/INDEX/VIEW/MATERIALIZED VIEW

**Advanced Features:**
- CTEs (Common Table Expressions) with RECURSIVE support
- Window functions (ROW_NUMBER, RANK, DENSE_RANK, NTILE, LAG, LEAD, FIRST_VALUE, LAST_VALUE)
- Set operations (UNION, EXCEPT, INTERSECT)
- Grouping Sets (ROLLUP, CUBE, GROUPING SETS)
- PostgreSQL extensions (LATERAL JOIN, FILTER clause, DISTINCT ON, JSON/JSONB operators)
- FETCH FIRST/OFFSET-FETCH (SQL-99 F861, F862)

### `ParseContext(ctx context.Context, tokens []token.Token) (*ast.AST, error)`
Parse a `[]token.Token` slice with context support. Kept for backward compatibility; prefer `ParseContextFromModelTokens`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
astNode, err := p.ParseContext(ctx, tokens)
```

### `Reset()`
Reset parser state for reuse.
