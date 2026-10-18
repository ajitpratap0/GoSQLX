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

### `Parse(tokens []token.Token) (*ast.AST, error)`
Parse tokens into AST.

```go
astNode, err := p.Parse(tokens)
```

**Supported Statements (v1.6.0):**

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
Parse with context support.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
astNode, err := p.ParseContext(ctx, tokens)
```

### `Reset()`
Reset parser state for reuse.
