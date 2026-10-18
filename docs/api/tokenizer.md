# tokenizer package

The zero-copy SQL lexer that turns raw bytes into position-tagged tokens.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Functions

### `GetTokenizer() *Tokenizer`
Retrieve tokenizer from pool.

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz) // ALWAYS defer
```

### `PutTokenizer(t *Tokenizer)`
Return tokenizer to pool.

## Type: `Tokenizer`

### `Tokenize(input []byte) ([]models.TokenWithSpan, error)`
Tokenize SQL with zero-copy operation and position tracking.

```go
tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
```

### `TokenizeContext(ctx context.Context, input []byte) ([]models.TokenWithSpan, error)`
Tokenize with context support.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
tokens, err := tkz.TokenizeContext(ctx, []byte("SELECT * FROM users"))
```

## Supported Token Types

| Token Type | Example | Notes |
|------------|---------|-----------------|
| `TokenTypeSelect` | `SELECT` | ✅ Standard |
| `TokenTypeFrom` | `FROM` | ✅ Standard |
| `TokenTypeWhere` | `WHERE` | ✅ Standard |
| `TokenTypeIdentifier` | `users`, `id` | ✅ Standard |
| `TokenTypeNumber` | `42`, `3.14` | ✅ Scientific notation support |
| `TokenTypeSingleQuotedString` | `'hello'` | ✅ Standard |
| `TokenTypeDoubleQuotedString` | `"column name"` | ✅ Standard |
| `TokenTypeBacktickIdentifier` | `` `column` `` | ✅ MySQL dialect |
| `TokenTypeLateral` | `LATERAL` | ✅ PostgreSQL |
| `TokenTypeFilter` | `FILTER` | ✅ SQL:2003 |
| `TokenTypeDistinctOn` | `DISTINCT ON` | ✅ PostgreSQL |
| `TokenTypeReturning` | `RETURNING` | ✅ PostgreSQL |
| `TokenTypeFetch` | `FETCH FIRST` | ✅ SQL-99 F861 |
| `TokenTypeTruncate` | `TRUNCATE` | ✅ SQL:2008 |
| **JSON/JSONB Operators** | | |
| `TokenTypeArrow` | `->` | ✅ PostgreSQL |
| `TokenTypeDoubleArrow` | `->>` | ✅ PostgreSQL |
| `TokenTypeHashArrow` | `#>` | ✅ PostgreSQL |
| `TokenTypeHashDoubleArrow` | `#>>` | ✅ PostgreSQL |
| `TokenTypeAtGreater` | `@>` | ✅ PostgreSQL containment |
| `TokenTypeLessAt` | `<@` | ✅ PostgreSQL contained by |
| `TokenTypeQuestionMark` | `?` | ✅ PostgreSQL key exists |
| `TokenTypeQuestionPipe` | `?|` | ✅ PostgreSQL any key exists |
| `TokenTypeQuestionAmpersand` | `?&` | ✅ PostgreSQL all keys exist |
| `TokenTypeHashMinus` | `#-` | ✅ PostgreSQL delete at path |

**Features:**
- O(1) integer-based token type checking via the ModelType field
- Unicode support (UTF-8)
- Dialect-specific tokens (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- Zero-copy operations
- Position tracking (line, column, offset)
- Scientific notation support (1.23e4, 1.23E+4)
- Triple-quoted strings (Python-style)
- Escape sequences (\n, \t, \r, \\, \', \")
