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

## Dialect-specific lexing

Use `NewWithDialect(dialect keywords.SQLDialect) (*Tokenizer, error)` or
`(*Tokenizer).SetDialect(dialect keywords.SQLDialect)` before tokenizing.
An empty dialect or `keywords.DialectUnknown` selects PostgreSQL keyword
recognition, with strict string escapes; an explicit PostgreSQL dialect uses
standard strings with literal backslashes.

- Numeric tokens retain their source spelling. Decimal and exponent forms are
  supported; `0x` hexadecimal forms are accepted in every dialect. PostgreSQL,
  MySQL/MariaDB and ClickHouse also accept `0b` binary forms; PostgreSQL accepts
  `0o` octal forms. PostgreSQL, SQLite and ClickHouse allow single underscores
  between digits, and PostgreSQL also allows one immediately after a base prefix.
  Oracle accepts floating-point suffixes such as `1.5f` and `1e5D`.
- PostgreSQL `U&'...'` strings and `U&"..."` identifiers support four-digit and
  `+` six-digit Unicode escapes, surrogate pairs and an optional `UESCAPE`
  character. Invalid Unicode escapes return an error. Strings retain validated
  source spelling; identifiers expose decoded names.
- String backslash handling follows the selected dialect: PostgreSQL standard
  strings, Oracle, SQLite, SQL Server and generic SQL keep backslashes literal;
  MySQL/MariaDB decode escapes while preserving `\%` and `\_`; ClickHouse and
  BigQuery decode supported escapes and keep unknown ones; Snowflake and Redshift
  decode supported escapes and drop the backslash on unknown ones. An unconfigured
  tokenizer uses strict escapes and rejects dialect-dependent escape sequences.
- MySQL and MariaDB treat `#` through the end of the line as a comment. In other
  dialects it remains available to operators or identifiers according to their
  lexical rules.

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
| `TokenTypeQuestionPipe` | `?\|` | ✅ PostgreSQL any key exists |
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
- Escape sequences follow the configured dialect
