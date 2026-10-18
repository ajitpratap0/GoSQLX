# errors package

Structured errors with codes, positions and hints.

Import path: `github.com/ajitpratap0/GoSQLX/pkg/errors` ([pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/errors))

Part of the [GoSQLX API reference](../API_REFERENCE.md).

## Types

### `Error`
```go
type Error struct {
    Code     ErrorCode        // NEW v1.6.0: Structured error codes
    Message  string
    Location *models.Location
    Context  string
    Hint     string           // NEW v1.6.0: Helpful hints
    DocURL   string           // NEW v1.6.0: Documentation link
}
```

**v1.6.0 Enhancements:**
- Structured error codes (E1001-E1005 tokenizer, E2001-E2012 parser, E3001-E3004 semantic)
- Helpful hints for common errors
- Documentation links

### `ErrorCode` (Type)
```go
type ErrorCode string

const (
    // Tokenizer errors (E1001-E1005)
    ErrCodeUnterminatedString   ErrorCode = "E1001"
    ErrCodeInvalidNumber        ErrorCode = "E1002"
    ErrCodeUnexpectedCharacter  ErrorCode = "E1003"
    ErrCodeInvalidEscape        ErrorCode = "E1004"
    ErrCodeUnterminatedComment  ErrorCode = "E1005"

    // Parser errors (E2001-E2012)
    ErrCodeSyntax               ErrorCode = "E2001"
    ErrCodeUnexpectedToken      ErrorCode = "E2002"
    ErrCodeUnexpectedEOF        ErrorCode = "E2003"
    ErrCodeInvalidIdentifier    ErrorCode = "E2004"
    ErrCodeUnsupportedFeature   ErrorCode = "E2005"
    ErrCodeInvalidExpression    ErrorCode = "E2006"
    ErrCodeMissingColumn        ErrorCode = "E2007"
    ErrCodeMissingTable         ErrorCode = "E2008"
    ErrCodeInvalidJoin          ErrorCode = "E2009"
    ErrCodeInvalidWindow        ErrorCode = "E2010"
    ErrCodeInvalidGroupBy       ErrorCode = "E2011"
    ErrCodeInvalidOrderBy       ErrorCode = "E2012"

    // Semantic errors (E3001-E3004)
    ErrCodeUndefinedTable       ErrorCode = "E3001"
    ErrCodeUndefinedColumn      ErrorCode = "E3002"
    ErrCodeTypeMismatch         ErrorCode = "E3003"
    ErrCodeAmbiguousColumn      ErrorCode = "E3004"
)
```

## Functions

### `NewSyntaxError(msg string, loc *models.Location) *Error`
Create syntax error.

```go
err := errors.NewSyntaxError("Expected FROM", &location)
```

### `NewUnexpectedTokenError(expected, got string, loc *models.Location) *Error`
Create unexpected token error.

### `NewUnexpectedEOFError(loc *models.Location) *Error`
Create unexpected EOF error.

### `(e *Error) Error() string`
Get error message.

### `(e *Error) WithContext(ctx string) *Error`
Add context to error.

### `(e *Error) WithHint(hint string) *Error` (**NEW v1.6.0**)
Add helpful hint.

### `(e *Error) WithDocURL(url string) *Error` (**NEW v1.6.0**)
Add documentation link.

**Example:**
```go
err := errors.NewSyntaxError("Missing WHERE clause", &loc).
    WithHint("Consider adding a WHERE clause to filter results").
    WithDocURL("https://gosqlx.dev/docs/where-clause")
```
