# LSP Error Code Support

## Overview

The GoSQLX LSP server now includes error codes in diagnostics, providing better integration with IDEs and enabling programmatic error handling.

## Features

### Error Code Extraction

When GoSQLX encounters parsing errors, the LSP server extracts structured error information including:

- **Error Code**: Unique identifier (e.g., `E2001`, `E1002`) for programmatic handling
- **Location**: Precise line and column position (converted to 0-based for LSP)
- **Clean Message**: Error message without verbose context for better IDE display
- **Severity**: Error severity level (error, warning, info, hint)

### Error Code Categories

GoSQLX uses a structured error code system:

- **E1xxx**: Tokenizer errors (lexical analysis)
  - `E1001`: Unexpected character
  - `E1002`: Unterminated string literal
  - `E1003`: Invalid number format
  - `E1004`: Invalid operator sequence

- **E2xxx**: Parser syntax errors
  - `E2001`: Unexpected token
  - `E2002`: Expected token not found
  - `E2003`: Missing required clause
  - `E2004`: General syntax error

- **E3xxx**: Semantic errors
  - `E3001`: Undefined table
  - `E3002`: Undefined column
  - `E3003`: Type mismatch

- **E4xxx**: Unsupported features
  - `E4001`: Feature not yet supported
  - `E4002`: SQL dialect not supported

## LSP Diagnostic Format

Diagnostics published to the LSP client include:

```json
{
  "range": {
    "start": {"line": 4, "character": 9},
    "end": {"line": 4, "character": 15}
  },
  "severity": 1,
  "code": "E2001",
  "source": "gosqlx",
  "message": "unexpected token SELECT"
}
```

## Implementation Details

### Handler Updates

The `createDiagnosticFromError` function now:

1. **Detects structured errors**: Checks if the error is a `*errors.Error` type
2. **Extracts error code**: Uses the `Code` field from structured errors
3. **Converts positions**: Transforms 1-based positions to 0-based for LSP
4. **Provides clean messages**: Uses the message field without verbose context

### Backward Compatibility

The implementation maintains backward compatibility:

- **Structured errors**: Full error code and position information
- **Plain errors**: Fallback to regex-based position extraction
- **No error code**: Diagnostic still created without the `code` field

### Code Example

```go
// Before (without error code)
diag := Diagnostic{
    Range: Range{Start: Position{Line: 4, Character: 9}, End: Position{Line: 4, Character: 15}},
    Severity: SeverityError,
    Source: "gosqlx",
    Message: "Error E2001 at line 5, column 10: unexpected token SELECT...",
}

// After (with error code)
diag := Diagnostic{
    Range: Range{Start: Position{Line: 4, Character: 9}, End: Position{Line: 4, Character: 15}},
    Severity: SeverityError,
    Code: "E2001",  // ← Error code extracted
    Source: "gosqlx",
    Message: "unexpected token SELECT",  // ← Clean message
}
```

## Benefits

### For IDE Users

- **Better error display**: IDEs can show error codes alongside messages
- **Quick actions**: IDEs can provide code-specific quick fixes
- **Error filtering**: Filter diagnostics by error code
- **Documentation links**: Jump to error code documentation

### For Tool Developers

- **Programmatic handling**: Handle specific error types in automation
- **Error categorization**: Group errors by category (tokenizer vs parser)
- **Metrics**: Track error code frequency and patterns
- **Testing**: Assert on specific error codes in tests

## Testing

The feature is tested with comprehensive test coverage:

- `TestCreateDiagnosticFromError_WithStructuredError`: Validates error code extraction
- `TestCreateDiagnosticFromError_WithPlainError`: Tests plain error fallback
- `TestCreateDiagnosticFromError_EdgeCases`: Covers edge cases (negative positions, line 0)

All tests pass, confirming correct implementation.

## Future Enhancements

Potential future improvements:

1. **Error code quick fixes**: Provide code-specific suggestions
2. **Error documentation**: Link to online error code documentation
3. **Error severity mapping**: Map error codes to appropriate severities
4. **Error recovery hints**: Include recovery suggestions based on error code
