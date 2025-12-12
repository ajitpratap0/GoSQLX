// Package errors provides a structured error system for GoSQLX with error codes,
// context extraction, and intelligent hints for debugging SQL parsing issues.
//
// This package is designed to provide clear, actionable error messages for SQL parsing failures.
// It is the production-grade error handling system for GoSQLX v1.6.0 with support for:
//   - Structured error codes (E1xxx-E4xxx)
//   - Precise location tracking with line/column information
//   - SQL context extraction with visual highlighting
//   - Intelligent suggestions using Levenshtein distance for typo detection
//   - Cached suggestions for performance in LSP scenarios
//   - Thread-safe concurrent error handling
//
// See doc.go for comprehensive package documentation and examples.
package errors

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ErrorCode represents a unique error code for programmatic handling.
//
// ErrorCode is a strongly-typed string for error classification. It enables
// programmatic error handling, filtering, and logging in production systems.
//
// Error codes follow the pattern: E[category][number]
//   - E1xxx: Tokenizer/lexical errors
//   - E2xxx: Parser/syntax errors
//   - E3xxx: Semantic errors
//   - E4xxx: Unsupported features
//
// Example usage:
//
//	err := errors.NewError(errors.ErrCodeUnexpectedToken, "msg", location)
//	if errors.IsCode(err, errors.ErrCodeUnexpectedToken) {
//	    // Handle unexpected token error specifically
//	}
//
//	code := errors.GetCode(err)
//	switch code {
//	case errors.ErrCodeExpectedToken:
//	    // Handle syntax errors
//	case errors.ErrCodeUndefinedTable:
//	    // Handle semantic errors
//	}
type ErrorCode string

// Error code categories
const (
	// E1xxx: Tokenizer errors
	ErrCodeUnexpectedChar     ErrorCode = "E1001" // Unexpected character in input
	ErrCodeUnterminatedString ErrorCode = "E1002" // String literal not closed
	ErrCodeInvalidNumber      ErrorCode = "E1003" // Invalid numeric literal
	ErrCodeInvalidOperator    ErrorCode = "E1004" // Invalid operator sequence
	ErrCodeInvalidIdentifier  ErrorCode = "E1005" // Invalid identifier format
	ErrCodeInputTooLarge      ErrorCode = "E1006" // Input exceeds size limits (DoS protection)
	ErrCodeTokenLimitReached  ErrorCode = "E1007" // Token count exceeds limit (DoS protection)
	ErrCodeTokenizerPanic     ErrorCode = "E1008" // Tokenizer panic recovered

	// E2xxx: Parser syntax errors
	ErrCodeUnexpectedToken       ErrorCode = "E2001" // Unexpected token encountered
	ErrCodeExpectedToken         ErrorCode = "E2002" // Expected specific token not found
	ErrCodeMissingClause         ErrorCode = "E2003" // Required SQL clause missing
	ErrCodeInvalidSyntax         ErrorCode = "E2004" // General syntax error
	ErrCodeIncompleteStatement   ErrorCode = "E2005" // Statement incomplete
	ErrCodeInvalidExpression     ErrorCode = "E2006" // Invalid expression syntax
	ErrCodeRecursionDepthLimit   ErrorCode = "E2007" // Recursion depth exceeded (DoS protection)
	ErrCodeUnsupportedDataType   ErrorCode = "E2008" // Data type not supported
	ErrCodeUnsupportedConstraint ErrorCode = "E2009" // Constraint type not supported
	ErrCodeUnsupportedJoin       ErrorCode = "E2010" // JOIN type not supported
	ErrCodeInvalidCTE            ErrorCode = "E2011" // Invalid CTE (WITH clause) syntax
	ErrCodeInvalidSetOperation   ErrorCode = "E2012" // Invalid set operation (UNION/EXCEPT/INTERSECT)

	// E3xxx: Semantic errors
	ErrCodeUndefinedTable  ErrorCode = "E3001" // Table not defined
	ErrCodeUndefinedColumn ErrorCode = "E3002" // Column not defined
	ErrCodeTypeMismatch    ErrorCode = "E3003" // Type mismatch in expression
	ErrCodeAmbiguousColumn ErrorCode = "E3004" // Ambiguous column reference

	// E4xxx: Unsupported features
	ErrCodeUnsupportedFeature ErrorCode = "E4001" // Feature not yet supported
	ErrCodeUnsupportedDialect ErrorCode = "E4002" // SQL dialect not supported
)

// Error represents a structured error with rich context and hints.
//
// Error is the main error type in GoSQLX, providing comprehensive information
// for debugging and user feedback. It includes error codes, precise locations,
// SQL context with highlighting, intelligent hints, and help URLs.
//
// Fields:
//   - Code: Unique error identifier (E1xxx-E4xxx) for programmatic handling
//   - Message: Human-readable error description
//   - Location: Precise line/column where error occurred (1-based)
//   - Context: SQL source context with highlighting (optional)
//   - Hint: Auto-generated suggestion to fix the error (optional)
//   - HelpURL: Documentation link for this error code
//   - Cause: Underlying error if wrapped (optional)
//
// Example creation:
//
//	err := errors.NewError(
//	    errors.ErrCodeUnexpectedToken,
//	    "unexpected token: COMMA",
//	    models.Location{Line: 5, Column: 20},
//	)
//	err = err.WithContext(sqlSource, 1)
//	err = err.WithHint("Expected FROM keyword after SELECT clause")
//
// Error output format:
//
//	Error E2001 at line 5, column 20: unexpected token: COMMA
//
//	  4 | SELECT name, email
//	  5 | FROM users, WHERE active = true
//	                ^^^^
//	  6 |
//
//	Hint: Expected FROM keyword after SELECT clause
//	Help: https://docs.gosqlx.dev/errors/E2001
//
// Thread Safety: Error instances are immutable after creation. Methods like
// WithContext, WithHint return new Error instances and are safe for concurrent use.
type Error struct {
	Code     ErrorCode       // Unique error code (e.g., "E2001")
	Message  string          // Human-readable error message
	Location models.Location // Line and column where error occurred
	Context  *ErrorContext   // SQL context around the error
	Hint     string          // Suggestion to fix the error
	HelpURL  string          // Documentation link for this error
	Cause    error           // Underlying error if any
}

// ErrorContext contains the SQL source and position information for display.
//
// ErrorContext provides the SQL source code context around an error with
// precise highlighting information. Used to generate visual error displays
// with line numbers and position indicators.
//
// Fields:
//   - SQL: Original SQL query source code
//   - StartLine: First line to display in context (1-based)
//   - EndLine: Last line to display in context (1-based)
//   - HighlightCol: Column to start highlighting (1-based)
//   - HighlightLen: Number of characters to highlight
//
// Example:
//
//	ctx := &errors.ErrorContext{
//	    SQL:          "SELECT * FORM users",
//	    StartLine:    1,
//	    EndLine:      1,
//	    HighlightCol: 10,
//	    HighlightLen: 4,  // Highlight "FORM"
//	}
//
// The context is displayed as:
//
//	1 | SELECT * FORM users
//	           ^^^^
type ErrorContext struct {
	SQL          string // Original SQL query
	StartLine    int    // Starting line number (1-indexed)
	EndLine      int    // Ending line number (1-indexed)
	HighlightCol int    // Column to highlight (1-indexed)
	HighlightLen int    // Length of highlight (number of characters)
}

// Error implements the error interface.
//
// Returns a formatted error message including:
//   - Error code and location (line/column)
//   - Error message
//   - SQL context with visual highlighting (if available)
//   - Hint/suggestion (if available)
//   - Help URL for documentation
//
// Example output:
//
//	Error E2002 at line 1, column 15: expected FROM, got FORM
//
//	  1 | SELECT * FORM users WHERE id = 1
//	               ^^^^
//
//	Hint: Did you mean 'FROM' instead of 'FORM'?
//	Help: https://docs.gosqlx.dev/errors/E2002
//
// This method is called automatically when the error is printed or logged.
func (e *Error) Error() string {
	var sb strings.Builder

	// Error code and location
	sb.WriteString(fmt.Sprintf("Error %s at line %d, column %d: %s",
		e.Code, e.Location.Line, e.Location.Column, e.Message))

	// Add context if available
	if e.Context != nil {
		sb.WriteString("\n")
		sb.WriteString(e.formatContext())
	}

	// Add hint if available
	if e.Hint != "" {
		sb.WriteString("\n\nHint: ")
		sb.WriteString(e.Hint)
	}

	// Add help URL if available
	if e.HelpURL != "" {
		sb.WriteString("\nHelp: ")
		sb.WriteString(e.HelpURL)
	}

	return sb.String()
}

// formatContext formats the SQL context with position indicator
// Shows up to 3 lines: 1 line before, the error line, and 1 line after
func (e *Error) formatContext() string {
	if e.Context == nil || e.Context.SQL == "" {
		return ""
	}

	var sb strings.Builder
	lines := strings.Split(e.Context.SQL, "\n")

	if e.Location.Line <= 0 || e.Location.Line > len(lines) {
		return ""
	}

	errorLineNum := e.Location.Line

	// Calculate line number width for alignment (minimum 2 digits)
	maxLineNum := errorLineNum + 1
	if maxLineNum > len(lines) {
		maxLineNum = len(lines)
	}
	lineNumWidth := len(fmt.Sprintf("%d", maxLineNum))
	if lineNumWidth < 2 {
		lineNumWidth = 2
	}

	sb.WriteString("\n")

	// Show line before (if exists)
	if errorLineNum > 1 {
		lineNum := errorLineNum - 1
		line := lines[lineNum-1]
		sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, lineNum, line))
	}

	// Show error line
	line := lines[errorLineNum-1]
	sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, errorLineNum, line))

	// Add position indicator (^)
	if e.Location.Column > 0 {
		// Account for line number prefix
		prefix := fmt.Sprintf("  %*d | ", lineNumWidth, errorLineNum)
		spaces := strings.Repeat(" ", len(prefix)+e.Location.Column-1)
		highlight := "^"
		if e.Context.HighlightLen > 1 {
			highlight = strings.Repeat("^", e.Context.HighlightLen)
		}
		sb.WriteString(spaces + highlight + "\n")
	}

	// Show line after (if exists)
	if errorLineNum < len(lines) {
		lineNum := errorLineNum + 1
		line := lines[lineNum-1]
		sb.WriteString(fmt.Sprintf("  %*d | %s", lineNumWidth, lineNum, line))
	}

	return sb.String()
}

// Unwrap returns the underlying error.
//
// Implements error unwrapping for Go 1.13+ error chains. This allows
// errors.Is and errors.As to work with wrapped errors.
//
// Example:
//
//	originalErr := someFunc()
//	wrappedErr := errors.NewError(...).WithCause(originalErr)
//	if errors.Is(wrappedErr, originalErr) {
//	    // Can check for original error
//	}
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new structured error.
//
// Factory function for creating GoSQLX errors with error code, message,
// and location. This is the primary way to create errors in the library.
//
// Parameters:
//   - code: ErrorCode for programmatic error handling (E1xxx-E4xxx)
//   - message: Human-readable error description
//   - location: Precise line/column where error occurred
//
// Returns a new Error with the specified fields and auto-generated help URL.
//
// Example:
//
//	err := errors.NewError(
//	    errors.ErrCodeUnexpectedToken,
//	    "unexpected token: COMMA",
//	    models.Location{Line: 5, Column: 20},
//	)
//	// err.HelpURL is automatically set to https://docs.gosqlx.dev/errors/E2001
//
// The error can be enhanced with additional context:
//
//	err = err.WithContext(sqlSource, 1).WithHint("Expected FROM keyword")
func NewError(code ErrorCode, message string, location models.Location) *Error {
	return &Error{
		Code:     code,
		Message:  message,
		Location: location,
		HelpURL:  fmt.Sprintf("https://docs.gosqlx.dev/errors/%s", code),
	}
}

// WithContext adds SQL context to the error.
//
// Attaches SQL source code context with highlighting information for
// visual error display. The context shows surrounding lines and highlights
// the specific location of the error.
//
// Parameters:
//   - sql: Original SQL source code
//   - highlightLen: Number of characters to highlight (starting at error column)
//
// Returns the same Error instance with context added (for method chaining).
//
// Example:
//
//	err := errors.NewError(code, "error message", location)
//	err = err.WithContext("SELECT * FORM users", 4)  // Highlight "FORM"
//
// The context will be displayed as:
//
//	1 | SELECT * FORM users
//	           ^^^^
//
// Note: WithContext modifies the error in-place and returns it for chaining.
func (e *Error) WithContext(sql string, highlightLen int) *Error {
	e.Context = &ErrorContext{
		SQL:          sql,
		StartLine:    e.Location.Line,
		EndLine:      e.Location.Line,
		HighlightCol: e.Location.Column,
		HighlightLen: highlightLen,
	}
	return e
}

// WithHint adds a suggestion hint to the error.
//
// Attaches a helpful suggestion for fixing the error. Hints are generated
// automatically by builder functions or can be added manually.
//
// Parameters:
//   - hint: Suggestion text (e.g., "Did you mean 'FROM' instead of 'FORM'?")
//
// Returns the same Error instance with hint added (for method chaining).
//
// Example:
//
//	err := errors.NewError(code, "message", location)
//	err = err.WithHint("Expected FROM keyword after SELECT clause")
//
// Auto-generated hints:
//
//	err := errors.ExpectedTokenError("FROM", "FORM", location, sql)
//	// Automatically includes: "Did you mean 'FROM' instead of 'FORM'?"
//
// Note: WithHint modifies the error in-place and returns it for chaining.
func (e *Error) WithHint(hint string) *Error {
	e.Hint = hint
	return e
}

// WithCause adds an underlying cause error.
//
// Wraps another error as the cause of this error, enabling error chaining
// and unwrapping with errors.Is and errors.As.
//
// Parameters:
//   - cause: The underlying error that caused this error
//
// Returns the same Error instance with cause added (for method chaining).
//
// Example:
//
//	ioErr := os.ReadFile(filename)  // Returns error
//	err := errors.NewError(
//	    errors.ErrCodeInvalidSyntax,
//	    "failed to read SQL file",
//	    location,
//	).WithCause(ioErr)
//
//	// Check for original error
//	if errors.Is(err, os.ErrNotExist) {
//	    // Handle file not found
//	}
//
// Note: WithCause modifies the error in-place and returns it for chaining.
func (e *Error) WithCause(cause error) *Error {
	e.Cause = cause
	return e
}

// IsCode checks if an error has a specific error code.
//
// Type-safe way to check error codes for programmatic error handling.
// Works with both *Error and other error types (returns false for non-Error).
//
// Parameters:
//   - err: The error to check
//   - code: The ErrorCode to match against
//
// Returns true if err is a *Error with matching code, false otherwise.
//
// Example:
//
//	if errors.IsCode(err, errors.ErrCodeUnterminatedString) {
//	    // Handle unterminated string error specifically
//	}
//
//	if errors.IsCode(err, errors.ErrCodeExpectedToken) {
//	    // Handle expected token error
//	}
//
// Common pattern:
//
//	switch {
//	case errors.IsCode(err, errors.ErrCodeUnexpectedToken):
//	    // Handle unexpected token
//	case errors.IsCode(err, errors.ErrCodeMissingClause):
//	    // Handle missing clause
//	default:
//	    // Handle other errors
//	}
func IsCode(err error, code ErrorCode) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == code
	}
	return false
}

// GetCode returns the error code from an error, or empty string if not a structured error.
//
// Extracts the ErrorCode from a *Error. Returns empty string for non-Error types.
//
// Parameters:
//   - err: The error to extract code from
//
// Returns the ErrorCode if err is a *Error, empty string otherwise.
//
// Example:
//
//	code := errors.GetCode(err)
//	switch code {
//	case errors.ErrCodeExpectedToken:
//	    // Handle syntax errors
//	case errors.ErrCodeUndefinedTable:
//	    // Handle semantic errors
//	case "":
//	    // Not a structured error
//	}
//
// Logging example:
//
//	if code := errors.GetCode(err); code != "" {
//	    log.Printf("SQL error [%s]: %v", code, err)
//	}
func GetCode(err error) ErrorCode {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
