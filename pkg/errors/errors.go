// Package errors provides a structured error system for GoSQLX with error codes,
// context extraction, and intelligent hints for debugging SQL parsing issues.
//
// This package is designed to provide clear, actionable error messages for SQL parsing failures.
package errors

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ErrorCode represents a unique error code for programmatic handling
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

// Error represents a structured error with rich context and hints
type Error struct {
	Code     ErrorCode       // Unique error code (e.g., "E2001")
	Message  string          // Human-readable error message
	Location models.Location // Line and column where error occurred
	Context  *ErrorContext   // SQL context around the error
	Hint     string          // Suggestion to fix the error
	HelpURL  string          // Documentation link for this error
	Cause    error           // Underlying error if any
}

// ErrorContext contains the SQL source and position information for display
type ErrorContext struct {
	SQL          string // Original SQL query
	StartLine    int    // Starting line number (1-indexed)
	EndLine      int    // Ending line number (1-indexed)
	HighlightCol int    // Column to highlight (1-indexed)
	HighlightLen int    // Length of highlight (number of characters)
}

// Error implements the error interface
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

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Cause
}

// NewError creates a new structured error
func NewError(code ErrorCode, message string, location models.Location) *Error {
	return &Error{
		Code:     code,
		Message:  message,
		Location: location,
		HelpURL:  fmt.Sprintf("https://docs.gosqlx.dev/errors/%s", code),
	}
}

// WithContext adds SQL context to the error
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

// WithHint adds a suggestion hint to the error
func (e *Error) WithHint(hint string) *Error {
	e.Hint = hint
	return e
}

// WithCause adds an underlying cause error
func (e *Error) WithCause(cause error) *Error {
	e.Cause = cause
	return e
}

// IsCode checks if an error has a specific error code
func IsCode(err error, code ErrorCode) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == code
	}
	return false
}

// GetCode returns the error code from an error, or empty string if not a structured error
func GetCode(err error) ErrorCode {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
