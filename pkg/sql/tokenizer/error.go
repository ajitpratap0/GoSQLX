package tokenizer

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Error represents a tokenization error with precise location information.
//
// This type provides structured error reporting with line and column positions,
// making it easy for users to identify and fix SQL syntax issues.
//
// Note: Modern code should use the errors from pkg/errors package instead,
// which provide more comprehensive error categorization and context.
// This type is maintained for backward compatibility.
//
// Example:
//
//	if err != nil {
//	    if tokErr, ok := err.(*tokenizer.Error); ok {
//	        fmt.Printf("Tokenization failed at line %d, column %d: %s\n",
//	            tokErr.Location.Line, tokErr.Location.Column, tokErr.Message)
//	    }
//	}
type Error struct {
	Message  string          // Human-readable error message
	Location models.Location // Position where the error occurred (1-based)
}

// Error implements the error interface, returning a formatted error message
// with location information.
//
// Format: "<message> at line <line>, column <column>"
//
// Example output: "unterminated string literal at line 5, column 23"
func (e *Error) Error() string {
	return fmt.Sprintf("%s at line %d, column %d", e.Message, e.Location.Line, e.Location.Column)
}

// NewError creates a new tokenization error with a message and location.
//
// Parameters:
//   - message: Human-readable description of the error
//   - location: Position in the input where the error occurred
//
// Returns a pointer to an Error with the specified message and location.
func NewError(message string, location models.Location) *Error {
	return &Error{
		Message:  message,
		Location: location,
	}
}

// ErrorUnexpectedChar creates an error for an unexpected character.
//
// This is used when the tokenizer encounters a character that cannot
// start any valid token in the current context.
//
// Parameters:
//   - ch: The unexpected character (byte)
//   - location: Position where the character was found
//
// Returns an Error describing the unexpected character.
//
// Example: "unexpected character: @ at line 2, column 5"
func ErrorUnexpectedChar(ch byte, location models.Location) *Error {
	return NewError(fmt.Sprintf("unexpected character: %c", ch), location)
}

// ErrorUnterminatedString creates an error for an unterminated string literal.
//
// This occurs when a string literal (single or double quoted) is not properly
// closed before the end of the line or input.
//
// Parameters:
//   - location: Position where the string started
//
// Returns an Error indicating the string was not terminated.
//
// Example: "unterminated string literal at line 3, column 15"
func ErrorUnterminatedString(location models.Location) *Error {
	return NewError("unterminated string literal", location)
}

// ErrorInvalidNumber creates an error for an invalid number format.
//
// This is used when a number token has invalid syntax, such as:
//   - Decimal point without digits: "123."
//   - Exponent without digits: "123e"
//   - Multiple decimal points: "12.34.56"
//
// Parameters:
//   - value: The invalid number string
//   - location: Position where the number started
//
// Returns an Error describing the invalid number format.
//
// Example: "invalid number format: 123.e at line 1, column 10"
func ErrorInvalidNumber(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid number format: %s", value), location)
}

// ErrorInvalidIdentifier creates an error for an invalid identifier.
//
// This is used when an identifier has invalid syntax, such as:
//   - Starting with a digit (when not quoted)
//   - Containing invalid characters
//   - Unterminated quoted identifier
//
// Parameters:
//   - value: The invalid identifier string
//   - location: Position where the identifier started
//
// Returns an Error describing the invalid identifier.
//
// Example: "invalid identifier: 123abc at line 2, column 8"
func ErrorInvalidIdentifier(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid identifier: %s", value), location)
}

// ErrorInvalidOperator creates an error for an invalid operator.
//
// This is used when an operator token has invalid syntax, such as:
//   - Incomplete multi-character operators
//   - Invalid operator combinations
//
// Parameters:
//   - value: The invalid operator string
//   - location: Position where the operator started
//
// Returns an Error describing the invalid operator.
//
// Example: "invalid operator: <=> at line 1, column 20"
func ErrorInvalidOperator(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid operator: %s", value), location)
}
