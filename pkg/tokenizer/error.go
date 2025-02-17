package tokenizer

import (
	"fmt"
	"GoSQLX/pkg/models"
)

// Error represents a tokenization error with location information
type Error struct {
	Message  string
	Location models.Location
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s at line %d, column %d", e.Message, e.Location.Line, e.Location.Column)
}

// NewError creates a new tokenization error
func NewError(message string, location models.Location) *Error {
	return &Error{
		Message:  message,
		Location: location,
	}
}

// ErrorUnexpectedChar creates an error for an unexpected character
func ErrorUnexpectedChar(ch byte, location models.Location) *Error {
	return NewError(fmt.Sprintf("unexpected character: %c", ch), location)
}

// ErrorUnterminatedString creates an error for an unterminated string
func ErrorUnterminatedString(location models.Location) *Error {
	return NewError("unterminated string literal", location)
}

// ErrorInvalidNumber creates an error for an invalid number format
func ErrorInvalidNumber(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid number format: %s", value), location)
}

// ErrorInvalidIdentifier creates an error for an invalid identifier
func ErrorInvalidIdentifier(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid identifier: %s", value), location)
}

// ErrorInvalidOperator creates an error for an invalid operator
func ErrorInvalidOperator(value string, location models.Location) *Error {
	return NewError(fmt.Sprintf("invalid operator: %s", value), location)
}
