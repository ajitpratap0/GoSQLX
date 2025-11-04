package errors

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Builder functions for common error scenarios

// UnexpectedCharError creates an error for unexpected character in tokenization
func UnexpectedCharError(char rune, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnexpectedChar,
		fmt.Sprintf("unexpected character '%c'", char),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Remove or escape the character '%c'", char))
}

// UnterminatedStringError creates an error for unterminated string literal
func UnterminatedStringError(location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnterminatedString,
		"unterminated string literal",
		location,
	).WithContext(sql, 1).WithHint(GenerateHint(ErrCodeUnterminatedString, "", ""))
}

// InvalidNumberError creates an error for invalid numeric literal
func InvalidNumberError(value string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidNumber,
		fmt.Sprintf("invalid numeric literal: '%s'", value),
		location,
	).WithContext(sql, len(value)).WithHint("Check the numeric format (e.g., 123, 123.45, 1.23e10)")
}

// UnexpectedTokenError creates an error for unexpected token in parsing
func UnexpectedTokenError(tokenType, tokenValue string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("unexpected token: %s", tokenType)
	if tokenValue != "" {
		message = fmt.Sprintf("unexpected token: %s ('%s')", tokenType, tokenValue)
	}

	err := NewError(ErrCodeUnexpectedToken, message, location).WithContext(sql, len(tokenValue))

	// Generate intelligent hint
	hint := GenerateHint(ErrCodeUnexpectedToken, "", tokenValue)
	if hint != "" {
		err = err.WithHint(hint)
	}

	return err
}

// ExpectedTokenError creates an error for missing expected token
func ExpectedTokenError(expected, got string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("expected %s, got %s", expected, got)

	err := NewError(ErrCodeExpectedToken, message, location).WithContext(sql, len(got))

	// Generate intelligent hint with typo detection
	hint := GenerateHint(ErrCodeExpectedToken, expected, got)
	if hint != "" {
		err = err.WithHint(hint)
	}

	return err
}

// MissingClauseError creates an error for missing required SQL clause
func MissingClauseError(clause string, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeMissingClause,
		fmt.Sprintf("missing required %s clause", clause),
		location,
	).WithContext(sql, 1)

	hint := GenerateHint(ErrCodeMissingClause, clause, "")
	if hint != "" {
		err = err.WithHint(hint)
	} else if commonHint := GetCommonHint("missing_" + clause); commonHint != "" {
		err = err.WithHint(commonHint)
	}

	return err
}

// InvalidSyntaxError creates a general syntax error
func InvalidSyntaxError(description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidSyntax,
		fmt.Sprintf("invalid syntax: %s", description),
		location,
	).WithContext(sql, 1).WithHint(GenerateHint(ErrCodeInvalidSyntax, "", ""))
}

// UnsupportedFeatureError creates an error for unsupported SQL features
func UnsupportedFeatureError(feature string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedFeature,
		fmt.Sprintf("unsupported feature: %s", feature),
		location,
	).WithContext(sql, len(feature)).WithHint(GenerateHint(ErrCodeUnsupportedFeature, "", ""))
}

// IncompleteStatementError creates an error for incomplete SQL statement
func IncompleteStatementError(location models.Location, sql string) *Error {
	return NewError(
		ErrCodeIncompleteStatement,
		"incomplete SQL statement",
		location,
	).WithContext(sql, 1).WithHint("Complete the SQL statement or check for missing clauses")
}

// WrapError wraps an existing error with structured error information
func WrapError(code ErrorCode, message string, location models.Location, sql string, cause error) *Error {
	return NewError(code, message, location).WithContext(sql, 1).WithCause(cause)
}
