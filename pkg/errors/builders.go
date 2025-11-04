package errors

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Builder functions for common error scenarios

// UnexpectedCharError creates an error for unexpected character in tokenization
func UnexpectedCharError(char rune, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeUnexpectedChar,
		fmt.Sprintf("unexpected character '%c'", char),
		location,
	)
	err.WithContext(sql, 1)
	err.WithHint(fmt.Sprintf("Remove or escape the character '%c'", char))
	return err
}

// UnterminatedStringError creates an error for unterminated string literal
func UnterminatedStringError(location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeUnterminatedString,
		"unterminated string literal",
		location,
	)
	err.WithContext(sql, 1)
	err.WithHint(GenerateHint(ErrCodeUnterminatedString, "", ""))
	return err
}

// InvalidNumberError creates an error for invalid numeric literal
func InvalidNumberError(value string, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeInvalidNumber,
		fmt.Sprintf("invalid numeric literal: '%s'", value),
		location,
	)
	err.WithContext(sql, len(value))
	err.WithHint("Check the numeric format (e.g., 123, 123.45, 1.23e10)")
	return err
}

// UnexpectedTokenError creates an error for unexpected token in parsing
func UnexpectedTokenError(tokenType, tokenValue string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("unexpected token: %s", tokenType)
	if tokenValue != "" {
		message = fmt.Sprintf("unexpected token: %s ('%s')", tokenType, tokenValue)
	}

	err := NewError(ErrCodeUnexpectedToken, message, location)
	err.WithContext(sql, len(tokenValue))

	// Generate intelligent hint
	hint := GenerateHint(ErrCodeUnexpectedToken, "", tokenValue)
	if hint != "" {
		err.WithHint(hint)
	}

	return err
}

// ExpectedTokenError creates an error for missing expected token
func ExpectedTokenError(expected, got string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("expected %s, got %s", expected, got)

	err := NewError(ErrCodeExpectedToken, message, location)
	err.WithContext(sql, len(got))

	// Generate intelligent hint with typo detection
	hint := GenerateHint(ErrCodeExpectedToken, expected, got)
	if hint != "" {
		err.WithHint(hint)
	}

	return err
}

// MissingClauseError creates an error for missing required SQL clause
func MissingClauseError(clause string, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeMissingClause,
		fmt.Sprintf("missing required %s clause", clause),
		location,
	)
	err.WithContext(sql, 1)

	hint := GenerateHint(ErrCodeMissingClause, clause, "")
	if hint != "" {
		err.WithHint(hint)
	} else if commonHint := GetCommonHint("missing_" + clause); commonHint != "" {
		err.WithHint(commonHint)
	}

	return err
}

// InvalidSyntaxError creates a general syntax error
func InvalidSyntaxError(description string, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeInvalidSyntax,
		fmt.Sprintf("invalid syntax: %s", description),
		location,
	)
	err.WithContext(sql, 1)
	err.WithHint(GenerateHint(ErrCodeInvalidSyntax, "", ""))
	return err
}

// UnsupportedFeatureError creates an error for unsupported SQL features
func UnsupportedFeatureError(feature string, location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeUnsupportedFeature,
		fmt.Sprintf("unsupported feature: %s", feature),
		location,
	)
	err.WithContext(sql, len(feature))
	err.WithHint(GenerateHint(ErrCodeUnsupportedFeature, "", ""))
	return err
}

// IncompleteStatementError creates an error for incomplete SQL statement
func IncompleteStatementError(location models.Location, sql string) *Error {
	err := NewError(
		ErrCodeIncompleteStatement,
		"incomplete SQL statement",
		location,
	)
	err.WithContext(sql, 1)
	err.WithHint("Complete the SQL statement or check for missing clauses")
	return err
}

// WrapError wraps an existing error with structured error information
func WrapError(code ErrorCode, message string, location models.Location, sql string, cause error) *Error {
	err := NewError(code, message, location)
	err.WithContext(sql, 1)
	err.WithCause(cause)
	return err
}
