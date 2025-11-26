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

// Tokenizer DoS Protection Errors (E1006-E1008)

// InputTooLargeError creates an error for input exceeding size limits
func InputTooLargeError(size, maxSize int64, location models.Location) *Error {
	return NewError(
		ErrCodeInputTooLarge,
		fmt.Sprintf("input size %d bytes exceeds limit of %d bytes", size, maxSize),
		location,
	).WithHint(fmt.Sprintf("Reduce input size to under %d bytes or adjust MaxInputSize configuration", maxSize))
}

// TokenLimitReachedError creates an error for token count exceeding limit
func TokenLimitReachedError(count, maxTokens int, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeTokenLimitReached,
		fmt.Sprintf("token count %d exceeds limit of %d tokens", count, maxTokens),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Simplify query or adjust MaxTokens limit (currently %d)", maxTokens))
}

// TokenizerPanicError creates an error for recovered tokenizer panic
func TokenizerPanicError(panicValue interface{}, location models.Location) *Error {
	return NewError(
		ErrCodeTokenizerPanic,
		fmt.Sprintf("tokenizer panic recovered: %v", panicValue),
		location,
	).WithHint("This indicates a serious tokenizer bug. Please report this issue with the SQL input.")
}

// Parser Feature Errors (E2007-E2012)

// RecursionDepthLimitError creates an error for recursion depth exceeded
func RecursionDepthLimitError(depth, maxDepth int, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeRecursionDepthLimit,
		fmt.Sprintf("recursion depth %d exceeds limit of %d", depth, maxDepth),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Simplify nested expressions or subqueries (current limit: %d levels)", maxDepth))
}

// UnsupportedDataTypeError creates an error for unsupported data type
func UnsupportedDataTypeError(dataType string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedDataType,
		fmt.Sprintf("data type '%s' is not yet supported", dataType),
		location,
	).WithContext(sql, len(dataType)).WithHint("Use a supported data type (e.g., INTEGER, VARCHAR, TEXT, TIMESTAMP)")
}

// UnsupportedConstraintError creates an error for unsupported constraint
func UnsupportedConstraintError(constraint string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedConstraint,
		fmt.Sprintf("constraint '%s' is not yet supported", constraint),
		location,
	).WithContext(sql, len(constraint)).WithHint("Supported constraints: PRIMARY KEY, FOREIGN KEY, UNIQUE, NOT NULL, CHECK")
}

// UnsupportedJoinError creates an error for unsupported JOIN type
func UnsupportedJoinError(joinType string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedJoin,
		fmt.Sprintf("JOIN type '%s' is not yet supported", joinType),
		location,
	).WithContext(sql, len(joinType)).WithHint("Supported JOINs: INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, NATURAL JOIN")
}

// InvalidCTEError creates an error for invalid CTE (WITH clause) syntax
func InvalidCTEError(description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidCTE,
		fmt.Sprintf("invalid CTE syntax: %s", description),
		location,
	).WithContext(sql, 1).WithHint("Check WITH clause syntax: WITH cte_name AS (SELECT ...) SELECT * FROM cte_name")
}

// InvalidSetOperationError creates an error for invalid set operation
func InvalidSetOperationError(operation, description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidSetOperation,
		fmt.Sprintf("invalid %s operation: %s", operation, description),
		location,
	).WithContext(sql, len(operation)).WithHint("Ensure both queries have the same number and compatible types of columns")
}

// Semantic Errors (E3001-E3004)

// UndefinedTableError creates an error for referencing an undefined table
func UndefinedTableError(tableName string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUndefinedTable,
		fmt.Sprintf("table '%s' does not exist", tableName),
		location,
	).WithContext(sql, len(tableName)).WithHint(fmt.Sprintf("Check the table name '%s' for typos or ensure it exists in the schema", tableName))
}

// UndefinedColumnError creates an error for referencing an undefined column
func UndefinedColumnError(columnName, tableName string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("column '%s' does not exist", columnName)
	hint := fmt.Sprintf("Check the column name '%s' for typos or ensure it exists in the table", columnName)
	if tableName != "" {
		message = fmt.Sprintf("column '%s' does not exist in table '%s'", columnName, tableName)
		hint = fmt.Sprintf("Check that column '%s' exists in table '%s'", columnName, tableName)
	}
	return NewError(
		ErrCodeUndefinedColumn,
		message,
		location,
	).WithContext(sql, len(columnName)).WithHint(hint)
}

// TypeMismatchError creates an error for type mismatch in expressions
func TypeMismatchError(leftType, rightType, context string, location models.Location, sql string) *Error {
	message := fmt.Sprintf("type mismatch: cannot compare %s with %s", leftType, rightType)
	if context != "" {
		message = fmt.Sprintf("type mismatch in %s: cannot compare %s with %s", context, leftType, rightType)
	}
	return NewError(
		ErrCodeTypeMismatch,
		message,
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Ensure compatible types or use explicit CAST to convert %s to %s", leftType, rightType))
}

// AmbiguousColumnError creates an error for ambiguous column reference
func AmbiguousColumnError(columnName string, tables []string, location models.Location, sql string) *Error {
	tableList := "multiple tables"
	if len(tables) > 0 {
		tableList = fmt.Sprintf("tables: %s", joinStrings(tables, ", "))
	}
	return NewError(
		ErrCodeAmbiguousColumn,
		fmt.Sprintf("column '%s' is ambiguous (appears in %s)", columnName, tableList),
		location,
	).WithContext(sql, len(columnName)).WithHint(fmt.Sprintf("Qualify the column with a table name or alias, e.g., 'table_name.%s'", columnName))
}

// joinStrings is a helper to join strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
