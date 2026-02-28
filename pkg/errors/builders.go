// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package errors

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Builder functions for common error scenarios

// UnexpectedCharError creates an E1001 error for an unexpected character encountered
// during tokenization. The hint instructs the caller to remove or escape the character.
//
// Parameters:
//   - char: The invalid character found in the SQL input
//   - location: Line/column where the character appears
//   - sql: Full SQL source used to generate visual context
func UnexpectedCharError(char rune, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnexpectedChar,
		fmt.Sprintf("unexpected character '%c'", char),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Remove or escape the character '%c'", char))
}

// UnterminatedStringError creates an E1002 error for an unterminated string literal.
// A string literal is considered unterminated when the tokenizer reaches end-of-input
// before finding the matching closing quote character.
//
// Parameters:
//   - location: Line/column where the opening quote was found
//   - sql: Full SQL source used to generate visual context
func UnterminatedStringError(location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnterminatedString,
		"unterminated string literal",
		location,
	).WithContext(sql, 1).WithHint(GenerateHint(ErrCodeUnterminatedString, "", ""))
}

// UnterminatedBlockCommentError creates an E1009 error for a block comment that
// was opened with /* but never closed with */. The hint guides the caller to add
// the missing closing delimiter.
//
// Parameters:
//   - location: Line/column where the /* opening was found
//   - sql: Full SQL source used to generate visual context
func UnterminatedBlockCommentError(location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnterminatedBlockComment,
		"unterminated block comment (missing */)",
		location,
	).WithContext(sql, 2).WithHint("Close the comment with */ or check for unmatched /*")
}

// InvalidNumberError creates an E1003 error for a malformed numeric literal, such as
// a number with multiple decimal points (1.2.3) or an invalid exponent format.
//
// Parameters:
//   - value: The raw string that could not be parsed as a number
//   - location: Line/column where the literal starts
//   - sql: Full SQL source used to generate visual context
func InvalidNumberError(value string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidNumber,
		fmt.Sprintf("invalid numeric literal: '%s'", value),
		location,
	).WithContext(sql, len(value)).WithHint("Check the numeric format (e.g., 123, 123.45, 1.23e10)")
}

// UnexpectedTokenError creates an E2001 error for a token that does not fit the
// expected grammar at the current parse position. An intelligent "Did you mean?"
// hint is auto-generated using Levenshtein distance when the token resembles a
// known SQL keyword.
//
// Parameters:
//   - tokenType: The type of the unexpected token (e.g., "IDENT", "COMMA")
//   - tokenValue: The raw text of the token (empty string if not applicable)
//   - location: Line/column where the token was found
//   - sql: Full SQL source used to generate visual context
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

// ExpectedTokenError creates an E2002 error when a required token is absent or a
// different token appears in its place. The builder applies Levenshtein-based typo
// detection and auto-generates a "Did you mean?" hint when the found token is close
// to the expected one (e.g., FORM vs FROM).
//
// Parameters:
//   - expected: The token or keyword that was required (e.g., "FROM")
//   - got: The token or keyword that was actually found (e.g., "FORM")
//   - location: Line/column where the mismatch occurred
//   - sql: Full SQL source used to generate visual context
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

// MissingClauseError creates an E2003 error when a required SQL clause is absent.
// For example, a SELECT statement without a FROM clause, or a JOIN without an ON
// condition. A pre-built hint from CommonHints is used if available.
//
// Parameters:
//   - clause: Name of the missing clause (e.g., "FROM", "ON")
//   - location: Line/column where the clause should have appeared
//   - sql: Full SQL source used to generate visual context
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

// InvalidSyntaxError creates an E2004 general syntax error for violations that do
// not match any more specific error code. Use more specific builder functions (e.g.,
// ExpectedTokenError, MissingClauseError) when possible for better diagnostics.
//
// Parameters:
//   - description: Free-form description of the syntax problem
//   - location: Line/column where the violation was detected
//   - sql: Full SQL source used to generate visual context
func InvalidSyntaxError(description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidSyntax,
		fmt.Sprintf("invalid syntax: %s", description),
		location,
	).WithContext(sql, 1).WithHint(GenerateHint(ErrCodeInvalidSyntax, "", ""))
}

// UnsupportedFeatureError creates an E4001 error when the parser encounters a valid
// SQL construct that is recognised but not yet implemented. This distinguishes
// "not supported" from a syntax error so callers can handle the two cases separately.
//
// Parameters:
//   - feature: Name or description of the unsupported feature (e.g., "LATERAL JOIN")
//   - location: Line/column where the feature was encountered
//   - sql: Full SQL source used to generate visual context
func UnsupportedFeatureError(feature string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedFeature,
		fmt.Sprintf("unsupported feature: %s", feature),
		location,
	).WithContext(sql, len(feature)).WithHint(GenerateHint(ErrCodeUnsupportedFeature, "", ""))
}

// IncompleteStatementError creates an E2005 error when the parser reaches the end
// of input before a SQL statement is complete. This typically means a clause or
// closing parenthesis is missing.
//
// Parameters:
//   - location: Line/column at end-of-input where parsing stopped
//   - sql: Full SQL source used to generate visual context
func IncompleteStatementError(location models.Location, sql string) *Error {
	return NewError(
		ErrCodeIncompleteStatement,
		"incomplete SQL statement",
		location,
	).WithContext(sql, 1).WithHint("Complete the SQL statement or check for missing clauses")
}

// WrapError creates a structured error that wraps an existing cause error.
// Use this to add error code, location, and SQL context to low-level errors
// (e.g., I/O errors, unexpected runtime panics) so they integrate with the
// GoSQLX error handling pipeline.
//
// Parameters:
//   - code: ErrorCode classifying the error category
//   - message: Human-readable description of what went wrong
//   - location: Line/column in the SQL where the problem occurred
//   - sql: Full SQL source used to generate visual context
//   - cause: Underlying error being wrapped (accessible via errors.Is / errors.As)
func WrapError(code ErrorCode, message string, location models.Location, sql string, cause error) *Error {
	return NewError(code, message, location).WithContext(sql, 1).WithCause(cause)
}

// Tokenizer DoS Protection Errors (E1006-E1008)

// InputTooLargeError creates an E1006 error when the SQL input exceeds the
// configured maximum byte size. This protects against denial-of-service attacks
// that submit extremely large SQL strings. The hint advises reducing input or
// adjusting the MaxInputSize configuration.
//
// Parameters:
//   - size: Actual input size in bytes
//   - maxSize: Configured maximum size in bytes
//   - location: Typically the beginning of input (line 1, column 1)
func InputTooLargeError(size, maxSize int64, location models.Location) *Error {
	return NewError(
		ErrCodeInputTooLarge,
		fmt.Sprintf("input size %d bytes exceeds limit of %d bytes", size, maxSize),
		location,
	).WithHint(fmt.Sprintf("Reduce input size to under %d bytes or adjust MaxInputSize configuration", maxSize))
}

// TokenLimitReachedError creates an E1007 error when the number of tokens produced
// by the tokenizer exceeds the configured maximum. This protects against pathological
// SQL that generates an excessive token stream. The hint suggests simplifying the
// query or raising the MaxTokens limit.
//
// Parameters:
//   - count: Actual number of tokens produced
//   - maxTokens: Configured token count limit
//   - location: Position in SQL where the limit was hit
//   - sql: Full SQL source used to generate visual context
func TokenLimitReachedError(count, maxTokens int, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeTokenLimitReached,
		fmt.Sprintf("token count %d exceeds limit of %d tokens", count, maxTokens),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Simplify query or adjust MaxTokens limit (currently %d)", maxTokens))
}

// TokenizerPanicError creates an E1008 error for a panic that was recovered inside
// the tokenizer. This signals a tokenizer implementation bug rather than a user
// input problem. The hint asks the user to report the issue.
//
// Parameters:
//   - panicValue: The value recovered from the panic (may be an error or string)
//   - location: Position in SQL at the time of the panic
func TokenizerPanicError(panicValue interface{}, location models.Location) *Error {
	return NewError(
		ErrCodeTokenizerPanic,
		fmt.Sprintf("tokenizer panic recovered: %v", panicValue),
		location,
	).WithHint("This indicates a serious tokenizer bug. Please report this issue with the SQL input.")
}

// Parser Feature Errors (E2007-E2012)

// RecursionDepthLimitError creates an E2007 error when the parser's recursion
// counter exceeds the configured maximum. This guards against deeply nested
// subqueries and expressions that could exhaust the call stack. The hint suggests
// simplifying the query structure.
//
// Parameters:
//   - depth: Current recursion depth when the limit was reached
//   - maxDepth: Configured maximum recursion depth
//   - location: Position in SQL where the depth limit was triggered
//   - sql: Full SQL source used to generate visual context
func RecursionDepthLimitError(depth, maxDepth int, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeRecursionDepthLimit,
		fmt.Sprintf("recursion depth %d exceeds limit of %d", depth, maxDepth),
		location,
	).WithContext(sql, 1).WithHint(fmt.Sprintf("Simplify nested expressions or subqueries (current limit: %d levels)", maxDepth))
}

// UnsupportedDataTypeError creates an E2008 error when the parser encounters a
// column data type that GoSQLX does not yet support. Supported types include
// INTEGER, VARCHAR, TEXT, and TIMESTAMP.
//
// Parameters:
//   - dataType: The unrecognised data type string (e.g., "GEOMETRY", "JSONB")
//   - location: Line/column where the type token was found
//   - sql: Full SQL source used to generate visual context
func UnsupportedDataTypeError(dataType string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedDataType,
		fmt.Sprintf("data type '%s' is not yet supported", dataType),
		location,
	).WithContext(sql, len(dataType)).WithHint("Use a supported data type (e.g., INTEGER, VARCHAR, TEXT, TIMESTAMP)")
}

// UnsupportedConstraintError creates an E2009 error when a table constraint type
// is present in the SQL but not yet handled by the parser. Supported constraints
// are PRIMARY KEY, FOREIGN KEY, UNIQUE, NOT NULL, and CHECK.
//
// Parameters:
//   - constraint: The unrecognised constraint type (e.g., "EXCLUDE")
//   - location: Line/column where the constraint was found
//   - sql: Full SQL source used to generate visual context
func UnsupportedConstraintError(constraint string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedConstraint,
		fmt.Sprintf("constraint '%s' is not yet supported", constraint),
		location,
	).WithContext(sql, len(constraint)).WithHint("Supported constraints: PRIMARY KEY, FOREIGN KEY, UNIQUE, NOT NULL, CHECK")
}

// UnsupportedJoinError creates an E2010 error for a JOIN type that the parser
// recognises syntactically but does not yet fully support. Supported join types
// are INNER, LEFT, RIGHT, FULL, CROSS, and NATURAL.
//
// Parameters:
//   - joinType: The unrecognised or unsupported join type string
//   - location: Line/column where the join type token was found
//   - sql: Full SQL source used to generate visual context
func UnsupportedJoinError(joinType string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUnsupportedJoin,
		fmt.Sprintf("JOIN type '%s' is not yet supported", joinType),
		location,
	).WithContext(sql, len(joinType)).WithHint("Supported JOINs: INNER JOIN, LEFT JOIN, RIGHT JOIN, FULL JOIN, CROSS JOIN, NATURAL JOIN")
}

// InvalidCTEError creates an E2011 error for malformed Common Table Expression
// (WITH clause) syntax. Common causes include a missing AS keyword, missing
// parentheses around the CTE body, or a missing trailing SELECT statement.
//
// Parameters:
//   - description: Explanation of the specific CTE syntax problem
//   - location: Line/column where the CTE syntax error was detected
//   - sql: Full SQL source used to generate visual context
func InvalidCTEError(description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidCTE,
		fmt.Sprintf("invalid CTE syntax: %s", description),
		location,
	).WithContext(sql, 1).WithHint("Check WITH clause syntax: WITH cte_name AS (SELECT ...) SELECT * FROM cte_name")
}

// InvalidSetOperationError creates an E2012 error for an invalid UNION, INTERSECT,
// or EXCEPT set operation. The most common cause is a column count or type mismatch
// between the left and right queries.
//
// Parameters:
//   - operation: The set operation keyword (e.g., "UNION", "INTERSECT")
//   - description: Explanation of why the operation is invalid
//   - location: Line/column where the set operation was found
//   - sql: Full SQL source used to generate visual context
func InvalidSetOperationError(operation, description string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeInvalidSetOperation,
		fmt.Sprintf("invalid %s operation: %s", operation, description),
		location,
	).WithContext(sql, len(operation)).WithHint("Ensure both queries have the same number and compatible types of columns")
}

// Semantic Errors (E3001-E3004)

// UndefinedTableError creates an E3001 error when a table name referenced in the
// query cannot be resolved in the available schema. The hint suggests checking for
// typos and verifying the table exists.
//
// Parameters:
//   - tableName: The unresolved table name
//   - location: Line/column where the table reference was found
//   - sql: Full SQL source used to generate visual context
func UndefinedTableError(tableName string, location models.Location, sql string) *Error {
	return NewError(
		ErrCodeUndefinedTable,
		fmt.Sprintf("table '%s' does not exist", tableName),
		location,
	).WithContext(sql, len(tableName)).WithHint(fmt.Sprintf("Check the table name '%s' for typos or ensure it exists in the schema", tableName))
}

// UndefinedColumnError creates an E3002 error when a column name cannot be found
// in the referenced table's schema. When tableName is non-empty, the error message
// includes the table context for clearer diagnosis.
//
// Parameters:
//   - columnName: The unresolved column name
//   - tableName: The table where the column was expected (empty if unknown)
//   - location: Line/column where the column reference was found
//   - sql: Full SQL source used to generate visual context
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

// TypeMismatchError creates an E3003 error when two sides of an expression have
// incompatible types (e.g., comparing an INTEGER column to a TEXT literal without
// a CAST). When context is non-empty, it is included in the message for clarity.
//
// Parameters:
//   - leftType: Data type of the left operand (e.g., "INTEGER")
//   - rightType: Data type of the right operand (e.g., "TEXT")
//   - context: Optional description of where the mismatch occurs (e.g., "WHERE clause")
//   - location: Line/column where the type mismatch was detected
//   - sql: Full SQL source used to generate visual context
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

// AmbiguousColumnError creates an E3004 error when a column name appears in more
// than one table in scope and no qualifier disambiguates it. The hint suggests
// qualifying the column with a table name or alias.
//
// Parameters:
//   - columnName: The ambiguous column name
//   - tables: Slice of table names that all contain the column (may be empty if unknown)
//   - location: Line/column where the ambiguous reference was found
//   - sql: Full SQL source used to generate visual context
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
	return strings.Join(strs, sep)
}
