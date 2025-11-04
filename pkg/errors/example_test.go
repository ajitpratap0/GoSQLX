package errors_test

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Example_basicError demonstrates creating a basic structured error
func Example_basicError() {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	err := errors.ExpectedTokenError("FROM", "FORM", location, sql)
	fmt.Println(err.Error())

	// Output includes:
	// - Error code
	// - Location (line and column)
	// - SQL context with position indicator
	// - Intelligent hint suggesting the correction
}

// Example_typoDetection demonstrates automatic typo detection
func Example_typoDetection() {
	// Common SQL keyword typos are automatically detected
	typos := map[string]string{
		"FORM":  "FROM",
		"SELCT": "SELECT",
		"WAHER": "WHERE",
		"JION":  "JOIN",
		"UPDTE": "UPDATE",
	}

	for typo, correct := range typos {
		suggestion := errors.SuggestKeyword(typo)
		if suggestion == correct {
			fmt.Printf("%s → %s ✓\n", typo, suggestion)
		}
	}
	// Output:
	// FORM → FROM ✓
	// SELCT → SELECT ✓
	// WAHER → WHERE ✓
	// JION → JOIN ✓
	// UPDTE → UPDATE ✓
}

// Example_errorCodes demonstrates programmatic error handling
func Example_errorCodes() {
	sql := "SELECT * FROM"
	location := models.Location{Line: 1, Column: 14}

	// Create an error
	err := errors.IncompleteStatementError(location, sql)

	// Check error code programmatically
	if errors.IsCode(err, errors.ErrCodeIncompleteStatement) {
		fmt.Println("Detected incomplete SQL statement")
	}

	// Get error code
	code := errors.GetCode(err)
	fmt.Printf("Error code: %s\n", code)

	// Output:
	// Detected incomplete SQL statement
	// Error code: E2005
}

// Example_contextExtraction demonstrates SQL context in error messages
func Example_contextExtraction() {
	// Multi-line SQL with error on line 2
	sql := `SELECT *
FROM users
WHERE age > 18.45.6
ORDER BY name`

	location := models.Location{Line: 3, Column: 13}
	err := errors.InvalidNumberError("18.45.6", location, sql)

	// Error includes:
	// - The problematic line from the SQL
	// - Position indicator pointing to the error
	// - Helpful hint about numeric format
	fmt.Println("Error detected in multi-line SQL:")
	_ = err // Use the error
}

// Example_chainedErrors demonstrates error wrapping
func Example_chainedErrors() {
	sql := "SELECT * FROM users"
	location := models.Location{Line: 1, Column: 1}

	// Create a chain of errors
	rootErr := errors.NewError(
		errors.ErrCodeInvalidSyntax,
		"invalid table reference",
		location,
	)

	wrappedErr := errors.WrapError(
		errors.ErrCodeUnexpectedToken,
		"parser error",
		location,
		sql,
		rootErr,
	)

	// Can unwrap to get root cause
	if wrappedErr.Unwrap() == rootErr {
		fmt.Println("Successfully wrapped error")
	}

	// Output:
	// Successfully wrapped error
}

// Example_customHints demonstrates adding custom hints
func Example_customHints() {
	sql := "SELECT * FROM users WHERE"
	location := models.Location{Line: 1, Column: 27}

	err := errors.NewError(
		errors.ErrCodeIncompleteStatement,
		"incomplete WHERE clause",
		location,
	)
	err.WithContext(sql, 5)
	err.WithHint("Add a condition after WHERE, e.g., WHERE age > 18")

	// Error now includes custom context and hint
	_ = err
}

// Example_multipleErrors demonstrates handling multiple validation errors
func Example_multipleErrors() {
	queries := []string{
		"SELECT * FORM users",             // E2002: Expected FROM
		"SELECT * FROM",                   // E2005: Incomplete statement
		"SELECT * FROM users WHERE age >", // E2005: Incomplete expression
	}

	errorCodes := []errors.ErrorCode{}
	for _, query := range queries {
		// In real usage, you'd call gosqlx.Parse() here
		// For this example, we'll simulate errors
		_ = query
	}

	fmt.Printf("Found %d SQL errors\n", len(errorCodes))
}
