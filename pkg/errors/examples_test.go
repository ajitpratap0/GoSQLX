package errors_test

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Example_enhancedErrorWithContext demonstrates the enhanced error formatting with 3 lines of context
func Example_enhancedErrorWithContext() {
	// Multi-line SQL with an error on line 3
	sql := `SELECT id, name, email
FROM users
WHERE age > 18.45.6
ORDER BY name`

	location := models.Location{Line: 3, Column: 13}
	err := errors.InvalidNumberError("18.45.6", location, sql)

	fmt.Println("Enhanced Error Output:")
	fmt.Println(err.Error())
	fmt.Println()

	// Note: This will show:
	// - Line 2 (FROM users)
	// - Line 3 (WHERE age > 18.45.6) with error indicator
	// - Line 4 (ORDER BY name)
}

// Example_typoDetectionWithSuggestions demonstrates automatic typo detection
func Example_typoDetectionWithSuggestions() {
	// Common SQL keyword typo
	sql := "SELECT * FORM users WHERE age > 18"
	location := models.Location{Line: 1, Column: 10}

	err := errors.ExpectedTokenError("FROM", "FORM", location, sql)

	fmt.Println("Typo Detection Example:")
	fmt.Println(err.Error())
	fmt.Println()

	// The error will include:
	// - Error code and location
	// - SQL context with the typo highlighted
	// - Intelligent hint: "Did you mean 'FROM' instead of 'FORM'?"
	// - Help URL for documentation
}

// Example_unterminatedString demonstrates unterminated string error
func Example_unterminatedString() {
	sql := "SELECT * FROM users WHERE name = 'John"
	location := models.Location{Line: 1, Column: 34}

	err := errors.UnterminatedStringError(location, sql)

	fmt.Println("Unterminated String Example:")
	fmt.Println(err.Error())
	fmt.Println()
}

// Example_invalidNumber demonstrates invalid number format error
func Example_invalidNumber() {
	sql := "SELECT * FROM products WHERE price > 19.99.5"
	location := models.Location{Line: 1, Column: 38}

	err := errors.InvalidNumberError("19.99.5", location, sql)

	fmt.Println("Invalid Number Example:")
	fmt.Println(err.Error())
	fmt.Println()
}

// Example_missingClause demonstrates missing clause error with suggestions
func Example_missingClause() {
	sql := "SELECT id, name, email users WHERE age > 18"
	location := models.Location{Line: 1, Column: 24}

	err := errors.MissingClauseError("FROM", location, sql)

	fmt.Println("Missing Clause Example:")
	fmt.Println(err.Error())
	fmt.Println()
}

// Example_incompleteStatement demonstrates incomplete SQL statement
func Example_incompleteStatement() {
	sql := "SELECT * FROM users WHERE"
	location := models.Location{Line: 1, Column: 26}

	err := errors.IncompleteStatementError(location, sql)

	fmt.Println("Incomplete Statement Example:")
	fmt.Println(err.Error())
	fmt.Println()
}

// Example_multiLineError demonstrates error in multi-line SQL with proper context
func Example_multiLineError() {
	sql := `SELECT
    u.id,
    u.name,
    u.email
FROM users u
JOIN orders o ON u.id = o.user_id
WHERE u.age > 18.45.6
AND o.total > 100`

	location := models.Location{Line: 7, Column: 15}
	err := errors.InvalidNumberError("18.45.6", location, sql)

	fmt.Println("Multi-line SQL Error:")
	fmt.Println(err.Error())
	fmt.Println()

	// Shows context with proper line numbering:
	// Line 6: JOIN orders o ON u.id = o.user_id
	// Line 7: WHERE u.age > 18.45.6   <- Error indicator here
	// Line 8: AND o.total > 100
}

// Example_errorCodeProgrammaticHandling demonstrates using error codes for logic
func Example_errorCodeProgrammaticHandling() {
	sql := "SELECT * FROM"
	location := models.Location{Line: 1, Column: 14}

	err := errors.IncompleteStatementError(location, sql)

	// Check error type programmatically
	if errors.IsCode(err, errors.ErrCodeIncompleteStatement) {
		fmt.Println("Detected incomplete SQL statement")
		fmt.Println("Error code:", errors.GetCode(err))
		fmt.Println("Can suggest adding table name")
	}

	// Output:
	// Detected incomplete SQL statement
	// Error code: E2005
	// Can suggest adding table name
}

// Example_unexpectedCharacter demonstrates unexpected character in SQL
func Example_unexpectedCharacter() {
	sql := "SELECT * FROM users WHERE age > 18 & active = 1"
	location := models.Location{Line: 1, Column: 36}

	err := errors.UnexpectedCharError('&', location, sql)

	fmt.Println("Unexpected Character Example:")
	fmt.Println(err.Error())
	fmt.Println()

	// Suggests: "Remove or escape the character '&'"
	// User should use AND instead of &
}

// Example_errorChaining demonstrates wrapping errors
func Example_errorChaining() {
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
		"parser error while processing SELECT",
		location,
		sql,
		rootErr,
	)

	fmt.Println("Chained Error:")
	fmt.Println(wrappedErr.Error())
	fmt.Println()

	// Can unwrap to get root cause
	if wrappedErr.Unwrap() != nil {
		fmt.Println("Root cause available through Unwrap()")
	}

	// Note: Output includes chained error with context
	// Root cause available through Unwrap()
}

// Example_customHintsEnhanced demonstrates adding custom hints to errors
func Example_customHintsEnhanced() {
	sql := "SELECT * FROM users WHERE age > '18'"
	location := models.Location{Line: 1, Column: 33}

	err := errors.NewError(
		errors.ErrCodeInvalidSyntax,
		"type mismatch in comparison",
		location,
	)
	err.WithContext(sql, 4) // Highlight '18'
	err.WithHint("Age comparisons should use numeric values without quotes. Change '18' to 18")

	fmt.Println("Custom Hint Example:")
	fmt.Println(err.Error())
	fmt.Println()
}

// Example_allErrorCodes demonstrates all available error codes
func Example_allErrorCodes() {
	fmt.Println("Available Error Codes:")
	fmt.Println()

	fmt.Println("Tokenizer Errors (E1xxx):")
	fmt.Println("  E1001: Unexpected character")
	fmt.Println("  E1002: Unterminated string")
	fmt.Println("  E1003: Invalid number")
	fmt.Println("  E1004: Invalid operator")
	fmt.Println("  E1005: Invalid identifier")
	fmt.Println()

	fmt.Println("Parser Errors (E2xxx):")
	fmt.Println("  E2001: Unexpected token")
	fmt.Println("  E2002: Expected token")
	fmt.Println("  E2003: Missing clause")
	fmt.Println("  E2004: Invalid syntax")
	fmt.Println("  E2005: Incomplete statement")
	fmt.Println("  E2006: Invalid expression")
	fmt.Println()

	fmt.Println("Semantic Errors (E3xxx):")
	fmt.Println("  E3001: Undefined table")
	fmt.Println("  E3002: Undefined column")
	fmt.Println("  E3003: Type mismatch")
	fmt.Println("  E3004: Ambiguous column")
	fmt.Println()

	fmt.Println("Unsupported Features (E4xxx):")
	fmt.Println("  E4001: Unsupported feature")
	fmt.Println("  E4002: Unsupported dialect")
}

// Example_comparingErrors demonstrates before and after error format
func Example_comparingErrors() {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	fmt.Println("=== BEFORE: Simple Error ===")
	fmt.Println("Error: expected FROM, got FORM")
	fmt.Println()

	fmt.Println("=== AFTER: Enhanced Error ===")
	err := errors.ExpectedTokenError("FROM", "FORM", location, sql)
	fmt.Println(err.Error())
	fmt.Println()

	fmt.Println("Enhancement includes:")
	fmt.Println("✓ Error code (E2002)")
	fmt.Println("✓ Precise location (line 1, column 10)")
	fmt.Println("✓ SQL context with visual indicator")
	fmt.Println("✓ Intelligent hint with typo detection")
	fmt.Println("✓ Documentation link")
}

// Example_realWorldScenario demonstrates a complete real-world error scenario
func Example_realWorldScenario() {
	// Simulate a real SQL query with multiple errors
	sqlQueries := []struct {
		sql      string
		location models.Location
		errType  string
	}{
		{
			sql:      "SELECT id, name email FROM users",
			location: models.Location{Line: 1, Column: 17},
			errType:  "missing_comma",
		},
		{
			sql:      "SELECT * FROM users WHERE age > '18'",
			location: models.Location{Line: 1, Column: 33},
			errType:  "string_instead_of_number",
		},
		{
			sql:      "SELECT * FROM users JOIN orders",
			location: models.Location{Line: 1, Column: 25},
			errType:  "missing_join_condition",
		},
	}

	fmt.Println("=== Real-World Error Scenarios ===")
	fmt.Println()

	for i, query := range sqlQueries {
		fmt.Printf("Scenario %d: %s\n", i+1, query.errType)
		fmt.Println("Query:", query.sql)

		// In real usage, the parser would detect and create these errors
		fmt.Println("(Error details would be shown here with full context and suggestions)")
		fmt.Println()
	}
}

// Example_errorRecovery demonstrates how to handle and recover from errors
func Example_errorRecovery() {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	err := errors.ExpectedTokenError("FROM", "FORM", location, sql)

	// Check if error is recoverable
	if errors.IsCode(err, errors.ErrCodeExpectedToken) {
		fmt.Println("Detected recoverable syntax error")
		fmt.Println("Suggestion: Fix the typo and retry")

		// Use the error's hint for auto-correction
		if err.Hint != "" {
			fmt.Println("Hint:", err.Hint)
		}
	}

	// Output:
	// Detected recoverable syntax error
	// Suggestion: Fix the typo and retry
	// Hint: Did you mean 'FROM' instead of 'FORM'?
}

// Example_batchValidation demonstrates validating multiple SQL statements
func Example_batchValidation() {
	statements := []string{
		"SELECT * FROM users",          // Valid
		"SELECT * FORM users",          // Typo
		"SELECT * FROM",                // Incomplete
		"SELECT id name FROM users",    // Missing comma
		"INSERT users VALUES (1, 'x')", // Missing INTO
	}

	fmt.Println("Batch Validation Results:")
	fmt.Println()

	for i, stmt := range statements {
		fmt.Printf("%d. %s\n", i+1, stmt)
		// In real usage, parser would validate each statement
		// and report errors with full context
	}

	fmt.Println()
	fmt.Println("Validation would show:")
	fmt.Println("✓ Statement 1: Valid")
	fmt.Println("✗ Statement 2: Error E2002 - Expected FROM")
	fmt.Println("✗ Statement 3: Error E2005 - Incomplete")
	fmt.Println("✗ Statement 4: Syntax error - Missing comma")
	fmt.Println("✗ Statement 5: Error E2003 - Missing INTO")
}
