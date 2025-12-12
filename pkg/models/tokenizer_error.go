package models

// TokenizerError represents an error during tokenization.
//
// TokenizerError is a simple error type for lexical analysis failures.
// It includes the error message and the precise location where the error occurred.
//
// For more sophisticated error handling with hints, suggestions, and context,
// use the errors package (pkg/errors) which provides structured errors with:
//   - Error codes (E1xxx for tokenizer errors)
//   - SQL context extraction and highlighting
//   - Intelligent suggestions and typo detection
//   - Help URLs for documentation
//
// Fields:
//   - Message: Human-readable error description
//   - Location: Precise position in source where error occurred (line/column)
//
// Example:
//
//	err := models.TokenizerError{
//	    Message:  "unexpected character '@' at position",
//	    Location: models.Location{Line: 2, Column: 15},
//	}
//	fmt.Println(err.Error()) // "unexpected character '@' at position"
//
// Upgrading to structured errors:
//
//	// Instead of TokenizerError, use errors package:
//	err := errors.UnexpectedCharError('@', location, sqlSource)
//	// Provides: error code, context, hints, help URL
//
// Common tokenizer errors:
//   - Unexpected characters in input
//   - Unterminated string literals
//   - Invalid numeric formats
//   - Invalid identifier syntax
//   - Input size limits exceeded (DoS protection)
//
// Performance: TokenizerError is a lightweight value type with minimal overhead.
type TokenizerError struct {
	Message  string   // Error description
	Location Location // Where the error occurred
}

// Error implements the error interface.
//
// Returns the error message. For full context and location information,
// use the errors package which provides FormatErrorWithContext.
//
// Example:
//
//	err := models.TokenizerError{Message: "invalid token", Location: loc}
//	fmt.Println(err.Error()) // Output: "invalid token"
func (e TokenizerError) Error() string {
	return e.Message
}
