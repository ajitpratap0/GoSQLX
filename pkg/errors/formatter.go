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

// FormatErrorWithContext formats an error with SQL context and visual indicators.
// For *Error values it delegates to the structured Error.Error() method, which
// includes code, location, SQL context highlighting, hint, and help URL. For all
// other error types it falls back to a plain "Error: <message>" string.
//
// Parameters:
//   - err: The error to format (may be *Error or a generic error)
//   - sql: The SQL source; currently unused for *Error (context is already attached)
//
// Returns the formatted error string ready for display to end users.
func FormatErrorWithContext(err error, sql string) string {
	// If it's already a structured error, just return its formatted string
	if structErr, ok := err.(*Error); ok {
		return structErr.Error()
	}

	// For non-structured errors, return simple format
	return fmt.Sprintf("Error: %v", err)
}

// FormatErrorWithContextAt creates a structured error for the given code and location,
// attaches the SQL context window, and auto-generates a hint. It then returns the
// fully-formatted error string. This is useful for one-shot error formatting without
// retaining the *Error value.
//
// Parameters:
//   - code: ErrorCode classifying the error category (e.g., ErrCodeExpectedToken)
//   - message: Human-readable description of the error
//   - location: Precise line/column where the error occurred
//   - sql: Full SQL source used to generate the context window
//   - highlightLen: Number of characters to highlight at the error column
//
// Returns the complete formatted error string including context highlighting.
func FormatErrorWithContextAt(code ErrorCode, message string, location models.Location, sql string, highlightLen int) string {
	err := NewError(code, message, location)
	err = err.WithContext(sql, highlightLen)

	// Auto-generate hints
	if hint := GenerateHint(code, "", ""); hint != "" {
		err = err.WithHint(hint)
	}

	return err.Error()
}

// FormatMultiLineContext formats an SQL context window around a specific error location.
// It shows up to three lines: one before the error, the error line itself, and one
// after. A caret indicator (^) is rendered below the error column, with optional
// multi-character highlighting when highlightLen > 1.
//
// Parameters:
//   - sql: The full SQL source string (may contain newlines)
//   - location: The line/column of the error (1-based)
//   - highlightLen: Number of characters to highlight; 1 renders a single caret
//
// Returns the formatted context block, or an empty string if location is invalid.
func FormatMultiLineContext(sql string, location models.Location, highlightLen int) string {
	if sql == "" || location.Line <= 0 {
		return ""
	}

	var sb strings.Builder
	lines := strings.Split(sql, "\n")

	if location.Line > len(lines) {
		return ""
	}

	errorLineNum := location.Line

	// Calculate line number width for alignment
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
	if location.Column > 0 {
		// Account for line number prefix
		prefix := fmt.Sprintf("  %*d | ", lineNumWidth, errorLineNum)
		spaces := strings.Repeat(" ", len(prefix)+location.Column-1)
		highlight := "^"
		if highlightLen > 1 {
			highlight = strings.Repeat("^", highlightLen)
		}
		sb.WriteString(spaces + highlight + "\n")
	}

	// Show line after (if exists)
	if errorLineNum < len(lines) {
		lineNum := errorLineNum + 1
		line := lines[lineNum-1]
		sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, lineNum, line))
	}

	return sb.String()
}

// FormatErrorSummary provides a concise one-line error summary suitable for
// structured logging and monitoring systems where a full context window would
// be too verbose. For *Error values the output format is:
//
//	[E2001] unexpected token: COMMA at line 5, column 20
//
// For other error types the output is "Error: <message>".
//
// Parameters:
//   - err: The error to summarise
//
// Returns the one-line summary string.
func FormatErrorSummary(err error) string {
	if structErr, ok := err.(*Error); ok {
		return fmt.Sprintf("[%s] %s at line %d, column %d",
			structErr.Code,
			structErr.Message,
			structErr.Location.Line,
			structErr.Location.Column)
	}
	return fmt.Sprintf("Error: %v", err)
}

// FormatErrorWithSuggestion creates and formats a structured error that includes a
// manually provided hint. When suggestion is empty, the function falls back to
// auto-generating a hint via GenerateHint. This is the preferred formatter when
// the caller already knows the correct fix.
//
// Parameters:
//   - code: ErrorCode classifying the error category
//   - message: Human-readable description of the error
//   - location: Precise line/column where the error occurred
//   - sql: Full SQL source used to generate the context window
//   - highlightLen: Number of characters to highlight at the error column
//   - suggestion: Custom hint text; empty string triggers auto-generation
//
// Returns the complete formatted error string.
func FormatErrorWithSuggestion(code ErrorCode, message string, location models.Location, sql string, highlightLen int, suggestion string) string {
	err := NewError(code, message, location)
	err = err.WithContext(sql, highlightLen)

	if suggestion != "" {
		err = err.WithHint(suggestion)
	} else {
		// Try to auto-generate suggestion
		if autoHint := GenerateHint(code, "", ""); autoHint != "" {
			err = err.WithHint(autoHint)
		}
	}

	return err.Error()
}

// FormatErrorList formats a slice of structured errors into a numbered list with
// full context for each entry. The output begins with a count line and separates
// each error with a blank line.
//
// Returns "No errors" when the slice is empty.
//
// Parameters:
//   - errors: Slice of *Error values to format
//
// Returns the multi-error report string.
func FormatErrorList(errors []*Error) string {
	if len(errors) == 0 {
		return "No errors"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d error(s):\n\n", len(errors)))

	for i, err := range errors {
		sb.WriteString(fmt.Sprintf("Error %d:\n", i+1))
		sb.WriteString(err.Error())
		sb.WriteString("\n\n")
	}

	return sb.String()
}

// FormatErrorWithExample formats an error and appends a side-by-side "Wrong / Correct"
// example to the hint. This is particularly useful for educational error messages
// (e.g., in linters or IDEs) where showing the correct pattern helps users learn
// the expected SQL syntax.
//
// Parameters:
//   - code: ErrorCode classifying the error category
//   - message: Human-readable description of the error
//   - location: Precise line/column where the error occurred
//   - sql: Full SQL source used to generate the context window
//   - highlightLen: Number of characters to highlight at the error column
//   - wrongExample: The erroneous SQL fragment (e.g., "SELECT * FORM users")
//   - correctExample: The corrected SQL fragment (e.g., "SELECT * FROM users")
//
// Returns the complete formatted error string including the before/after example.
func FormatErrorWithExample(code ErrorCode, message string, location models.Location, sql string, highlightLen int, wrongExample, correctExample string) string {
	err := NewError(code, message, location)
	err = err.WithContext(sql, highlightLen)

	// Add hint with before/after example
	hint := fmt.Sprintf("Wrong: %s\nCorrect: %s", wrongExample, correctExample)
	err = err.WithHint(hint)

	return err.Error()
}

// FormatContextWindow formats a configurable SQL context window of up to linesBefore
// lines before and linesAfter lines after the error line. Prefer this over
// FormatMultiLineContext when more surrounding context is needed (e.g., in IDE
// hover messages or verbose diagnostic reports).
//
// Parameters:
//   - sql: The full SQL source string
//   - location: The line/column of the error (1-based)
//   - highlightLen: Number of characters to highlight at the error column
//   - linesBefore: Number of source lines to display before the error line
//   - linesAfter: Number of source lines to display after the error line
//
// Returns the formatted context block, or an empty string if location is invalid.
func FormatContextWindow(sql string, location models.Location, highlightLen int, linesBefore, linesAfter int) string {
	if sql == "" || location.Line <= 0 {
		return ""
	}

	var sb strings.Builder
	lines := strings.Split(sql, "\n")

	if location.Line > len(lines) {
		return ""
	}

	errorLineNum := location.Line

	// Calculate line range
	startLine := errorLineNum - linesBefore
	if startLine < 1 {
		startLine = 1
	}

	endLine := errorLineNum + linesAfter
	if endLine > len(lines) {
		endLine = len(lines)
	}

	// Calculate line number width for alignment
	lineNumWidth := len(fmt.Sprintf("%d", endLine))
	if lineNumWidth < 2 {
		lineNumWidth = 2
	}

	sb.WriteString("\n")

	// Show lines before error
	for lineNum := startLine; lineNum < errorLineNum; lineNum++ {
		line := lines[lineNum-1]
		sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, lineNum, line))
	}

	// Show error line
	line := lines[errorLineNum-1]
	sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, errorLineNum, line))

	// Add position indicator (^)
	if location.Column > 0 {
		prefix := fmt.Sprintf("  %*d | ", lineNumWidth, errorLineNum)
		spaces := strings.Repeat(" ", len(prefix)+location.Column-1)
		highlight := "^"
		if highlightLen > 1 {
			highlight = strings.Repeat("^", highlightLen)
		}
		sb.WriteString(spaces + highlight + "\n")
	}

	// Show lines after error
	for lineNum := errorLineNum + 1; lineNum <= endLine; lineNum++ {
		line := lines[lineNum-1]
		sb.WriteString(fmt.Sprintf("  %*d | %s\n", lineNumWidth, lineNum, line))
	}

	return sb.String()
}

// IsStructuredError reports whether err is a GoSQLX *Error value.
// Use this to distinguish GoSQLX structured errors from generic Go errors
// before calling functions that require *Error (e.g., ExtractLocation).
//
// Example:
//
//	if errors.IsStructuredError(err) {
//	    loc, _ := errors.ExtractLocation(err)
//	    // use loc for IDE diagnostics
//	}
func IsStructuredError(err error) bool {
	_, ok := err.(*Error)
	return ok
}

// ExtractLocation extracts the line/column location from a GoSQLX *Error.
// This is the preferred way to obtain location data for IDE integrations such as
// LSP diagnostics, since it handles the type assertion safely.
//
// Returns the Location and true when err is a *Error; returns a zero Location
// and false for all other error types.
func ExtractLocation(err error) (models.Location, bool) {
	if structErr, ok := err.(*Error); ok {
		return structErr.Location, true
	}
	return models.Location{}, false
}

// ExtractErrorCode extracts the ErrorCode from a GoSQLX *Error.
// Unlike GetCode, this function returns a boolean indicating whether the extraction
// succeeded, making it suitable for use in type-switch–style handling.
//
// Returns the ErrorCode and true when err is a *Error; returns an empty string
// and false for all other error types.
func ExtractErrorCode(err error) (ErrorCode, bool) {
	if structErr, ok := err.(*Error); ok {
		return structErr.Code, true
	}
	return "", false
}
