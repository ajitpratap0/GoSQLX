package errors

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// FormatErrorWithContext formats an error with SQL context and visual indicators
// This is a convenience function that wraps the Error.Error() method
func FormatErrorWithContext(err error, sql string) string {
	// If it's already a structured error, just return its formatted string
	if structErr, ok := err.(*Error); ok {
		return structErr.Error()
	}

	// For non-structured errors, return simple format
	return fmt.Sprintf("Error: %v", err)
}

// FormatErrorWithContextAt formats an error at a specific location with SQL context
func FormatErrorWithContextAt(code ErrorCode, message string, location models.Location, sql string, highlightLen int) string {
	err := NewError(code, message, location)
	err = err.WithContext(sql, highlightLen)

	// Auto-generate hints
	if hint := GenerateHint(code, "", ""); hint != "" {
		err = err.WithHint(hint)
	}

	return err.Error()
}

// FormatMultiLineContext formats error context for multi-line SQL with extended context
// Shows up to 3 lines (1 before, error line, 1 after) with proper indentation
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

// FormatErrorSummary provides a brief summary of an error without full context
// Useful for logging or when SQL context is not needed
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

// FormatErrorWithSuggestion formats an error with an intelligent suggestion
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

// FormatErrorList formats multiple errors in a readable list
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

// FormatErrorWithExample formats an error with a corrected example
func FormatErrorWithExample(code ErrorCode, message string, location models.Location, sql string, highlightLen int, wrongExample, correctExample string) string {
	err := NewError(code, message, location)
	err = err.WithContext(sql, highlightLen)

	// Add hint with before/after example
	hint := fmt.Sprintf("Wrong: %s\nCorrect: %s", wrongExample, correctExample)
	err = err.WithHint(hint)

	return err.Error()
}

// FormatContextWindow formats a larger context window (up to N lines before and after)
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

// IsStructuredError checks if an error is a structured GoSQLX error
func IsStructuredError(err error) bool {
	_, ok := err.(*Error)
	return ok
}

// ExtractLocation extracts location information from an error
func ExtractLocation(err error) (models.Location, bool) {
	if structErr, ok := err.(*Error); ok {
		return structErr.Location, true
	}
	return models.Location{}, false
}

// ExtractErrorCode extracts the error code from an error
func ExtractErrorCode(err error) (ErrorCode, bool) {
	if structErr, ok := err.(*Error); ok {
		return structErr.Code, true
	}
	return "", false
}
