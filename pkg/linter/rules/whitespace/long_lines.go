package whitespace

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// LongLinesRule (L005) detects lines exceeding a configurable maximum length.
//
// Long lines reduce readability, especially in code reviews, side-by-side diffs,
// and terminal environments. This rule enforces a maximum line length to improve
// readability across different viewing contexts.
//
// Rule ID: L005
// Severity: Info
// Auto-fix: Not supported (requires semantic understanding)
//
// Example violation (maxLength=80):
//
//	SELECT user_id, username, email, created_at, updated_at, last_login FROM users WHERE active = true  <- 95 chars (violation)
//
// The rule skips comment-only lines as they often contain documentation or URLs
// that shouldn't be broken. Lines with trailing whitespace are measured including
// the whitespace.
type LongLinesRule struct {
	linter.BaseRule
	MaxLength int
}

// NewLongLinesRule creates a new L005 rule instance.
//
// Parameters:
//   - maxLength: Maximum line length in characters (minimum 1, default 100)
//
// If maxLength is 0 or negative, defaults to 100 characters.
//
// Returns a configured LongLinesRule ready for use with the linter.
func NewLongLinesRule(maxLength int) *LongLinesRule {
	if maxLength <= 0 {
		maxLength = 100 // Default to 100 characters
	}

	return &LongLinesRule{
		BaseRule: linter.NewBaseRule(
			"L005",
			"Long Lines",
			"Lines should not exceed maximum length for readability",
			linter.SeverityInfo,
			false, // Auto-fix not supported (requires semantic understanding)
		),
		MaxLength: maxLength,
	}
}

// Check performs the long lines check on SQL content.
//
// Measures each line's length and reports violations for lines exceeding MaxLength.
// Empty lines and comment-only lines (starting with -- or /*) are skipped.
//
// The violation column points to the position just after MaxLength to indicate
// where the line becomes too long.
//
// Returns a slice of violations (one per line exceeding maximum length) and nil error.
func (r *LongLinesRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		lineLength := len(line)

		// Skip empty lines
		if lineLength == 0 {
			continue
		}

		// Skip comment-only lines (optional - could be configurable)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		if lineLength > r.MaxLength {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Line exceeds maximum length",
				Location:   models.Location{Line: lineNum + 1, Column: r.MaxLength + 1},
				Line:       line,
				Suggestion: fmt.Sprintf("Split this line into multiple lines (current: %d chars, max: %d)", lineLength, r.MaxLength),
				CanAutoFix: false,
			})
		}
	}

	return violations, nil
}

// Fix is not supported for this rule as it requires semantic understanding.
//
// Breaking long lines requires understanding:
//   - SQL clause boundaries (WHERE, AND, OR, etc.)
//   - String literal boundaries
//   - Appropriate indentation for continuation
//   - Logical grouping of conditions
//
// These decisions require human judgment about readability and cannot be automated
// safely without risk of creating worse formatting.
//
// Returns the content unchanged with nil error.
func (r *LongLinesRule) Fix(content string, violations []linter.Violation) (string, error) {
	// No automatic fix available
	return content, nil
}
