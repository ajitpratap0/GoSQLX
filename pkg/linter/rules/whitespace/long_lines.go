package whitespace

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// LongLinesRule checks for lines exceeding maximum length
type LongLinesRule struct {
	linter.BaseRule
	MaxLength int
}

// NewLongLinesRule creates a new L005 rule instance
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

// Check performs the long lines check
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
				Rule:     r.ID(),
				RuleName: r.Name(),
				Severity: r.Severity(),
				Message:  "Line exceeds maximum length",
				Location: models.Location{Line: lineNum + 1, Column: r.MaxLength + 1},
				Line:     line,
				Suggestion: func() string {
					return "Split this line into multiple lines (current: " +
						string(rune(lineLength)) + " chars, max: " +
						string(rune(r.MaxLength)) + ")"
				}(),
				CanAutoFix: false,
			})
		}
	}

	return violations, nil
}

// Fix is not supported for long lines (requires semantic understanding)
func (r *LongLinesRule) Fix(content string, violations []linter.Violation) (string, error) {
	// No automatic fix available
	return content, nil
}
