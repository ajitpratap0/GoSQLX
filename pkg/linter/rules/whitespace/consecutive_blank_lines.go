package whitespace

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ConsecutiveBlankLinesRule (L003) detects and fixes excessive consecutive blank lines.
//
// Excessive blank lines reduce code density and make it harder to view complete queries
// on screen. This rule enforces a configurable maximum number of consecutive blank
// lines, improving readability without eliminating vertical spacing entirely.
//
// Rule ID: L003
// Severity: Warning
// Auto-fix: Supported
//
// Example violation (maxConsecutive=1):
//
//	SELECT * FROM users
//
//
//	WHERE active = true  <- Two blank lines above (violation)
//
// Fixed output:
//
//	SELECT * FROM users
//
//	WHERE active = true  <- Single blank line
//
// The rule also removes excessive blank lines at the end of files.
type ConsecutiveBlankLinesRule struct {
	linter.BaseRule
	maxConsecutive int
}

// NewConsecutiveBlankLinesRule creates a new L003 rule instance.
//
// Parameters:
//   - maxConsecutive: Maximum number of consecutive blank lines allowed (minimum 1)
//
// If maxConsecutive is less than 1, defaults to 1.
//
// Returns a configured ConsecutiveBlankLinesRule ready for use with the linter.
func NewConsecutiveBlankLinesRule(maxConsecutive int) *ConsecutiveBlankLinesRule {
	if maxConsecutive < 1 {
		maxConsecutive = 1 // Default to max 1 consecutive blank line
	}
	return &ConsecutiveBlankLinesRule{
		BaseRule: linter.NewBaseRule(
			"L003",
			"Consecutive Blank Lines",
			"Too many consecutive blank lines",
			linter.SeverityWarning,
			true, // Supports auto-fix
		),
		maxConsecutive: maxConsecutive,
	}
}

// Check performs the consecutive blank lines check on SQL content.
//
// Scans through lines tracking consecutive blank lines. Reports violations when
// consecutive blank count exceeds maxConsecutive. Also checks for excessive blank
// lines at file end.
//
// Returns a slice of violations (one per sequence of excessive blank lines) and nil error.
func (r *ConsecutiveBlankLinesRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	consecutiveCount := 0
	startLine := 0

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			if consecutiveCount == 0 {
				startLine = lineNum + 1 // 1-indexed
			}
			consecutiveCount++
		} else {
			if consecutiveCount > r.maxConsecutive {
				violations = append(violations, linter.Violation{
					Rule:     r.ID(),
					RuleName: r.Name(),
					Severity: r.Severity(),
					Message: func() string {
						if r.maxConsecutive == 1 {
							return "Multiple consecutive blank lines found"
						}
						return "Too many consecutive blank lines"
					}(),
					Location: models.Location{Line: startLine, Column: 1},
					Line:     "",
					Suggestion: "Reduce consecutive blank lines to " + func() string {
						if r.maxConsecutive == 1 {
							return "at most 1"
						} else {
							return "the configured maximum"
						}
					}(),
					CanAutoFix: true,
				})
			}
			consecutiveCount = 0
		}
	}

	// Check if file ends with too many blank lines
	if consecutiveCount > r.maxConsecutive {
		violations = append(violations, linter.Violation{
			Rule:       r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    "File ends with multiple consecutive blank lines",
			Location:   models.Location{Line: startLine, Column: 1},
			Line:       "",
			Suggestion: "Remove excess trailing blank lines",
			CanAutoFix: true,
		})
	}

	return violations, nil
}

// Fix removes excess consecutive blank lines from SQL content.
//
// Processes content line by line, preserving up to maxConsecutive blank lines in
// any sequence. Additional blank lines beyond the limit are removed. Also trims
// excess trailing blank lines at file end.
//
// Returns the fixed content with consecutive blank lines reduced to maximum, and nil error.
func (r *ConsecutiveBlankLinesRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")
	result := make([]string, 0, len(lines))

	consecutiveCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			consecutiveCount++
			if consecutiveCount <= r.maxConsecutive {
				result = append(result, line)
			}
		} else {
			consecutiveCount = 0
			result = append(result, line)
		}
	}

	// Trim trailing blank lines at end of file to at most maxConsecutive
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		blankCount := 0
		for i := len(result) - 1; i >= 0 && strings.TrimSpace(result[i]) == ""; i-- {
			blankCount++
		}
		if blankCount > r.maxConsecutive {
			result = result[:len(result)-1]
		} else {
			break
		}
	}

	return strings.Join(result, "\n"), nil
}
