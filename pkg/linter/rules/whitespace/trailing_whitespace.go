package whitespace

import (
	"strings"
	"unicode"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TrailingWhitespaceRule checks for unnecessary trailing whitespace
type TrailingWhitespaceRule struct {
	linter.BaseRule
}

// NewTrailingWhitespaceRule creates a new L001 rule instance
func NewTrailingWhitespaceRule() *TrailingWhitespaceRule {
	return &TrailingWhitespaceRule{
		BaseRule: linter.NewBaseRule(
			"L001",
			"Trailing Whitespace",
			"Unnecessary trailing whitespace at end of lines",
			linter.SeverityWarning,
			true, // Supports auto-fix
		),
	}
}

// Check performs the trailing whitespace check
func (r *TrailingWhitespaceRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		// Check if line has trailing whitespace
		if len(line) == 0 {
			continue
		}

		lastChar := rune(line[len(line)-1])
		if unicode.IsSpace(lastChar) && lastChar != '\n' && lastChar != '\r' {
			// Find the column where trailing whitespace starts
			trimmed := strings.TrimRight(line, " \t")
			column := len(trimmed) + 1

			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Line has trailing whitespace",
				Location:   models.Location{Line: lineNum + 1, Column: column},
				Line:       line,
				Suggestion: "Remove trailing spaces or tabs from the end of the line",
				CanAutoFix: true,
			})
		}
	}

	return violations, nil
}

// Fix removes trailing whitespace from all lines
func (r *TrailingWhitespaceRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	return strings.Join(lines, "\n"), nil
}
