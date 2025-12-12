package whitespace

import (
	"strings"
	"unicode"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TrailingWhitespaceRule (L001) detects and removes unnecessary trailing whitespace
// at the end of lines.
//
// This rule identifies spaces and tabs at line endings that serve no purpose and
// can cause issues with version control diffs and some text editors. Trailing
// whitespace is commonly introduced by text editors, copy-paste operations, or
// inconsistent formatting practices.
//
// Rule ID: L001
// Severity: Warning
// Auto-fix: Supported
//
// Example violations:
//
//	SELECT * FROM users   <- Trailing spaces
//	WHERE active = true	  <- Trailing tab
//
// Fixed output:
//
//	SELECT * FROM users
//	WHERE active = true
//
// The rule preserves newline characters but removes all trailing spaces and tabs.
type TrailingWhitespaceRule struct {
	linter.BaseRule
}

// NewTrailingWhitespaceRule creates a new L001 rule instance.
//
// The rule detects trailing spaces and tabs on any line and supports automatic
// fixing by stripping all trailing whitespace.
//
// Returns a configured TrailingWhitespaceRule ready for use with the linter.
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

// Check performs the trailing whitespace check on SQL content.
//
// Scans each line for spaces or tabs at the end (excluding newline characters).
// For each line with trailing whitespace, a violation is reported at the position
// where the trailing whitespace begins.
//
// Empty lines are skipped as they cannot have meaningful trailing whitespace.
//
// Returns a slice of violations (one per line with trailing whitespace) and nil error.
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

// Fix removes trailing whitespace from all lines in the SQL content.
//
// Processes the content line by line, trimming spaces and tabs from the right side
// of each line. Newlines are preserved. The violations parameter is ignored since
// the fix is applied uniformly to all lines.
//
// This operation is safe to apply automatically and doesn't change SQL semantics.
//
// Returns the fixed content with all trailing whitespace removed, and nil error.
func (r *TrailingWhitespaceRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	return strings.Join(lines, "\n"), nil
}
