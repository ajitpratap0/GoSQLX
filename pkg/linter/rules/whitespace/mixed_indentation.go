package whitespace

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// MixedIndentationRule checks for mixed tabs and spaces in indentation
type MixedIndentationRule struct {
	linter.BaseRule
}

// NewMixedIndentationRule creates a new L002 rule instance
func NewMixedIndentationRule() *MixedIndentationRule {
	return &MixedIndentationRule{
		BaseRule: linter.NewBaseRule(
			"L002",
			"Mixed Indentation",
			"Inconsistent use of tabs and spaces for indentation",
			linter.SeverityError,
			true, // Supports auto-fix (convert to spaces)
		),
	}
}

// Check performs the mixed indentation check
func (r *MixedIndentationRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	// Track the first indentation type we encounter
	var firstIndentType string // "tab" or "space"

	for lineNum, line := range ctx.Lines {
		if len(line) == 0 {
			continue
		}

		// Get leading whitespace
		leadingWhitespace := getLeadingWhitespace(line)
		if len(leadingWhitespace) == 0 {
			continue
		}

		// Check what type of indentation this line uses
		hasTabs := strings.Contains(leadingWhitespace, "\t")
		hasSpaces := strings.Contains(leadingWhitespace, " ")

		// Mixed tabs and spaces on same line
		if hasTabs && hasSpaces {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Line mixes tabs and spaces for indentation",
				Location:   models.Location{Line: lineNum + 1, Column: 1},
				Line:       line,
				Suggestion: "Use either tabs or spaces consistently for indentation (spaces recommended)",
				CanAutoFix: true,
			})
			continue
		}

		// Track first indentation type and check consistency
		currentType := ""
		if hasTabs {
			currentType = "tab"
		} else if hasSpaces {
			currentType = "space"
		}

		if currentType != "" {
			if firstIndentType == "" {
				firstIndentType = currentType
			} else if firstIndentType != currentType {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Inconsistent indentation: file uses both tabs and spaces",
					Location:   models.Location{Line: lineNum + 1, Column: 1},
					Line:       line,
					Suggestion: "Use " + firstIndentType + "s consistently throughout the file",
					CanAutoFix: true,
				})
			}
		}
	}

	return violations, nil
}

// Fix converts all indentation to spaces (4 spaces per tab)
func (r *MixedIndentationRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		// Replace tabs with 4 spaces in leading whitespace only
		leadingWhitespace := getLeadingWhitespace(line)
		if len(leadingWhitespace) > 0 {
			fixed := strings.ReplaceAll(leadingWhitespace, "\t", "    ")
			lines[i] = fixed + strings.TrimLeft(line, " \t")
		}
	}

	return strings.Join(lines, "\n"), nil
}

// getLeadingWhitespace returns the leading whitespace of a line
func getLeadingWhitespace(line string) string {
	for i, char := range line {
		if char != ' ' && char != '\t' {
			return line[:i]
		}
	}
	return line // Entire line is whitespace
}
