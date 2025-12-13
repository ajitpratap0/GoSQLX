package whitespace

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// MixedIndentationRule (L002) detects and fixes inconsistent use of tabs and spaces
// for indentation within a file.
//
// Mixed indentation causes display issues across different editors and environments
// where tab width settings vary. This rule enforces consistent indentation by
// detecting both line-level mixing (tabs and spaces on the same line) and file-level
// inconsistency (some lines using tabs, others using spaces).
//
// Rule ID: L002
// Severity: Error
// Auto-fix: Supported (converts all tabs to 4 spaces)
//
// Example violations:
//
//	SELECT *        <- Uses spaces
//	FROM users      <- Uses spaces
//		WHERE active  <- Uses tab
//
// Fixed output (all spaces):
//
//	SELECT *
//	FROM users
//	    WHERE active
//
// The auto-fix converts all leading tabs to 4 spaces, preserving tabs that appear
// inside SQL strings or after non-whitespace characters.
type MixedIndentationRule struct {
	linter.BaseRule
}

// NewMixedIndentationRule creates a new L002 rule instance.
//
// The rule detects two types of violations:
//  1. Line-level: Tabs and spaces mixed on the same line's indentation
//  2. File-level: Different lines using different indentation styles
//
// Auto-fix converts all indentation to spaces (4 spaces per tab).
//
// Returns a configured MixedIndentationRule ready for use with the linter.
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

// Check performs the mixed indentation check on SQL content.
//
// The check works in two phases:
//  1. Detects lines with both tabs and spaces in leading whitespace
//  2. Tracks first indentation type seen and reports inconsistency with that style
//
// Only leading whitespace (indentation) is checked; tabs and spaces after content
// are not considered violations.
//
// Returns a slice of violations (one per inconsistent line) and nil error.
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

// Fix converts all indentation to spaces (4 spaces per tab).
//
// Processes each line by replacing tabs with 4 spaces in the leading whitespace only.
// Tabs that appear after non-whitespace content (e.g., inside string literals or
// after SQL keywords) are preserved unchanged.
//
// This is a safe, idempotent transformation that doesn't affect SQL semantics.
//
// Returns the fixed content with consistent space-based indentation, and nil error.
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

// getLeadingWhitespace extracts the leading whitespace characters from a line.
//
// Returns all consecutive spaces and tabs from the start of the line until the
// first non-whitespace character. If the entire line is whitespace, returns the
// full line.
func getLeadingWhitespace(line string) string {
	for i, char := range line {
		if char != ' ' && char != '\t' {
			return line[:i]
		}
	}
	return line // Entire line is whitespace
}
