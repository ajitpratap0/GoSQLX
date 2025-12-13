package whitespace

import (
	"regexp"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// RedundantWhitespaceRule (L010) detects and removes multiple consecutive spaces
// outside of string literals and indentation.
//
// Inconsistent spacing between SQL keywords and identifiers reduces readability and
// can indicate careless formatting. This rule enforces single-space separation while
// preserving intentional spacing in string literals and line indentation.
//
// Rule ID: L010
// Severity: Info
// Auto-fix: Supported
//
// Example violations:
//
//	SELECT  *  FROM  users   <- Multiple spaces between keywords (violation)
//	WHERE  status  =  'active'
//
// Fixed output:
//
//	SELECT * FROM users      <- Single spaces
//	WHERE status = 'active'
//
// The rule preserves:
//   - Leading indentation (not considered redundant)
//   - Spaces inside string literals ('multiple  spaces')
//   - Tabs (not replaced, only consecutive spaces are affected)
type RedundantWhitespaceRule struct {
	linter.BaseRule
}

// Pre-compiled regex patterns for performance
var (
	multipleSpacesRegex = regexp.MustCompile(`  +`) // Two or more consecutive spaces
)

// NewRedundantWhitespaceRule creates a new L010 rule instance.
//
// The rule detects sequences of 2 or more consecutive spaces outside of string
// literals and indentation, supporting automatic fixing by reducing them to single
// spaces.
//
// Returns a configured RedundantWhitespaceRule ready for use with the linter.
func NewRedundantWhitespaceRule() *RedundantWhitespaceRule {
	return &RedundantWhitespaceRule{
		BaseRule: linter.NewBaseRule(
			"L010",
			"Redundant Whitespace",
			"Multiple consecutive spaces should be reduced to single space",
			linter.SeverityInfo,
			true, // Supports auto-fix
		),
	}
}

// Check performs the redundant whitespace check on SQL content.
//
// Extracts non-string portions of each line and searches for sequences of 2+ spaces
// using regex pattern matching. Leading whitespace (indentation) is skipped. For
// each match, a violation is reported.
//
// Returns a slice of violations (one per redundant whitespace sequence) and nil error.
func (r *RedundantWhitespaceRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		// Skip checking inside string literals - we'll check the non-string parts
		parts := extractNonStringParts(line)

		for _, part := range parts {
			// Check for multiple consecutive spaces (not at line start - indentation)
			matches := multipleSpacesRegex.FindAllStringIndex(part.text, -1)
			for _, match := range matches {
				// Calculate actual column in original line
				column := part.startCol + match[0] + 1 // 1-indexed

				// Skip if this is at the beginning of line (indentation)
				if part.startCol == 0 && match[0] == 0 {
					// Check if it's leading whitespace on the line
					if strings.TrimLeft(line[:column], " \t") == "" {
						continue // Skip leading indentation
					}
				}

				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Multiple consecutive spaces found",
					Location:   models.Location{Line: lineNum + 1, Column: column},
					Line:       line,
					Suggestion: "Reduce to single space",
					CanAutoFix: true,
				})
			}
		}
	}

	return violations, nil
}

// linePart represents a non-string portion of a line with its position.
type linePart struct {
	text     string
	startCol int // 0-indexed position in original line
}

// extractNonStringParts extracts parts of a line outside of string literals.
//
// Parses the line character by character, tracking single and double quoted strings.
// Returns slices of text that are not inside quotes, along with their starting
// column positions in the original line.
//
// This ensures redundant whitespace inside strings like 'multiple  spaces' is
// preserved and not flagged as violations.
func extractNonStringParts(line string) []linePart {
	parts := []linePart{}
	inString := false
	stringChar := rune(0)
	partStart := 0
	currentPart := strings.Builder{}

	for i, ch := range line {
		if !inString && (ch == '\'' || ch == '"') {
			// Save current non-string part
			if currentPart.Len() > 0 {
				parts = append(parts, linePart{
					text:     currentPart.String(),
					startCol: partStart,
				})
				currentPart.Reset()
			}
			inString = true
			stringChar = ch
			continue
		}

		if inString {
			if ch == stringChar {
				inString = false
				stringChar = 0
				partStart = i + 1
			}
			continue
		}

		if currentPart.Len() == 0 {
			partStart = i
		}
		currentPart.WriteRune(ch)
	}

	// Add final part
	if currentPart.Len() > 0 {
		parts = append(parts, linePart{
			text:     currentPart.String(),
			startCol: partStart,
		})
	}

	return parts
}

// Fix removes redundant whitespace from SQL content.
//
// Processes content line by line, reducing multiple consecutive spaces to single
// spaces while preserving leading indentation and spaces inside string literals.
//
// Returns the fixed content with redundant whitespace removed, and nil error.
func (r *RedundantWhitespaceRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lines[i] = r.fixLine(line)
	}

	return strings.Join(lines, "\n"), nil
}

// fixLine reduces multiple spaces to single space in a line.
//
// Preserves leading whitespace (indentation) and spaces inside string literals
// (both single and double quoted). Uses state machine to track whether currently
// inside a string.
//
// Returns the fixed line with redundant whitespace removed.
func (r *RedundantWhitespaceRule) fixLine(line string) string {
	// Preserve leading whitespace (indentation)
	leading := ""
	trimmed := line
	for i, ch := range line {
		if ch != ' ' && ch != '\t' {
			leading = line[:i]
			trimmed = line[i:]
			break
		}
	}

	// Process the rest of the line, preserving strings
	result := strings.Builder{}
	result.WriteString(leading)

	inString := false
	stringChar := rune(0)
	prevSpace := false

	for _, ch := range trimmed {
		if !inString && (ch == '\'' || ch == '"') {
			inString = true
			stringChar = ch
			result.WriteRune(ch)
			prevSpace = false
			continue
		}

		if inString {
			result.WriteRune(ch)
			if ch == stringChar {
				inString = false
				stringChar = 0
			}
			continue
		}

		// Reduce multiple spaces to single space
		if ch == ' ' {
			if !prevSpace {
				result.WriteRune(ch)
			}
			prevSpace = true
		} else {
			result.WriteRune(ch)
			prevSpace = false
		}
	}

	return result.String()
}
