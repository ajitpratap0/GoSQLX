package whitespace

import (
	"regexp"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// RedundantWhitespaceRule checks for redundant/excessive whitespace
type RedundantWhitespaceRule struct {
	linter.BaseRule
}

// Pre-compiled regex patterns for performance
var (
	multipleSpacesRegex = regexp.MustCompile(`  +`) // Two or more consecutive spaces
)

// NewRedundantWhitespaceRule creates a new L010 rule instance
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

// Check performs the redundant whitespace check
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

// linePart represents a non-string portion of a line
type linePart struct {
	text     string
	startCol int // 0-indexed position in original line
}

// extractNonStringParts extracts parts of a line that are not inside string literals
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

// Fix removes redundant whitespace
func (r *RedundantWhitespaceRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lines[i] = r.fixLine(line)
	}

	return strings.Join(lines, "\n"), nil
}

// fixLine reduces multiple spaces to single space, preserving strings and indentation
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
