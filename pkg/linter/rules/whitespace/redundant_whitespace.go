// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whitespace

import (
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
// Scans each line for runs of 2+ ASCII spaces outside single and double quotes.
// Runs starting at byte zero are indentation and are skipped. Columns are byte
// positions, including when the input contains invalid UTF-8.
//
// Returns a slice of violations (one per redundant whitespace sequence) and nil error.
func (r *RedundantWhitespaceRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		// Single pass over the non-string parts of the line: a run of two or
		// more spaces outside quotes is a violation unless it starts the line
		// (indentation). Runs never span a quoted string.
		inString := false
		var quote byte
		runStart := -1
		report := func(end int) {
			if runStart >= 0 && end-runStart >= 2 && runStart != 0 {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Multiple consecutive spaces found",
					Location:   models.Location{Line: lineNum + 1, Column: runStart + 1}, // 1-indexed
					Line:       line,
					Suggestion: "Reduce to single space",
					CanAutoFix: true,
				})
			}
			runStart = -1
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if inString {
				if c == quote {
					inString = false
				}
				continue
			}
			switch c {
			case '\'', '"':
				report(i)
				inString = true
				quote = c
			case ' ':
				if runStart < 0 {
					runStart = i
				}
			default:
				report(i)
			}
		}
		if !inString {
			report(len(line))
		}
	}

	return violations, nil
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
