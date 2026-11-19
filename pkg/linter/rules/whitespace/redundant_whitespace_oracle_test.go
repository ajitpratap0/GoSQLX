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

package whitespace_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Frozen pre-byte-scan implementation, including its invalid UTF-8 column bug.
var multipleSpacesRegex = regexp.MustCompile(`  +`)

func oldRedundantWhitespaceCheck(r *whitespace.RedundantWhitespaceRule, ctx *linter.Context) ([]linter.Violation, error) {
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

func TestExtractNonStringParts(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectedParts int
	}{
		{
			name:          "No strings",
			line:          "SELECT id FROM users",
			expectedParts: 1,
		},
		{
			name:          "Single quoted string",
			line:          "SELECT 'hello' FROM users",
			expectedParts: 2, // "SELECT " and " FROM users"
		},
		{
			name:          "Double quoted string",
			line:          `SELECT "hello" FROM users`,
			expectedParts: 2,
		},
		{
			name:          "Multiple strings",
			line:          "SELECT 'hello', 'world' FROM users",
			expectedParts: 3, // "SELECT ", ", ", " FROM users"
		},
		{
			name:          "Empty line",
			line:          "",
			expectedParts: 0,
		},
		{
			name:          "Only string",
			line:          "'hello world'",
			expectedParts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := extractNonStringParts(tt.line)
			if len(parts) != tt.expectedParts {
				t.Errorf("Expected %d parts, got %d: %+v", tt.expectedParts, len(parts), parts)
			}
		})
	}
}
