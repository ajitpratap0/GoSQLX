package whitespace

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// IndentationDepthRule checks for excessive indentation depth
type IndentationDepthRule struct {
	linter.BaseRule
	maxDepth   int
	indentSize int // Size of one indentation level (default 4)
}

// NewIndentationDepthRule creates a new L004 rule instance
func NewIndentationDepthRule(maxDepth int, indentSize int) *IndentationDepthRule {
	if maxDepth < 1 {
		maxDepth = 4 // Default max depth
	}
	if indentSize < 1 {
		indentSize = 4 // Default indent size
	}
	return &IndentationDepthRule{
		BaseRule: linter.NewBaseRule(
			"L004",
			"Indentation Depth",
			"Excessive indentation depth may indicate overly complex queries",
			linter.SeverityWarning,
			false, // No auto-fix - requires query restructuring
		),
		maxDepth:   maxDepth,
		indentSize: indentSize,
	}
}

// Check performs the indentation depth check
func (r *IndentationDepthRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Calculate indentation depth
		depth := r.calculateIndentDepth(line)

		if depth > r.maxDepth {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    fmt.Sprintf("Indentation depth exceeds maximum: %d levels (max %d)", depth, r.maxDepth),
				Location:   models.Location{Line: lineNum + 1, Column: 1},
				Line:       line,
				Suggestion: "Consider simplifying the query or breaking it into smaller parts",
				CanAutoFix: false,
			})
		}
	}

	return violations, nil
}

// calculateIndentDepth calculates the indentation depth of a line
func (r *IndentationDepthRule) calculateIndentDepth(line string) int {
	spaces := 0
	tabs := 0

	for _, ch := range line {
		if ch == ' ' {
			spaces++
		} else if ch == '\t' {
			tabs++
		} else {
			break
		}
	}

	// Calculate total depth: tabs count as full indents, spaces as partial
	totalSpaces := tabs*r.indentSize + spaces
	return totalSpaces / r.indentSize
}

// Fix is not supported for this rule (requires query restructuring)
func (r *IndentationDepthRule) Fix(content string, violations []linter.Violation) (string, error) {
	// No auto-fix available for indentation depth
	return content, nil
}
