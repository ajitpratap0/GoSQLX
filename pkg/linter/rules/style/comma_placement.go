package style

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// CommaStyle represents the preferred comma placement style
type CommaStyle string

const (
	// CommaTrailing means commas at end of lines: col1,
	CommaTrailing CommaStyle = "trailing"
	// CommaLeading means commas at start of lines: , col1
	CommaLeading CommaStyle = "leading"
)

// CommaPlacementRule checks for consistent comma placement
type CommaPlacementRule struct {
	linter.BaseRule
	preferredStyle CommaStyle
}

// NewCommaPlacementRule creates a new L008 rule instance
func NewCommaPlacementRule(preferredStyle CommaStyle) *CommaPlacementRule {
	if preferredStyle == "" {
		preferredStyle = CommaTrailing // Default to trailing commas
	}
	return &CommaPlacementRule{
		BaseRule: linter.NewBaseRule(
			"L008",
			"Comma Placement",
			"Commas should be placed consistently (trailing or leading)",
			linter.SeverityInfo,
			false, // No auto-fix - requires careful restructuring
		),
		preferredStyle: preferredStyle,
	}
}

// Check performs the comma placement check
func (r *CommaPlacementRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	// Enforce the user's preferred style
	enforceStyle := r.preferredStyle

	// Scan lines for comma placement violations
	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Skip lines that are only commas or don't contain commas
		if !strings.Contains(trimmed, ",") || trimmed == "," {
			continue
		}

		hasLeading := strings.HasPrefix(trimmed, ",")
		hasTrailing := strings.HasSuffix(trimmed, ",")

		if enforceStyle == CommaTrailing && hasLeading {
			// Find column of leading comma
			col := strings.Index(line, ",") + 1
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Leading comma found, but trailing comma style is preferred",
				Location:   models.Location{Line: lineNum + 1, Column: col},
				Line:       line,
				Suggestion: "Move comma to end of previous line",
				CanAutoFix: false,
			})
		}

		if enforceStyle == CommaLeading && hasTrailing && lineNum < len(ctx.Lines)-1 {
			// Only flag trailing commas if there's a next line
			nextLine := ""
			if lineNum+1 < len(ctx.Lines) {
				nextLine = strings.TrimSpace(ctx.Lines[lineNum+1])
			}

			// Don't flag if next line starts with a keyword (new clause)
			if isNewClause(nextLine) {
				continue
			}

			// Find column of trailing comma
			col := strings.LastIndex(line, ",") + 1
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Trailing comma found, but leading comma style is preferred",
				Location:   models.Location{Line: lineNum + 1, Column: col},
				Line:       line,
				Suggestion: "Move comma to start of next line",
				CanAutoFix: false,
			})
		}
	}

	return violations, nil
}

// isNewClause checks if a line starts with a SQL clause keyword
func isNewClause(line string) bool {
	line = strings.ToUpper(strings.TrimSpace(line))
	clauses := []string{"SELECT", "FROM", "WHERE", "AND", "OR", "JOIN", "LEFT", "RIGHT",
		"INNER", "OUTER", "CROSS", "ON", "ORDER", "GROUP", "HAVING", "LIMIT", "OFFSET",
		"UNION", "EXCEPT", "INTERSECT", "VALUES", "SET", "RETURNING"}

	for _, clause := range clauses {
		if strings.HasPrefix(line, clause) {
			return true
		}
	}
	return false
}

// Fix is not supported for this rule (requires careful restructuring)
func (r *CommaPlacementRule) Fix(content string, violations []linter.Violation) (string, error) {
	// No auto-fix available
	return content, nil
}
