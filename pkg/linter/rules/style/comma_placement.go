package style

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// CommaStyle represents the preferred comma placement style in multi-line lists.
type CommaStyle string

const (
	// CommaTrailing places commas at the end of lines (traditional style).
	// Example:
	//   SELECT
	//       column1,
	//       column2,
	//       column3
	//   FROM table
	CommaTrailing CommaStyle = "trailing"

	// CommaLeading places commas at the start of lines (modern style).
	// Example:
	//   SELECT
	//       column1
	//       , column2
	//       , column3
	//   FROM table
	CommaLeading CommaStyle = "leading"
)

// CommaPlacementRule (L008) enforces consistent comma placement style.
//
// Inconsistent comma placement reduces readability and makes it harder to scan
// column lists or value lists. This rule detects commas that don't match the
// configured placement style.
//
// Rule ID: L008
// Severity: Info
// Auto-fix: Not supported (requires multi-line restructuring)
//
// Example violation (CommaTrailing style):
//
//	SELECT
//	    user_id
//	    , username     <- Leading comma (violation)
//	    , email
//	FROM users
//
// Expected output:
//
//	SELECT
//	    user_id,       <- Trailing comma
//	    username,
//	    email
//	FROM users
//
// The rule checks commas in SELECT columns, INSERT value lists, and other
// comma-separated contexts.
type CommaPlacementRule struct {
	linter.BaseRule
	preferredStyle CommaStyle
}

// NewCommaPlacementRule creates a new L008 rule instance.
//
// Parameters:
//   - preferredStyle: CommaTrailing or CommaLeading (defaults to CommaTrailing if empty)
//
// Returns a configured CommaPlacementRule ready for use with the linter.
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

// Check performs the comma placement check on SQL content.
//
// Scans each line for leading or trailing commas and reports violations when they
// don't match the preferred style. Lines starting with SQL keywords (FROM, WHERE,
// etc.) are skipped as they indicate new clauses rather than continuation lines.
//
// Returns a slice of violations (one per misplaced comma) and nil error.
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

// isNewClause checks if a line starts with a SQL clause keyword.
//
// Tests whether the line begins with keywords like SELECT, FROM, WHERE, JOIN, etc.
// that indicate the start of a new SQL clause rather than a continuation of a
// comma-separated list.
//
// Returns true if the line starts with a clause keyword, false otherwise.
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

// Fix is not supported for this rule as it requires multi-line restructuring.
//
// Auto-fixing comma placement would require:
//   - Moving commas between lines while preserving formatting
//   - Handling comments that may appear before/after commas
//   - Understanding list context (SELECT columns vs INSERT values vs function args)
//   - Adjusting whitespace appropriately
//
// These transformations are complex and best performed by developers or dedicated
// SQL formatters that understand full query structure.
//
// Returns the content unchanged with nil error.
func (r *CommaPlacementRule) Fix(content string, violations []linter.Violation) (string, error) {
	// No auto-fix available
	return content, nil
}
