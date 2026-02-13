package style

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ColumnAlignmentRule (L006) checks for proper column alignment in multi-line
// SELECT statements.
//
// Misaligned columns in SELECT lists reduce readability and make it harder to
// understand column relationships. This rule detects columns that don't align
// with the majority alignment pattern in each SELECT statement.
//
// Rule ID: L006
// Severity: Info
// Auto-fix: Not supported (requires complex formatting logic)
//
// Example violation:
//
//	SELECT
//	    user_id,
//	  username,      <- Not aligned with user_id (violation)
//	    email,
//	    created_at
//	FROM users
//
// Expected output:
//
//	SELECT
//	    user_id,
//	    username,      <- Now aligned
//	    email,
//	    created_at
//	FROM users
//
// The rule finds the most common indentation level among columns and reports
// columns that deviate from this pattern.
type ColumnAlignmentRule struct {
	linter.BaseRule
}

// NewColumnAlignmentRule creates a new L006 rule instance.
//
// Returns a configured ColumnAlignmentRule ready for use with the linter.
// The rule does not support auto-fix due to the complexity of preserving
// formatting while adjusting indentation.
func NewColumnAlignmentRule() *ColumnAlignmentRule {
	return &ColumnAlignmentRule{
		BaseRule: linter.NewBaseRule(
			"L006",
			"Column Alignment",
			"SELECT columns should be properly aligned",
			linter.SeverityInfo,
			false, // No auto-fix - complex formatting
		),
	}
}

// Check performs the column alignment check on SQL content.
//
// Scans through lines identifying SELECT statements and tracking column indentation
// in multi-line SELECT lists. Computes the most common (mode) indentation level
// among columns and reports any columns that don't match this alignment.
//
// Only multi-line SELECT statements with 2+ columns are checked. Single-line SELECT
// and single-column SELECT statements don't have alignment issues.
//
// Returns a slice of violations (one per misaligned column) and nil error.
func (r *ColumnAlignmentRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	// Find SELECT statements and check their column alignment
	inSelectColumns := false
	selectLineNum := 0
	columnIndents := []int{}
	columnLines := []int{}

	for lineNum, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		// Detect start of SELECT
		if strings.HasPrefix(upper, "SELECT") {
			inSelectColumns = true
			selectLineNum = lineNum + 1
			columnIndents = []int{}
			columnLines = []int{}

			// Check if columns are on same line or start of multi-line
			afterSelect := strings.TrimPrefix(trimmed[6:], " ")
			if afterSelect != "" && !strings.HasPrefix(strings.ToUpper(afterSelect), "DISTINCT") {
				// Columns start on SELECT line
				indent := getIndentSize(line) + 7 // SELECT + space
				if strings.HasPrefix(upper, "SELECT DISTINCT") {
					indent = getIndentSize(line) + 16 // SELECT DISTINCT + space
				}
				columnIndents = append(columnIndents, indent)
				columnLines = append(columnLines, lineNum+1)
			}
			continue
		}

		// Check for end of SELECT columns
		if inSelectColumns {
			if strings.HasPrefix(upper, "FROM") ||
				strings.HasPrefix(upper, "WHERE") ||
				strings.HasPrefix(upper, "JOIN") ||
				strings.HasPrefix(upper, "ORDER") ||
				strings.HasPrefix(upper, "GROUP") ||
				strings.HasPrefix(upper, ";") ||
				trimmed == "" {
				// End of columns, check alignment
				if len(columnIndents) > 1 {
					violations = append(violations, r.checkColumnAlignment(columnIndents, columnLines, selectLineNum, ctx)...)
				}
				inSelectColumns = false
				continue
			}

			// This line has columns
			indent := getIndentSize(line)
			columnIndents = append(columnIndents, indent)
			columnLines = append(columnLines, lineNum+1)
		}
	}

	// Handle case where SELECT is at end of file
	if inSelectColumns && len(columnIndents) > 1 {
		violations = append(violations, r.checkColumnAlignment(columnIndents, columnLines, selectLineNum, ctx)...)
	}

	return violations, nil
}

// checkColumnAlignment checks if columns in a SELECT are properly aligned.
//
// Calculates the most common indentation level (mode) among columns and reports
// columns that don't match this level. The first column is skipped as it may
// appear on the SELECT line with different indentation.
//
// Returns a slice of violations for misaligned columns.
func (r *ColumnAlignmentRule) checkColumnAlignment(indents []int, lines []int, _ int, ctx *linter.Context) []linter.Violation {
	violations := []linter.Violation{}

	if len(indents) < 2 {
		return violations
	}

	// Find the most common indent (mode)
	indentCounts := make(map[int]int)
	for _, indent := range indents[1:] { // Skip first column (might be on SELECT line)
		indentCounts[indent]++
	}

	var expectedIndent int
	maxCount := 0
	for indent, count := range indentCounts {
		if count > maxCount {
			maxCount = count
			expectedIndent = indent
		}
	}

	// Report misaligned columns
	for i, indent := range indents[1:] { // Skip first column
		if indent != expectedIndent {
			lineNum := lines[i+1]
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Column not aligned with other columns",
				Location:   models.Location{Line: lineNum, Column: indent + 1},
				Line:       ctx.GetLine(lineNum),
				Suggestion: "Align column to match other columns in the SELECT list",
				CanAutoFix: false,
			})
		}
	}

	return violations
}

// getIndentSize calculates the indentation size of a line.
//
// Counts leading spaces (1 each) and tabs (4 each) to compute total indentation.
// Stops at the first non-whitespace character.
//
// Returns the total indentation size in space-equivalent units.
func getIndentSize(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 4 // Treat tab as 4 spaces
		default:
			return count
		}
	}
	return count
}

// Fix is not supported for this rule as it requires complex formatting logic.
//
// Auto-fixing column alignment would require:
//   - Understanding SELECT clause structure
//   - Preserving comments and inline formatting
//   - Choosing appropriate indentation levels
//   - Handling edge cases (subqueries, CASE expressions, etc.)
//
// These decisions are best made by developers using a dedicated SQL formatter.
//
// Returns the content unchanged with nil error.
func (r *ColumnAlignmentRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
