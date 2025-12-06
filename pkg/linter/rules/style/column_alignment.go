package style

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ColumnAlignmentRule checks for proper column alignment in SELECT statements
type ColumnAlignmentRule struct {
	linter.BaseRule
}

// NewColumnAlignmentRule creates a new L006 rule instance
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

// Check performs the column alignment check
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

// checkColumnAlignment checks if columns are properly aligned
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

// getIndentSize returns the number of leading spaces/tabs in a line
func getIndentSize(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 4 // Treat tab as 4 spaces
		} else {
			break
		}
	}
	return count
}

// Fix is not supported for this rule
func (r *ColumnAlignmentRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
