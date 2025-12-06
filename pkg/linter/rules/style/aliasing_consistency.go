package style

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AliasStyle represents the preferred alias style
type AliasStyle string

const (
	// AliasExplicit requires explicit AS keyword: table AS t
	AliasExplicit AliasStyle = "explicit"
	// AliasImplicit allows implicit aliases: table t
	AliasImplicit AliasStyle = "implicit"
)

// AliasingConsistencyRule checks for consistent aliasing patterns
type AliasingConsistencyRule struct {
	linter.BaseRule
	preferExplicitAS bool
}

// NewAliasingConsistencyRule creates a new L009 rule instance
func NewAliasingConsistencyRule(preferExplicitAS bool) *AliasingConsistencyRule {
	return &AliasingConsistencyRule{
		BaseRule: linter.NewBaseRule(
			"L009",
			"Aliasing Consistency",
			"Table and column aliases should be used consistently",
			linter.SeverityWarning,
			false, // No auto-fix - requires careful analysis
		),
		preferExplicitAS: preferExplicitAS,
	}
}

// Check performs the aliasing consistency check
func (r *AliasingConsistencyRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	// Check if we have AST available
	if ctx.AST == nil || ctx.ParseErr != nil {
		// Fall back to text-based analysis
		return r.checkTextBased(ctx)
	}

	// AST-based analysis
	return r.checkASTBased(ctx)
}

// checkTextBased performs text-based alias checking
func (r *AliasingConsistencyRule) checkTextBased(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	// Track aliases defined vs aliases used
	definedAliases := make(map[string]int)     // alias -> line defined
	fullTableNames := make(map[string]int)     // table name -> line defined
	usedQualifiedRefs := make(map[string]bool) // table.column references

	// First pass: find alias definitions
	for lineNum, line := range ctx.Lines {
		upper := strings.ToUpper(line)

		// Look for FROM/JOIN table alias patterns
		// Pattern: FROM tablename [AS] alias or JOIN tablename [AS] alias
		if strings.Contains(upper, "FROM") || strings.Contains(upper, "JOIN") {
			parts := tokenizeForAliases(line)
			for i, part := range parts {
				upperPart := strings.ToUpper(part)
				if upperPart == "FROM" || strings.HasSuffix(upperPart, "JOIN") {
					// Next word is table name, word after might be alias
					if i+1 < len(parts) {
						tableName := parts[i+1]
						fullTableNames[tableName] = lineNum + 1

						// Check if there's an AS keyword or implicit alias
						if i+2 < len(parts) {
							nextPart := strings.ToUpper(parts[i+2])
							if nextPart == "AS" {
								if i+3 < len(parts) {
									alias := parts[i+3]
									definedAliases[alias] = lineNum + 1
								}
							} else if nextPart != "ON" && nextPart != "WHERE" && nextPart != "JOIN" &&
								nextPart != "LEFT" && nextPart != "RIGHT" && nextPart != "INNER" &&
								nextPart != "OUTER" && nextPart != "CROSS" && nextPart != "," {
								// Implicit alias
								alias := parts[i+2]
								definedAliases[alias] = lineNum + 1
							}
						}
					}
				}
			}
		}
	}

	// Second pass: find qualified references (table.column)
	for _, line := range ctx.Lines {
		// Find patterns like table.column or alias.column
		parts := tokenizeForAliases(line)
		for _, part := range parts {
			if strings.Contains(part, ".") {
				dotParts := strings.Split(part, ".")
				if len(dotParts) == 2 {
					qualifier := dotParts[0]
					usedQualifiedRefs[qualifier] = true
				}
			}
		}
	}

	// Check for inconsistency: using full table names and aliases mixed
	for tableName, definedLine := range fullTableNames {
		// Check if this table has an alias
		hasAlias := false
		for alias := range definedAliases {
			// Simple heuristic: alias is short, table name is long
			if len(alias) < len(tableName) {
				hasAlias = true
				break
			}
		}

		// Check if table name is used in qualified references
		if usedQualifiedRefs[tableName] && hasAlias {
			violations = append(violations, linter.Violation{
				Rule:       r.ID(),
				RuleName:   r.Name(),
				Severity:   r.Severity(),
				Message:    "Mixed use of table name '" + tableName + "' and aliases",
				Location:   models.Location{Line: definedLine, Column: 1},
				Line:       ctx.GetLine(definedLine),
				Suggestion: "Use the alias consistently throughout the query",
				CanAutoFix: false,
			})
		}
	}

	return violations, nil
}

// checkASTBased performs AST-based alias checking
func (r *AliasingConsistencyRule) checkASTBased(ctx *linter.Context) ([]linter.Violation, error) {
	astViolations := []linter.Violation{}

	// Walk the AST to find aliasing patterns
	for _, stmt := range ctx.AST.Statements {
		if selectStmt, ok := stmt.(*ast.SelectStatement); ok {
			stmtViolations := r.checkSelectStatement(selectStmt, ctx)
			astViolations = append(astViolations, stmtViolations...)
		}
	}

	return astViolations, nil
}

// checkSelectStatement checks a SELECT statement for aliasing consistency
func (r *AliasingConsistencyRule) checkSelectStatement(stmt *ast.SelectStatement, ctx *linter.Context) []linter.Violation {
	stmtViolations := []linter.Violation{}

	// Collect all table aliases and names
	tableAliases := make(map[string]string) // alias -> table name
	tableNames := make(map[string]bool)     // table names without aliases

	// Check FROM clause - From is []TableReference (not []Expression)
	for i := range stmt.From {
		tableRef := &stmt.From[i]
		if tableRef.Alias != "" {
			tableAliases[tableRef.Alias] = tableRef.Name
		} else if tableRef.Name != "" {
			tableNames[tableRef.Name] = true
		}
	}

	// Check JOINs - JoinClause has Left and Right TableReference fields
	for i := range stmt.Joins {
		join := &stmt.Joins[i]
		// Check the Right side of the join (the table being joined)
		if join.Right.Alias != "" {
			tableAliases[join.Right.Alias] = join.Right.Name
		} else if join.Right.Name != "" {
			tableNames[join.Right.Name] = true
		}
	}

	// Check if there are both aliased and non-aliased tables
	if len(tableAliases) > 0 && len(tableNames) > 0 {
		stmtViolations = append(stmtViolations, linter.Violation{
			Rule:       r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    "Some tables have aliases while others don't",
			Location:   models.Location{Line: 1, Column: 1},
			Line:       ctx.GetLine(1),
			Suggestion: "Use aliases consistently for all tables in the query",
			CanAutoFix: false,
		})
	}

	return stmtViolations
}

// tokenizeForAliases extracts words from a line for alias analysis
func tokenizeForAliases(line string) []string {
	words := []string{}
	inString := false
	stringChar := rune(0)
	currentWord := strings.Builder{}

	for _, ch := range line {
		// Handle string literals
		if !inString && (ch == '\'' || ch == '"') {
			if currentWord.Len() > 0 {
				words = append(words, currentWord.String())
				currentWord.Reset()
			}
			inString = true
			stringChar = ch
			continue
		}

		if inString {
			if ch == stringChar {
				inString = false
				stringChar = 0
			}
			continue
		}

		// Word boundaries
		if ch == ' ' || ch == '\t' || ch == ',' || ch == '(' || ch == ')' || ch == ';' {
			if currentWord.Len() > 0 {
				words = append(words, currentWord.String())
				currentWord.Reset()
			}
			// Keep comma as a token
			if ch == ',' {
				words = append(words, ",")
			}
		} else {
			currentWord.WriteRune(ch)
		}
	}

	if currentWord.Len() > 0 {
		words = append(words, currentWord.String())
	}

	return words
}

// Fix is not supported for this rule
func (r *AliasingConsistencyRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
