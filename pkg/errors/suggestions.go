package errors

import (
	"fmt"
	"regexp"
	"strings"
)

// ErrorPattern represents a common SQL error pattern with suggestions
type ErrorPattern struct {
	Pattern     *regexp.Regexp
	Description string
	Suggestion  string
}

// Common error patterns with helpful suggestions
var errorPatterns = []ErrorPattern{
	{
		Pattern:     regexp.MustCompile(`(?i)expected\s+FROM.*got\s+'?([A-Za-z]+)'?`),
		Description: "Common typo in FROM keyword",
		Suggestion:  "Check spelling of SQL keywords (e.g., FORM → FROM)",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)expected\s+SELECT.*got\s+'?([A-Za-z]+)'?`),
		Description: "Common typo in SELECT keyword",
		Suggestion:  "Check spelling of SELECT keyword (e.g., SELCT → SELECT)",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)expected\s+WHERE.*got\s+'?([A-Za-z]+)'?`),
		Description: "Common typo in WHERE keyword",
		Suggestion:  "Check spelling of WHERE keyword (e.g., WAHER → WHERE)",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)unterminated\s+string`),
		Description: "Missing closing quote in string literal",
		Suggestion:  "Ensure all string literals are properly closed with matching quotes (' or \")",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)invalid\s+numeric\s+literal.*\d+\.\d+\.\d+`),
		Description: "Multiple decimal points in number",
		Suggestion:  "Numbers can only have one decimal point (e.g., 123.45)",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)unexpected\s+token.*STRING`),
		Description: "String literal where identifier expected",
		Suggestion:  "Use identifiers without quotes or use proper escaping for column/table names",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)missing.*FROM\s+clause`),
		Description: "Missing FROM clause in SELECT",
		Suggestion:  "SELECT statements require FROM clause: SELECT columns FROM table",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)incomplete.*statement`),
		Description: "SQL statement is incomplete",
		Suggestion:  "Check for missing clauses, closing parentheses, or semicolons",
	},
}

// MistakePattern represents common SQL mistakes with explanations
type MistakePattern struct {
	Name        string
	Example     string // Example of the mistake
	Correct     string // Correct version
	Explanation string
}

// Common SQL mistakes
var commonMistakes = []MistakePattern{
	{
		Name:        "string_instead_of_number",
		Example:     "WHERE age > '18'",
		Correct:     "WHERE age > 18",
		Explanation: "Numeric comparisons should use numbers without quotes",
	},
	{
		Name:        "missing_comma_in_list",
		Example:     "SELECT id name FROM users",
		Correct:     "SELECT id, name FROM users",
		Explanation: "Separate column names with commas in SELECT list",
	},
	{
		Name:        "equals_instead_of_like",
		Example:     "WHERE name = '%John%'",
		Correct:     "WHERE name LIKE '%John%'",
		Explanation: "Use LIKE operator for pattern matching with wildcards",
	},
	{
		Name:        "missing_join_condition",
		Example:     "FROM users JOIN orders",
		Correct:     "FROM users JOIN orders ON users.id = orders.user_id",
		Explanation: "JOIN clauses require ON or USING condition",
	},
	{
		Name:        "ambiguous_column",
		Example:     "SELECT id FROM users, orders WHERE id > 10",
		Correct:     "SELECT users.id FROM users, orders WHERE users.id > 10",
		Explanation: "Qualify column names when they appear in multiple tables",
	},
	{
		Name:        "wrong_aggregate_syntax",
		Example:     "SELECT COUNT * FROM users",
		Correct:     "SELECT COUNT(*) FROM users",
		Explanation: "Aggregate functions require parentheses around arguments",
	},
	{
		Name:        "missing_group_by",
		Example:     "SELECT dept, COUNT(*) FROM employees",
		Correct:     "SELECT dept, COUNT(*) FROM employees GROUP BY dept",
		Explanation: "Non-aggregated columns in SELECT must appear in GROUP BY",
	},
	{
		Name:        "having_without_group_by",
		Example:     "SELECT * FROM users HAVING COUNT(*) > 5",
		Correct:     "SELECT dept, COUNT(*) FROM users GROUP BY dept HAVING COUNT(*) > 5",
		Explanation: "HAVING clause requires GROUP BY (use WHERE for non-aggregated filters)",
	},
	{
		Name:        "order_by_aggregate_without_select",
		Example:     "SELECT name FROM users ORDER BY COUNT(*)",
		Correct:     "SELECT name, COUNT(*) FROM users GROUP BY name ORDER BY COUNT(*)",
		Explanation: "Aggregates in ORDER BY should appear in SELECT list",
	},
	{
		Name:        "multiple_aggregation_levels",
		Example:     "SELECT AVG(COUNT(*)) FROM users",
		Correct:     "SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM users GROUP BY dept) t",
		Explanation: "Use subquery to aggregate aggregates",
	},
}

// SuggestFromPattern tries to match error message against known patterns
func SuggestFromPattern(errorMessage string) string {
	for _, pattern := range errorPatterns {
		if pattern.Pattern.MatchString(errorMessage) {
			return pattern.Suggestion
		}
	}
	return ""
}

// GetMistakeExplanation returns explanation for a common mistake
func GetMistakeExplanation(mistakeName string) (MistakePattern, bool) {
	for _, mistake := range commonMistakes {
		if mistake.Name == mistakeName {
			return mistake, true
		}
	}
	return MistakePattern{}, false
}

// AnalyzeTokenError analyzes token-based errors and provides context-aware suggestions
func AnalyzeTokenError(tokenType, tokenValue, expectedType string) string {
	// String literal where number expected
	if tokenType == "STRING" && (expectedType == "NUMBER" || expectedType == "INTEGER") {
		return fmt.Sprintf("Expected a number but found a string literal '%s'. Remove the quotes if this should be numeric.", tokenValue)
	}

	// Number where string expected
	if tokenType == "NUMBER" && expectedType == "STRING" {
		return fmt.Sprintf("Expected a string but found a number %s. Add quotes if this should be a string literal.", tokenValue)
	}

	// Identifier issues
	if tokenType == "IDENT" {
		suggestion := SuggestKeyword(tokenValue)
		if suggestion != "" && suggestion != strings.ToUpper(tokenValue) {
			return fmt.Sprintf("Unknown identifier '%s'. Did you mean the keyword '%s'?", tokenValue, suggestion)
		}
	}

	// Missing operator between tokens
	if tokenType == "IDENT" && expectedType == "OPERATOR" {
		return "Expected an operator (=, <, >, AND, OR, etc.) between expressions."
	}

	// Unclosed parenthesis
	if tokenType == "EOF" && expectedType == "RPAREN" {
		return "Unclosed parenthesis detected. Check that all opening parentheses have matching closing parentheses."
	}

	// Generic suggestion
	return fmt.Sprintf("Expected %s but found %s. Review the SQL syntax at this position.", expectedType, tokenType)
}

// SuggestForIncompleteStatement provides suggestions for incomplete SQL statements
func SuggestForIncompleteStatement(lastKeyword string) string {
	suggestions := map[string]string{
		"SELECT": "Add columns to select and FROM clause: SELECT columns FROM table",
		"FROM":   "Add table name after FROM: FROM table_name",
		"WHERE":  "Add condition after WHERE: WHERE column = value",
		"JOIN":   "Add table name and ON condition: JOIN table ON condition",
		"ON":     "Add join condition: ON table1.column = table2.column",
		"ORDER":  "Add BY keyword and column: ORDER BY column",
		"GROUP":  "Add BY keyword and column: GROUP BY column",
		"SET":    "Add column assignments: SET column = value",
		"VALUES": "Add value list in parentheses: VALUES (value1, value2, ...)",
		"INTO":   "Add table name: INTO table_name",
		"UPDATE": "Add table name: UPDATE table_name SET ...",
		"DELETE": "Add FROM clause: DELETE FROM table_name",
		"INSERT": "Add INTO clause: INSERT INTO table_name ...",
		"CREATE": "Add object type and name: CREATE TABLE table_name ...",
		"DROP":   "Add object type and name: DROP TABLE table_name",
		"ALTER":  "Add TABLE and modifications: ALTER TABLE table_name ...",
	}

	if suggestion, ok := suggestions[strings.ToUpper(lastKeyword)]; ok {
		return suggestion
	}

	return "Complete the SQL statement with required clauses and syntax."
}

// SuggestForSyntaxError provides context-aware suggestions for syntax errors
func SuggestForSyntaxError(context, expectedToken string) string {
	contextUpper := strings.ToUpper(context)

	// SELECT statement context
	if strings.Contains(contextUpper, "SELECT") {
		if expectedToken == "FROM" {
			return "SELECT statements need a FROM clause. Format: SELECT columns FROM table"
		}
		if strings.Contains(expectedToken, "comma") || expectedToken == "," {
			return "Separate column names with commas in SELECT list"
		}
	}

	// JOIN context
	if strings.Contains(contextUpper, "JOIN") {
		if expectedToken == "ON" || expectedToken == "USING" {
			return "JOIN requires a condition. Use: JOIN table ON condition or JOIN table USING (column)"
		}
	}

	// WHERE context
	if strings.Contains(contextUpper, "WHERE") {
		if strings.Contains(expectedToken, "operator") {
			return "WHERE conditions need comparison operators: =, <, >, <=, >=, !=, LIKE, IN, BETWEEN"
		}
	}

	// INSERT context
	if strings.Contains(contextUpper, "INSERT") {
		if expectedToken == "INTO" {
			return "INSERT statements require INTO keyword: INSERT INTO table_name"
		}
		if expectedToken == "VALUES" {
			return "Specify values using VALUES clause: VALUES (value1, value2, ...)"
		}
	}

	// UPDATE context
	if strings.Contains(contextUpper, "UPDATE") {
		if expectedToken == "SET" {
			return "UPDATE statements require SET clause: UPDATE table SET column = value"
		}
	}

	return fmt.Sprintf("Check SQL syntax. Expected %s in this context.", expectedToken)
}

// GenerateDidYouMean generates "Did you mean?" suggestions for typos
func GenerateDidYouMean(actual string, possibleValues []string) string {
	if len(possibleValues) == 0 {
		return ""
	}

	// Use Levenshtein distance to find closest matches
	minDistance := len(actual) + 1
	var bestMatches []string

	for _, possible := range possibleValues {
		distance := levenshteinDistance(strings.ToUpper(actual), strings.ToUpper(possible))

		if distance < minDistance {
			minDistance = distance
			bestMatches = []string{possible}
		} else if distance == minDistance {
			bestMatches = append(bestMatches, possible)
		}
	}

	// Only suggest if distance is reasonable
	threshold := len(actual) / 2
	if threshold < 2 {
		threshold = 2
	}

	if minDistance <= threshold && len(bestMatches) > 0 {
		if len(bestMatches) == 1 {
			return fmt.Sprintf("Did you mean '%s'?", bestMatches[0])
		}
		return fmt.Sprintf("Did you mean one of: %s?", strings.Join(bestMatches, ", "))
	}

	return ""
}

// FormatMistakeExample formats a mistake pattern for display
func FormatMistakeExample(mistake MistakePattern) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Common Mistake: %s\n", mistake.Name))
	sb.WriteString(fmt.Sprintf("  ❌ Wrong: %s\n", mistake.Example))
	sb.WriteString(fmt.Sprintf("  ✓ Right: %s\n", mistake.Correct))
	sb.WriteString(fmt.Sprintf("  Explanation: %s\n", mistake.Explanation))
	return sb.String()
}
