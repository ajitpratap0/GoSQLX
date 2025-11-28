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
	{
		Name:        "window_function_without_over",
		Example:     "SELECT name, ROW_NUMBER() FROM employees",
		Correct:     "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees",
		Explanation: "Window functions require OVER clause with optional PARTITION BY and ORDER BY",
	},
	{
		Name:        "partition_by_without_over",
		Example:     "SELECT name, RANK() PARTITION BY dept FROM employees",
		Correct:     "SELECT name, RANK() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees",
		Explanation: "PARTITION BY must be inside OVER clause for window functions",
	},
	{
		Name:        "cte_without_select",
		Example:     "WITH cte AS (SELECT * FROM users)",
		Correct:     "WITH cte AS (SELECT * FROM users) SELECT * FROM cte",
		Explanation: "WITH (CTE) must be followed by a SELECT/INSERT/UPDATE/DELETE statement",
	},
	{
		Name:        "recursive_cte_without_union",
		Example:     "WITH RECURSIVE cte AS (SELECT id FROM employees)",
		Correct:     "WITH RECURSIVE cte AS (SELECT id FROM employees WHERE manager_id IS NULL UNION ALL SELECT e.id FROM employees e JOIN cte ON e.manager_id = cte.id)",
		Explanation: "Recursive CTEs require UNION/UNION ALL to combine base and recursive cases",
	},
	{
		Name:        "window_frame_without_order",
		Example:     "SELECT SUM(amount) OVER (ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales",
		Correct:     "SELECT SUM(amount) OVER (ORDER BY date ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM sales",
		Explanation: "Window frame clauses (ROWS/RANGE) require ORDER BY in OVER clause",
	},
	{
		Name:        "set_operation_without_matching_columns",
		Example:     "SELECT id, name FROM users UNION SELECT id FROM orders",
		Correct:     "SELECT id, name FROM users UNION SELECT order_id, customer_name FROM orders",
		Explanation: "UNION/INTERSECT/EXCEPT require same number of columns with compatible types",
	},
	{
		Name:        "union_all_vs_union",
		Example:     "SELECT * FROM users WHERE age > 18 UNION SELECT * FROM users WHERE age <= 18",
		Correct:     "SELECT * FROM users WHERE age > 18 UNION ALL SELECT * FROM users WHERE age <= 18",
		Explanation: "Use UNION ALL when you know there are no duplicates (faster than UNION)",
	},
	{
		Name:        "order_by_in_union_subquery",
		Example:     "(SELECT * FROM users ORDER BY name) UNION (SELECT * FROM admins ORDER BY name)",
		Correct:     "SELECT * FROM users UNION SELECT * FROM admins ORDER BY name",
		Explanation: "ORDER BY should be after the entire UNION, not in individual queries",
	},
	{
		Name:        "missing_comma_in_cte_list",
		Example:     "WITH cte1 AS (SELECT * FROM users) cte2 AS (SELECT * FROM orders) SELECT * FROM cte1",
		Correct:     "WITH cte1 AS (SELECT * FROM users), cte2 AS (SELECT * FROM orders) SELECT * FROM cte1",
		Explanation: "Separate multiple CTEs with commas",
	},
	{
		Name:        "window_function_in_where",
		Example:     "SELECT * FROM employees WHERE ROW_NUMBER() OVER (ORDER BY salary) = 1",
		Correct:     "SELECT * FROM (SELECT *, ROW_NUMBER() OVER (ORDER BY salary) as rn FROM employees) t WHERE rn = 1",
		Explanation: "Window functions cannot be used directly in WHERE clause; use subquery or CTE",
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

// SuggestForWindowFunction provides suggestions for window function errors
func SuggestForWindowFunction(context, functionName string) string {
	contextUpper := strings.ToUpper(context)

	// Missing OVER clause
	if !strings.Contains(contextUpper, "OVER") {
		return fmt.Sprintf("Window function %s requires OVER clause: %s OVER (ORDER BY column)", functionName, functionName)
	}

	// PARTITION BY without OVER
	if strings.Contains(contextUpper, "PARTITION") && !strings.Contains(contextUpper, "OVER") {
		return "PARTITION BY must be inside OVER clause: OVER (PARTITION BY column ORDER BY ...)"
	}

	// Frame clause without ORDER BY
	if (strings.Contains(contextUpper, "ROWS") || strings.Contains(contextUpper, "RANGE")) &&
		!strings.Contains(contextUpper, "ORDER") {
		return "Window frame clauses (ROWS/RANGE) require ORDER BY: OVER (ORDER BY column ROWS BETWEEN ...)"
	}

	return "Check window function syntax: function_name OVER ([PARTITION BY ...] [ORDER BY ...] [frame_clause])"
}

// SuggestForCTE provides suggestions for Common Table Expression errors
func SuggestForCTE(context string) string {
	contextUpper := strings.ToUpper(context)

	// CTE without following statement
	if strings.Contains(contextUpper, "WITH") && !strings.Contains(contextUpper, "SELECT") &&
		!strings.Contains(contextUpper, "INSERT") && !strings.Contains(contextUpper, "UPDATE") {
		return "WITH clause must be followed by SELECT, INSERT, UPDATE, or DELETE statement"
	}

	// Recursive CTE without UNION
	if strings.Contains(contextUpper, "RECURSIVE") && !strings.Contains(contextUpper, "UNION") {
		return "Recursive CTEs require UNION or UNION ALL: WITH RECURSIVE cte AS (base_query UNION ALL recursive_query) ..."
	}

	// Missing comma between CTEs
	if strings.Count(contextUpper, " AS (") > 1 && strings.Count(contextUpper, ",") < strings.Count(contextUpper, " AS (")-1 {
		return "Multiple CTEs must be separated by commas: WITH cte1 AS (...), cte2 AS (...) ..."
	}

	return "Check CTE syntax: WITH cte_name AS (query) SELECT ... or WITH RECURSIVE cte AS (base UNION ALL recursive) ..."
}

// SuggestForSetOperation provides suggestions for UNION/INTERSECT/EXCEPT errors
func SuggestForSetOperation(operation, context string) string {
	contextUpper := strings.ToUpper(context)

	// Order by in subquery
	if strings.Contains(contextUpper, "(SELECT") && strings.Contains(contextUpper, "ORDER BY") {
		return fmt.Sprintf("ORDER BY should be after the entire %s, not in individual queries", operation)
	}

	// Mismatched columns
	if strings.Contains(context, "column") || strings.Contains(context, "mismatch") {
		return fmt.Sprintf("%s requires same number of columns with compatible types in both queries", operation)
	}

	return fmt.Sprintf("Check %s syntax: SELECT ... %s SELECT ... [ORDER BY ...]", operation, operation)
}

// SuggestForJoinError provides enhanced suggestions for JOIN-related errors
func SuggestForJoinError(joinType, context string) string {
	contextUpper := strings.ToUpper(context)

	// Missing ON or USING
	if !strings.Contains(contextUpper, "ON") && !strings.Contains(contextUpper, "USING") &&
		!strings.Contains(contextUpper, "NATURAL") {
		if joinType == "CROSS" {
			return "CROSS JOIN doesn't require ON clause, but other JOINs do"
		}
		return fmt.Sprintf("%s JOIN requires ON condition or USING clause: %s JOIN table ON condition", joinType, joinType)
	}

	// Ambiguous column in JOIN
	if strings.Contains(context, "ambiguous") {
		return "Qualify column names with table name or alias: table1.column = table2.column"
	}

	return fmt.Sprintf("Check %s JOIN syntax: FROM table1 %s JOIN table2 ON condition", joinType, joinType)
}

// GetAdvancedFeatureHint returns hints for advanced SQL features
func GetAdvancedFeatureHint(feature string) string {
	hints := map[string]string{
		"window_functions": "Window functions: ROW_NUMBER(), RANK(), DENSE_RANK(), LAG(), LEAD(), SUM() OVER (), etc.",
		"cte":              "CTEs (Common Table Expressions): WITH cte_name AS (query) SELECT * FROM cte_name",
		"recursive_cte":    "Recursive CTEs: WITH RECURSIVE cte AS (base_query UNION ALL recursive_query) ...",
		"set_operations":   "Set operations: UNION [ALL], INTERSECT, EXCEPT",
		"window_frames":    "Window frames: ROWS/RANGE BETWEEN start AND end (UNBOUNDED PRECEDING, CURRENT ROW, etc.)",
		"partition_by":     "PARTITION BY: Divides result set into partitions for window functions",
		"lateral_join":     "LATERAL joins: Allow subquery to reference columns from preceding tables",
		"grouping_sets":    "GROUPING SETS: Multiple GROUP BY clauses in single query",
	}

	feature = strings.ToLower(strings.ReplaceAll(feature, " ", "_"))
	if hint, ok := hints[feature]; ok {
		return hint
	}

	return "Check GoSQLX documentation for supported SQL features and syntax"
}
