package errors

import (
	"fmt"
	"strings"
)

// Common SQL keywords for suggestion matching
var commonKeywords = []string{
	"SELECT", "FROM", "WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "CROSS",
	"ON", "AND", "OR", "NOT", "IN", "LIKE", "BETWEEN", "IS", "NULL", "AS", "BY",
	"GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET", "UNION", "EXCEPT", "INTERSECT",
	"INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "CREATE", "ALTER", "DROP",
	"TABLE", "INDEX", "VIEW", "WITH", "CASE", "WHEN", "THEN", "ELSE", "END",
	"DISTINCT", "ALL", "ANY", "SOME", "EXISTS", "ASC", "DESC",
}

// SuggestKeyword uses Levenshtein distance to suggest the closest matching keyword
func SuggestKeyword(input string) string {
	input = strings.ToUpper(input)
	if input == "" {
		return ""
	}

	minDistance := len(input) + 1
	var bestMatch string

	for _, keyword := range commonKeywords {
		distance := levenshteinDistance(input, keyword)
		if distance < minDistance {
			minDistance = distance
			bestMatch = keyword
		}
	}

	// Only suggest if the distance is small relative to input length
	// (avoid suggesting "SELECT" for completely unrelated words)
	threshold := len(input) / 2
	if threshold < 2 {
		threshold = 2
	}

	if minDistance <= threshold {
		return bestMatch
	}

	return ""
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(s1, s2 string) int {
	len1 := len(s1)
	len2 := len(s2)

	// Create a 2D slice for dynamic programming
	matrix := make([][]int, len1+1)
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
	}

	// Initialize first row and column
	for i := 0; i <= len1; i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}

	// Fill in the rest of the matrix
	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len1][len2]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// GenerateHint generates an intelligent hint based on the error type and context
func GenerateHint(code ErrorCode, expected, found string) string {
	switch code {
	case ErrCodeExpectedToken:
		// Check if the found token is a typo of the expected token
		if found != "" {
			suggestion := SuggestKeyword(found)
			if suggestion != "" && strings.EqualFold(suggestion, expected) {
				return fmt.Sprintf("Did you mean '%s' instead of '%s'?", expected, found)
			}
		}
		return fmt.Sprintf("Expected '%s' keyword here", expected)

	case ErrCodeUnexpectedToken:
		// Suggest what might have been intended
		if found != "" {
			suggestion := SuggestKeyword(found)
			if suggestion != "" && suggestion != strings.ToUpper(found) {
				return fmt.Sprintf("Did you mean '%s'?", suggestion)
			}
		}
		return "Check the SQL syntax at this position"

	case ErrCodeUnterminatedString:
		return "Make sure all string literals are properly closed with matching quotes"

	case ErrCodeMissingClause:
		return fmt.Sprintf("Add the required '%s' clause to complete this statement", expected)

	case ErrCodeInvalidSyntax:
		return "Review the SQL syntax documentation for this statement type"

	case ErrCodeUnsupportedFeature:
		return "This feature is not yet supported. Check the documentation for supported SQL features"

	default:
		return ""
	}
}

// Common error scenarios with pre-built hints
var CommonHints = map[string]string{
	"missing_from":     "SELECT statements require a FROM clause unless selecting constants",
	"missing_where":    "Add a WHERE clause to filter the results",
	"unclosed_paren":   "Check that all parentheses are properly matched",
	"missing_comma":    "List items should be separated by commas",
	"invalid_join":     "JOIN clauses must include ON or USING conditions",
	"duplicate_alias":  "Each table alias must be unique within the query",
	"ambiguous_column": "Qualify the column name with the table name or alias (e.g., table.column)",
}

// GetCommonHint retrieves a pre-defined hint by key
func GetCommonHint(key string) string {
	if hint, ok := CommonHints[key]; ok {
		return hint
	}
	return ""
}
