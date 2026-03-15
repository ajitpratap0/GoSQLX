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

// SuggestKeyword uses Levenshtein distance to suggest the closest SQL keyword
// matching the given input token. The suggestion is only returned when the edit
// distance is within half the length of the input (minimum threshold of 2), which
// prevents semantically unrelated tokens from being suggested.
//
// Results are stored in a bounded LRU-style cache shared across all calls to
// improve performance during repeated error-reporting scenarios where the same
// misspelled token appears many times (e.g., in batch query validation).
//
// Returns the matching keyword in uppercase, or an empty string if no sufficiently
// close match is found.
func SuggestKeyword(input string) string {
	input = strings.ToUpper(input)
	if input == "" {
		return ""
	}

	// Check cache first
	if cached, ok := suggestionCache.get(input); ok {
		return cached
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

	var result string
	if minDistance <= threshold {
		result = bestMatch
	}

	// Cache the result
	suggestionCache.set(input, result)

	return result
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

// GenerateHint generates an actionable hint message tailored to the error code
// and the tokens involved. For token-mismatch errors it applies SuggestKeyword to
// detect typos and produces a "Did you mean?" message. For structural errors such
// as missing clauses or unsupported features it returns a generic guidance string.
//
// Parameters:
//   - code: The ErrorCode that identifies the class of error (e.g., ErrCodeExpectedToken)
//   - expected: The token or keyword that was required (used for ErrCodeExpectedToken
//     and ErrCodeMissingClause messages)
//   - found: The token that was actually present (used for typo detection)
//
// Returns an empty string for error codes that have no pre-defined hint.
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
		return fmt.Sprintf("expected %s here", expected)

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

// CommonHints is a pre-built map of human-readable hint messages keyed by a
// short scenario identifier. The map covers the most frequent SQL authoring
// mistakes and is intended for use in error formatters that want to attach a
// contextual hint without invoking the full suggestion pipeline.
//
// The available keys are:
//
//	"missing_from"     - SELECT without a FROM clause
//	"missing_where"    - reminder to add a WHERE filter
//	"unclosed_paren"   - unbalanced parentheses
//	"missing_comma"    - list items not separated by commas
//	"invalid_join"     - JOIN clause missing ON or USING
//	"duplicate_alias"  - non-unique table alias
//	"ambiguous_column" - unqualified column reference in multi-table query
//
// Use GetCommonHint for safe lookup with a zero-value fallback.
var CommonHints = map[string]string{
	"missing_from":     "SELECT statements require a FROM clause unless selecting constants",
	"missing_where":    "Add a WHERE clause to filter the results",
	"unclosed_paren":   "Check that all parentheses are properly matched",
	"missing_comma":    "List items should be separated by commas",
	"invalid_join":     "JOIN clauses must include ON or USING conditions",
	"duplicate_alias":  "Each table alias must be unique within the query",
	"ambiguous_column": "Qualify the column name with the table name or alias (e.g., table.column)",
}

// GetCommonHint retrieves a pre-defined hint message from CommonHints by its
// scenario key. This is the safe alternative to indexing the map directly; it
// returns an empty string instead of the zero value when the key is absent,
// making nil-check patterns unnecessary in callers.
//
// See CommonHints for the full list of valid keys.
func GetCommonHint(key string) string {
	if hint, ok := CommonHints[key]; ok {
		return hint
	}
	return ""
}
