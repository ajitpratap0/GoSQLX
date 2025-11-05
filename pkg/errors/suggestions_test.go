package errors

import (
	"strings"
	"testing"
)

func TestSuggestFromPattern(t *testing.T) {
	tests := []struct {
		name          string
		errorMessage  string
		wantSubstring string // Substring that should be in suggestion
	}{
		{
			name:          "FROM typo",
			errorMessage:  "expected FROM, got 'FORM'",
			wantSubstring: "FROM",
		},
		{
			name:          "SELECT typo",
			errorMessage:  "expected SELECT, got 'SELCT'",
			wantSubstring: "SELECT",
		},
		{
			name:          "WHERE typo",
			errorMessage:  "expected WHERE, got 'WAHER'",
			wantSubstring: "WHERE",
		},
		{
			name:          "unterminated string",
			errorMessage:  "unterminated string literal",
			wantSubstring: "quotes",
		},
		{
			name:          "invalid number",
			errorMessage:  "invalid numeric literal: 18.45.6",
			wantSubstring: "decimal point",
		},
		{
			name:          "missing FROM clause",
			errorMessage:  "missing required FROM clause",
			wantSubstring: "FROM",
		},
		{
			name:          "no match",
			errorMessage:  "some random error",
			wantSubstring: "", // Should return empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestFromPattern(tt.errorMessage)
			if tt.wantSubstring == "" {
				if got != "" {
					t.Errorf("SuggestFromPattern() = %q, want empty string for unmatched pattern", got)
				}
			} else {
				if !strings.Contains(got, tt.wantSubstring) {
					t.Errorf("SuggestFromPattern() = %q, should contain %q", got, tt.wantSubstring)
				}
			}
		})
	}
}

func TestGetMistakeExplanation(t *testing.T) {
	tests := []struct {
		name        string
		mistakeName string
		wantFound   bool
	}{
		{
			name:        "string instead of number",
			mistakeName: "string_instead_of_number",
			wantFound:   true,
		},
		{
			name:        "missing comma",
			mistakeName: "missing_comma_in_list",
			wantFound:   true,
		},
		{
			name:        "ambiguous column",
			mistakeName: "ambiguous_column",
			wantFound:   true,
		},
		{
			name:        "missing join condition",
			mistakeName: "missing_join_condition",
			wantFound:   true,
		},
		{
			name:        "non-existent mistake",
			mistakeName: "nonexistent_mistake",
			wantFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mistake, found := GetMistakeExplanation(tt.mistakeName)
			if found != tt.wantFound {
				t.Errorf("GetMistakeExplanation(%q) found = %v, want %v", tt.mistakeName, found, tt.wantFound)
			}
			if found {
				if mistake.Example == "" || mistake.Correct == "" || mistake.Explanation == "" {
					t.Errorf("GetMistakeExplanation(%q) returned incomplete mistake pattern", tt.mistakeName)
				}
			}
		})
	}
}

func TestAnalyzeTokenError(t *testing.T) {
	tests := []struct {
		name         string
		tokenType    string
		tokenValue   string
		expectedType string
		wantContains string
	}{
		{
			name:         "string instead of number",
			tokenType:    "STRING",
			tokenValue:   "18",
			expectedType: "NUMBER",
			wantContains: "Remove the quotes",
		},
		{
			name:         "number instead of string",
			tokenType:    "NUMBER",
			tokenValue:   "18",
			expectedType: "STRING",
			wantContains: "Add quotes",
		},
		{
			name:         "identifier typo",
			tokenType:    "IDENT",
			tokenValue:   "FORM",
			expectedType: "KEYWORD",
			wantContains: "FROM",
		},
		{
			name:         "missing operator",
			tokenType:    "IDENT",
			tokenValue:   "column_name",
			expectedType: "OPERATOR",
			wantContains: "operator",
		},
		{
			name:         "unclosed parenthesis",
			tokenType:    "EOF",
			tokenValue:   "",
			expectedType: "RPAREN",
			wantContains: "parenthes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeTokenError(tt.tokenType, tt.tokenValue, tt.expectedType)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.wantContains)) {
				t.Errorf("AnalyzeTokenError() = %q, should contain %q", got, tt.wantContains)
			}
		})
	}
}

func TestSuggestForIncompleteStatement(t *testing.T) {
	tests := []struct {
		name         string
		lastKeyword  string
		wantContains string
	}{
		{
			name:         "SELECT incomplete",
			lastKeyword:  "SELECT",
			wantContains: "FROM",
		},
		{
			name:         "FROM incomplete",
			lastKeyword:  "FROM",
			wantContains: "table",
		},
		{
			name:         "WHERE incomplete",
			lastKeyword:  "WHERE",
			wantContains: "condition",
		},
		{
			name:         "JOIN incomplete",
			lastKeyword:  "JOIN",
			wantContains: "ON",
		},
		{
			name:         "ORDER incomplete",
			lastKeyword:  "ORDER",
			wantContains: "BY",
		},
		{
			name:         "GROUP incomplete",
			lastKeyword:  "GROUP",
			wantContains: "BY",
		},
		{
			name:         "INSERT incomplete",
			lastKeyword:  "INSERT",
			wantContains: "INTO",
		},
		{
			name:         "UPDATE incomplete",
			lastKeyword:  "UPDATE",
			wantContains: "table",
		},
		{
			name:         "DELETE incomplete",
			lastKeyword:  "DELETE",
			wantContains: "FROM",
		},
		{
			name:         "unknown keyword",
			lastKeyword:  "UNKNOWN",
			wantContains: "Complete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestForIncompleteStatement(tt.lastKeyword)
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("SuggestForIncompleteStatement(%q) = %q, should contain %q", tt.lastKeyword, got, tt.wantContains)
			}
		})
	}
}

func TestSuggestForSyntaxError(t *testing.T) {
	tests := []struct {
		name          string
		context       string
		expectedToken string
		wantContains  string
	}{
		{
			name:          "SELECT missing FROM",
			context:       "SELECT * users",
			expectedToken: "FROM",
			wantContains:  "FROM clause",
		},
		{
			name:          "SELECT missing comma",
			context:       "SELECT id name",
			expectedToken: ",",
			wantContains:  "comma",
		},
		{
			name:          "JOIN missing ON",
			context:       "FROM users JOIN orders",
			expectedToken: "ON",
			wantContains:  "condition",
		},
		{
			name:          "WHERE missing operator",
			context:       "WHERE age 18",
			expectedToken: "operator",
			wantContains:  "comparison operators",
		},
		{
			name:          "INSERT missing INTO",
			context:       "INSERT users",
			expectedToken: "INTO",
			wantContains:  "INTO",
		},
		{
			name:          "UPDATE missing SET",
			context:       "UPDATE users",
			expectedToken: "SET",
			wantContains:  "SET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestForSyntaxError(tt.context, tt.expectedToken)
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("SuggestForSyntaxError() = %q, should contain %q", got, tt.wantContains)
			}
		})
	}
}

func TestGenerateDidYouMean(t *testing.T) {
	tests := []struct {
		name           string
		actual         string
		possibleValues []string
		wantContains   string
	}{
		{
			name:           "single close match",
			actual:         "FORM",
			possibleValues: []string{"FROM", "FORMAT", "FORMAL"},
			wantContains:   "FROM",
		},
		{
			name:           "multiple close matches",
			actual:         "SEL",
			possibleValues: []string{"SELECT", "SELL", "SELF"},
			wantContains:   "Did you mean",
		},
		{
			name:           "no close match",
			actual:         "ZZZZZ",
			possibleValues: []string{"SELECT", "FROM", "WHERE"},
			wantContains:   "", // Should return empty
		},
		{
			name:           "empty possible values",
			actual:         "FORM",
			possibleValues: []string{},
			wantContains:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateDidYouMean(tt.actual, tt.possibleValues)
			if tt.wantContains == "" {
				if got != "" {
					t.Errorf("GenerateDidYouMean() = %q, want empty string", got)
				}
			} else {
				if !strings.Contains(got, tt.wantContains) {
					t.Errorf("GenerateDidYouMean() = %q, should contain %q", got, tt.wantContains)
				}
			}
		})
	}
}

func TestFormatMistakeExample(t *testing.T) {
	mistake := MistakePattern{
		Name:        "test_mistake",
		Example:     "SELECT * FORM users",
		Correct:     "SELECT * FROM users",
		Explanation: "FROM is the correct keyword",
	}

	got := FormatMistakeExample(mistake)

	requiredParts := []string{
		"test_mistake",
		"SELECT * FORM users",
		"SELECT * FROM users",
		"FROM is the correct keyword",
		"Wrong:",
		"Right:",
		"Explanation:",
	}

	for _, part := range requiredParts {
		if !strings.Contains(got, part) {
			t.Errorf("FormatMistakeExample() should contain %q, got:\n%s", part, got)
		}
	}
}

func TestCommonMistakePatterns(t *testing.T) {
	// Verify all common mistakes have complete information
	for i, mistake := range commonMistakes {
		if mistake.Name == "" {
			t.Errorf("Mistake %d has empty Name", i)
		}
		if mistake.Example == "" {
			t.Errorf("Mistake %d (%s) has empty Example", i, mistake.Name)
		}
		if mistake.Correct == "" {
			t.Errorf("Mistake %d (%s) has empty Correct", i, mistake.Name)
		}
		if mistake.Explanation == "" {
			t.Errorf("Mistake %d (%s) has empty Explanation", i, mistake.Name)
		}
	}

	// Verify we have all expected mistake patterns
	expectedMistakes := []string{
		"string_instead_of_number",
		"missing_comma_in_list",
		"equals_instead_of_like",
		"missing_join_condition",
		"ambiguous_column",
		"wrong_aggregate_syntax",
		"missing_group_by",
		"having_without_group_by",
	}

	for _, expected := range expectedMistakes {
		found := false
		for _, mistake := range commonMistakes {
			if mistake.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected mistake pattern %q not found in commonMistakes", expected)
		}
	}
}

func TestErrorPatterns(t *testing.T) {
	// Verify all error patterns have complete information
	for i, pattern := range errorPatterns {
		if pattern.Pattern == nil {
			t.Errorf("Pattern %d has nil Pattern", i)
		}
		if pattern.Description == "" {
			t.Errorf("Pattern %d has empty Description", i)
		}
		if pattern.Suggestion == "" {
			t.Errorf("Pattern %d has empty Suggestion", i)
		}
	}

	// Test that patterns compile and match expected inputs
	testCases := []struct {
		pattern     int // Index into errorPatterns
		input       string
		shouldMatch bool
	}{
		{0, "expected FROM, got 'FORM'", true},
		{1, "expected SELECT, got 'SELCT'", true},
		{2, "expected WHERE, got 'WAHER'", true},
		{3, "unterminated string literal", true},
		{4, "invalid numeric literal: 18.45.6", true},
		{0, "some other error", false},
	}

	for _, tc := range testCases {
		if tc.pattern >= len(errorPatterns) {
			continue
		}
		pattern := errorPatterns[tc.pattern]
		matches := pattern.Pattern.MatchString(tc.input)
		if matches != tc.shouldMatch {
			t.Errorf("Pattern %d (%s) match(%q) = %v, want %v",
				tc.pattern, pattern.Description, tc.input, matches, tc.shouldMatch)
		}
	}
}

func BenchmarkAnalyzeTokenError(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeTokenError("STRING", "18", "NUMBER")
	}
}

func BenchmarkSuggestForIncompleteStatement(b *testing.B) {
	keywords := []string{"SELECT", "FROM", "WHERE", "JOIN", "ORDER"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyword := keywords[i%len(keywords)]
		_ = SuggestForIncompleteStatement(keyword)
	}
}

func BenchmarkGenerateDidYouMean(b *testing.B) {
	possibleValues := []string{"SELECT", "FROM", "WHERE", "JOIN", "ORDER", "GROUP", "HAVING"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GenerateDidYouMean("FORM", possibleValues)
	}
}
