package whitespace

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestLongLinesRule_Check(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		maxLength          int
		expectedViolations int
	}{
		{
			name:               "No violations - all lines under default max (100)",
			sql:                "SELECT id, name\nFROM users\nWHERE active = true",
			maxLength:          100,
			expectedViolations: 0,
		},
		{
			name:               "Single line exactly at max length (boundary condition)",
			sql:                strings.Repeat("A", 100),
			maxLength:          100,
			expectedViolations: 0,
		},
		{
			name:               "Single line one char over max length",
			sql:                strings.Repeat("A", 101),
			maxLength:          100,
			expectedViolations: 1,
		},
		{
			name:               "Single line well over max length (150 chars)",
			sql:                "SELECT id, name, email, address, phone, city, state, zip, country, created_at, updated_at, deleted_at, is_active, is_verified, preferences FROM users WHERE active = true",
			maxLength:          100,
			expectedViolations: 1,
		},
		{
			name:               "Multiple lines, some over max",
			sql:                "SELECT id, name\nFROM users\nWHERE active = true AND email IS NOT NULL AND verified = true AND created_at > '2023-01-01' AND deleted_at IS NULL",
			maxLength:          100,
			expectedViolations: 1,
		},
		{
			name:               "All lines over max",
			sql:                strings.Repeat("A", 101) + "\n" + strings.Repeat("B", 102) + "\n" + strings.Repeat("C", 103),
			maxLength:          100,
			expectedViolations: 3,
		},
		{
			name:               "Empty lines (should be ignored)",
			sql:                "SELECT id\n\n\nFROM users",
			maxLength:          100,
			expectedViolations: 0,
		},
		{
			name:               "Comment line with -- over max (should be skipped)",
			sql:                "-- " + strings.Repeat("This is a very long comment ", 10),
			maxLength:          100,
			expectedViolations: 0,
		},
		{
			name:               "Comment line with /* over max (should be skipped)",
			sql:                "/* " + strings.Repeat("This is a very long comment ", 10) + " */",
			maxLength:          100,
			expectedViolations: 0,
		},
		{
			name:               "SQL with inline comment exceeding max (should trigger violation)",
			sql:                "SELECT id, name, email, address, phone, city, state, zip, country FROM users WHERE active = true -- inline comment",
			maxLength:          100,
			expectedViolations: 1,
		},
		{
			name:               "Very long string literal in SQL",
			sql:                "INSERT INTO messages (content) VALUES ('" + strings.Repeat("very long message content ", 10) + "')",
			maxLength:          100,
			expectedViolations: 1,
		},
		{
			name:               "Custom max length: 80 characters",
			sql:                "SELECT id, name, email, address, phone, city, state, zip, country FROM users WHERE active = true",
			maxLength:          80,
			expectedViolations: 1,
		},
		{
			name:               "Custom max length: 120 characters",
			sql:                "SELECT id, name, email, address, phone, city, state, zip, country FROM users WHERE active = true",
			maxLength:          120,
			expectedViolations: 0,
		},
		{
			name:               "Zero max length (should use default 100)",
			sql:                "SELECT id FROM users",
			maxLength:          0,
			expectedViolations: 0,
		},
		{
			name:               "Comment-only line vs. code with comment",
			sql:                "-- This is a standalone comment that is quite long and exceeds the maximum line length configured\nSELECT id, name FROM users WHERE active = true -- This inline comment makes this line exceed max length",
			maxLength:          80,
			expectedViolations: 1,
		},
		{
			name:               "Multi-line comment block with long lines (only first line skipped)",
			sql:                "/* This is a multi-line comment block\n   with continuation that is short\n   that should be skipped */\nSELECT id FROM users",
			maxLength:          100,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(tt.maxLength)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
				for i, v := range violations {
					t.Logf("Violation %d: %s at line %d (length: %d)", i+1, v.Message, v.Location.Line, len(v.Line))
				}
			}

			// Verify violation details
			for _, v := range violations {
				if v.Rule != "L005" {
					t.Errorf("Expected rule ID 'L005', got '%s'", v.Rule)
				}
				if v.RuleName != "Long Lines" {
					t.Errorf("Expected rule name 'Long Lines', got '%s'", v.RuleName)
				}
				if v.Severity != linter.SeverityInfo {
					t.Errorf("Expected severity 'info', got '%s'", v.Severity)
				}
				if v.CanAutoFix {
					t.Error("Expected CanAutoFix to be false")
				}
				if v.Message != "Line exceeds maximum length" {
					t.Errorf("Expected message 'Line exceeds maximum length', got '%s'", v.Message)
				}
			}
		})
	}
}

func TestLongLinesRule_Check_LineNumbers(t *testing.T) {
	tests := []struct {
		name                string
		sql                 string
		maxLength           int
		expectedViolationAt []int
	}{
		{
			name:                "Violation on first line",
			sql:                 strings.Repeat("A", 101) + "\nSELECT id FROM users",
			maxLength:           100,
			expectedViolationAt: []int{1},
		},
		{
			name:                "Violation on third line",
			sql:                 "SELECT id\nFROM users\nWHERE active = true AND verified = true AND email IS NOT NULL AND created_at > '2023-01-01' AND deleted_at IS NULL",
			maxLength:           100,
			expectedViolationAt: []int{3},
		},
		{
			name:                "Multiple violations on different lines",
			sql:                 strings.Repeat("A", 101) + "\nSELECT id\n" + strings.Repeat("B", 102) + "\nFROM users\n" + strings.Repeat("C", 103),
			maxLength:           100,
			expectedViolationAt: []int{1, 3, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(tt.maxLength)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != len(tt.expectedViolationAt) {
				t.Errorf("Expected %d violations, got %d", len(tt.expectedViolationAt), len(violations))
			}

			for i, expectedLine := range tt.expectedViolationAt {
				if i >= len(violations) {
					break
				}
				if violations[i].Location.Line != expectedLine {
					t.Errorf("Violation %d: expected line %d, got %d", i, expectedLine, violations[i].Location.Line)
				}
			}
		})
	}
}

func TestLongLinesRule_Fix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Fix returns unchanged content (no auto-fix support)",
			input:    "SELECT id, name FROM users",
			expected: "SELECT id, name FROM users",
		},
		{
			name:     "Violations exist but content unchanged after fix",
			input:    strings.Repeat("A", 150) + "\nSELECT id FROM users",
			expected: strings.Repeat("A", 150) + "\nSELECT id FROM users",
		},
		{
			name:     "Empty string handled correctly",
			input:    "",
			expected: "",
		},
		{
			name:     "Large file unchanged",
			input:    strings.Repeat("SELECT id, name, email, address, phone, city, state, zip, country FROM users WHERE active = true\n", 100),
			expected: strings.Repeat("SELECT id, name, email, address, phone, city, state, zip, country FROM users WHERE active = true\n", 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(100)
			ctx := linter.NewContext(tt.input, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error during check: %v", err)
			}

			fixed, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Unexpected error during fix: %v", err)
			}

			if fixed != tt.expected {
				t.Errorf("Fix result mismatch:\nExpected: %q\nGot:      %q", tt.expected, fixed)
			}
		})
	}
}

func TestLongLinesRule_Metadata(t *testing.T) {
	rule := NewLongLinesRule(100)

	if rule.ID() != "L005" {
		t.Errorf("Expected ID 'L005', got '%s'", rule.ID())
	}

	if rule.Name() != "Long Lines" {
		t.Errorf("Expected name 'Long Lines', got '%s'", rule.Name())
	}

	if rule.Severity() != linter.SeverityInfo {
		t.Errorf("Expected severity 'info', got '%s'", rule.Severity())
	}

	if rule.CanAutoFix() {
		t.Error("Expected CanAutoFix to be false")
	}

	if rule.Description() == "" {
		t.Error("Expected non-empty description")
	}
}

func TestLongLinesRule_MaxLength(t *testing.T) {
	tests := []struct {
		name               string
		maxLength          int
		sql                string
		expectedViolations int
	}{
		{
			name:               "Max length 50",
			maxLength:          50,
			sql:                "SELECT id, name, email, address, phone FROM users WHERE active = true",
			expectedViolations: 1,
		},
		{
			name:               "Max length 200",
			maxLength:          200,
			sql:                "SELECT id, name, email, address, phone, city, state, zip, country, created_at, updated_at FROM users WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Max length 1 (extreme case)",
			maxLength:          1,
			sql:                "SELECT id FROM users",
			expectedViolations: 1,
		},
		{
			name:               "Default max length 100",
			maxLength:          100,
			sql:                strings.Repeat("A", 100),
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(tt.maxLength)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
			}

			// Verify MaxLength is set correctly
			expectedMaxLength := tt.maxLength
			if tt.maxLength <= 0 {
				expectedMaxLength = 100 // Default
			}
			if rule.MaxLength != expectedMaxLength {
				t.Errorf("Expected MaxLength %d, got %d", expectedMaxLength, rule.MaxLength)
			}
		})
	}
}

func TestLongLinesRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		maxLength          int
		expectedViolations int
		description        string
	}{
		{
			name:               "Empty string",
			sql:                "",
			maxLength:          100,
			expectedViolations: 0,
			description:        "Empty input should not cause errors",
		},
		{
			name:               "Single newline",
			sql:                "\n",
			maxLength:          100,
			expectedViolations: 0,
			description:        "Single newline should be handled",
		},
		{
			name:               "Line with only spaces (counts toward length)",
			sql:                strings.Repeat(" ", 101),
			maxLength:          100,
			expectedViolations: 1,
			description:        "Spaces-only line should count toward length",
		},
		{
			name:               "Unicode characters in long line",
			sql:                "SELECT id FROM users WHERE name = '" + strings.Repeat("日本語", 30) + "'",
			maxLength:          100,
			expectedViolations: 1,
			description:        "Unicode characters should be counted correctly",
		},
		{
			name:               "Tabs counting as single characters",
			sql:                strings.Repeat("\t", 101),
			maxLength:          100,
			expectedViolations: 1,
			description:        "Tabs should count as single characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(tt.maxLength)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("%s: Expected %d violations, got %d", tt.description, tt.expectedViolations, len(violations))
			}
		})
	}
}

func TestLongLinesRule_CommentDetection(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		maxLength          int
		expectedViolations int
		description        string
	}{
		{
			name:               "Single-line comment with -- at start",
			sql:                "-- " + strings.Repeat("This is a comment ", 20),
			maxLength:          100,
			expectedViolations: 0,
			description:        "Comment lines starting with -- should be skipped",
		},
		{
			name:               "Single-line comment with -- after whitespace",
			sql:                "    -- " + strings.Repeat("This is a comment ", 20),
			maxLength:          100,
			expectedViolations: 0,
			description:        "Comment lines with -- after whitespace should be skipped",
		},
		{
			name:               "Block comment with /* at start",
			sql:                "/* " + strings.Repeat("This is a block comment ", 20) + " */",
			maxLength:          100,
			expectedViolations: 0,
			description:        "Comment lines starting with /* should be skipped",
		},
		{
			name:               "Block comment with /* after whitespace",
			sql:                "    /* " + strings.Repeat("This is a block comment ", 20) + " */",
			maxLength:          100,
			expectedViolations: 0,
			description:        "Comment lines with /* after whitespace should be skipped",
		},
		{
			name:               "SQL with inline -- comment (should trigger)",
			sql:                "SELECT id, name, email, address, phone, city FROM users WHERE active = true -- inline comment",
			maxLength:          80,
			expectedViolations: 1,
			description:        "SQL with inline comments should trigger violations",
		},
		{
			name:               "SQL with inline /* comment (should trigger)",
			sql:                "SELECT id, name, email, address, phone, city FROM users WHERE active = true /* inline comment */",
			maxLength:          80,
			expectedViolations: 1,
			description:        "SQL with inline block comments should trigger violations",
		},
		{
			name:               "Mixed content: comment line and long SQL line",
			sql:                "-- " + strings.Repeat("Long comment ", 20) + "\nSELECT id, name, email, address, phone, city, state, zip FROM users WHERE active = true",
			maxLength:          80,
			expectedViolations: 1,
			description:        "Comment lines should be skipped, but SQL lines should be checked",
		},
		{
			name:               "Multi-line block comment (only first line is comment)",
			sql:                "/* Start of comment\n   Continuation short\n   End of comment */",
			maxLength:          100,
			expectedViolations: 0,
			description:        "Block comment starts are detected, continuation lines checked normally",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewLongLinesRule(tt.maxLength)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("%s: Expected %d violations, got %d", tt.description, tt.expectedViolations, len(violations))
				for i, v := range violations {
					t.Logf("Violation %d: %s at line %d", i+1, v.Message, v.Location.Line)
				}
			}
		})
	}
}

func TestLongLinesRule_ViolationDetails(t *testing.T) {
	sql := strings.Repeat("A", 150)
	rule := NewLongLinesRule(100)
	ctx := linter.NewContext(sql, "test.sql")

	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation, got %d", len(violations))
	}

	v := violations[0]

	// Verify violation properties
	if v.Rule != "L005" {
		t.Errorf("Expected Rule 'L005', got '%s'", v.Rule)
	}

	if v.RuleName != "Long Lines" {
		t.Errorf("Expected RuleName 'Long Lines', got '%s'", v.RuleName)
	}

	if v.Severity != linter.SeverityInfo {
		t.Errorf("Expected Severity 'info', got '%s'", v.Severity)
	}

	if v.Message != "Line exceeds maximum length" {
		t.Errorf("Expected Message 'Line exceeds maximum length', got '%s'", v.Message)
	}

	if v.Location.Line != 1 {
		t.Errorf("Expected Location.Line 1, got %d", v.Location.Line)
	}

	if v.Location.Column != 101 {
		t.Errorf("Expected Location.Column 101 (maxLength+1), got %d", v.Location.Column)
	}

	if v.Line != sql {
		t.Errorf("Expected Line to contain full line content")
	}

	expectedSuggestion := "Split this line into multiple lines (current: 150 chars, max: 100)"
	if v.Suggestion != expectedSuggestion {
		t.Errorf("Expected Suggestion '%s', got '%s'", expectedSuggestion, v.Suggestion)
	}

	if v.CanAutoFix {
		t.Error("Expected CanAutoFix to be false")
	}
}
