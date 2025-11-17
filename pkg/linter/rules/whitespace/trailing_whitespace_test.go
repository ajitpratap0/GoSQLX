package whitespace

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestTrailingWhitespaceRule_Check(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "No trailing whitespace",
			sql:                "SELECT id, name\nFROM users\nWHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Single line with trailing whitespace",
			sql:                "SELECT id   ",
			expectedViolations: 1,
		},
		{
			name:               "Multiple lines with trailing whitespace",
			sql:                "SELECT id   \nFROM users  \nWHERE active = true   ",
			expectedViolations: 3,
		},
		{
			name:               "Empty lines should be skipped",
			sql:                "SELECT id\n\nFROM users",
			expectedViolations: 0,
		},
		{
			name:               "Tab as trailing whitespace",
			sql:                "SELECT id\t",
			expectedViolations: 1,
		},
		{
			name:               "Mixed spaces and tabs as trailing",
			sql:                "SELECT id  \t  ",
			expectedViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewTrailingWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
				for i, v := range violations {
					t.Logf("Violation %d: %s at line %d", i+1, v.Message, v.Location.Line)
				}
			}

			// Verify violation details
			for _, v := range violations {
				if v.Rule != "L001" {
					t.Errorf("Expected rule ID 'L001', got '%s'", v.Rule)
				}
				if v.Severity != linter.SeverityWarning {
					t.Errorf("Expected severity 'warning', got '%s'", v.Severity)
				}
				if !v.CanAutoFix {
					t.Error("Expected CanAutoFix to be true")
				}
			}
		})
	}
}

func TestTrailingWhitespaceRule_Fix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove trailing spaces",
			input:    "SELECT id   \nFROM users",
			expected: "SELECT id\nFROM users",
		},
		{
			name:     "Remove trailing tabs",
			input:    "SELECT id\t\t\nFROM users",
			expected: "SELECT id\nFROM users",
		},
		{
			name:     "Remove mixed trailing whitespace",
			input:    "SELECT id  \t  \nFROM users",
			expected: "SELECT id\nFROM users",
		},
		{
			name:     "Preserve lines without trailing whitespace",
			input:    "SELECT id\nFROM users",
			expected: "SELECT id\nFROM users",
		},
		{
			name:     "Handle empty lines",
			input:    "SELECT id\n\nFROM users",
			expected: "SELECT id\n\nFROM users",
		},
		{
			name:     "Multiple lines with trailing whitespace",
			input:    "SELECT id   \nFROM users  \nWHERE active = true   ",
			expected: "SELECT id\nFROM users\nWHERE active = true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewTrailingWhitespaceRule()
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

func TestTrailingWhitespaceRule_Metadata(t *testing.T) {
	rule := NewTrailingWhitespaceRule()

	if rule.ID() != "L001" {
		t.Errorf("Expected ID 'L001', got '%s'", rule.ID())
	}

	if rule.Name() != "Trailing Whitespace" {
		t.Errorf("Expected name 'Trailing Whitespace', got '%s'", rule.Name())
	}

	if rule.Severity() != linter.SeverityWarning {
		t.Errorf("Expected severity 'warning', got '%s'", rule.Severity())
	}

	if !rule.CanAutoFix() {
		t.Error("Expected CanAutoFix to be true")
	}

	if rule.Description() == "" {
		t.Error("Expected non-empty description")
	}
}
