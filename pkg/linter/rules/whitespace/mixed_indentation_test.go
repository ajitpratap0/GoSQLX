package whitespace

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestMixedIndentationRule_Check(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "No indentation - all lines start with non-whitespace",
			sql:                "SELECT id, name\nFROM users\nWHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Consistent spaces throughout file (multiple lines)",
			sql:                "SELECT id, name\n    FROM users\n    WHERE active = true\n        AND verified = true",
			expectedViolations: 0,
		},
		{
			name:               "Consistent tabs throughout file (multiple lines)",
			sql:                "SELECT id, name\n\tFROM users\n\tWHERE active = true\n\t\tAND verified = true",
			expectedViolations: 0,
		},
		{
			name:               "Single line with tabs and spaces mixed in leading whitespace",
			sql:                "\t SELECT id FROM users",
			expectedViolations: 1,
		},
		{
			name:               "Multiple lines: some with tab indent, some with space indent",
			sql:                "SELECT id\n\tFROM users\n    WHERE active = true",
			expectedViolations: 1,
		},
		{
			name:               "Empty lines should be ignored",
			sql:                "SELECT id\n\n    FROM users\n\n    WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Whitespace-only lines",
			sql:                "SELECT id\n    \n    FROM users",
			expectedViolations: 0,
		},
		{
			name:               "First line sets space indent, later line uses tabs",
			sql:                "    SELECT id\n\tFROM users",
			expectedViolations: 1,
		},
		{
			name:               "First line sets tab indent, later line uses spaces",
			sql:                "\tSELECT id\n    FROM users",
			expectedViolations: 1,
		},
		{
			name:               "Complex: nested indentation all spaces (no violations)",
			sql:                "SELECT\n    id,\n    name,\n    (\n        SELECT COUNT(*)\n        FROM orders\n        WHERE user_id = users.id\n    ) AS order_count\nFROM users",
			expectedViolations: 0,
		},
		{
			name:               "Complex: nested indentation all tabs (no violations)",
			sql:                "SELECT\n\tid,\n\tname,\n\t(\n\t\tSELECT COUNT(*)\n\t\tFROM orders\n\t\tWHERE user_id = users.id\n\t) AS order_count\nFROM users",
			expectedViolations: 0,
		},
		{
			name:               "Line with no leading whitespace (should be ignored)",
			sql:                "SELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Single tab character indentation",
			sql:                "\tSELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Single space character indentation",
			sql:                " SELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Multiple spaces (4 spaces) indentation",
			sql:                "    SELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Tab followed by content",
			sql:                "\tSELECT id\n\tFROM users\n\tWHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Spaces followed by content",
			sql:                "    SELECT id\n    FROM users\n    WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Mixed on same line + inconsistent across file (multiple violations)",
			sql:                "\t SELECT id\n    FROM users\n\tWHERE active = true",
			expectedViolations: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
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
				if v.Rule != "L002" {
					t.Errorf("Expected rule ID 'L002', got '%s'", v.Rule)
				}
				if v.RuleName != "Mixed Indentation" {
					t.Errorf("Expected rule name 'Mixed Indentation', got '%s'", v.RuleName)
				}
				if v.Severity != linter.SeverityError {
					t.Errorf("Expected severity 'error', got '%s'", v.Severity)
				}
				if !v.CanAutoFix {
					t.Error("Expected CanAutoFix to be true")
				}
			}
		})
	}
}

func TestMixedIndentationRule_Check_ViolationMessages(t *testing.T) {
	tests := []struct {
		name            string
		sql             string
		expectedMessage string
	}{
		{
			name:            "Mixed tabs and spaces on same line",
			sql:             "\t SELECT id FROM users",
			expectedMessage: "Line mixes tabs and spaces for indentation",
		},
		{
			name:            "Inconsistent indentation across file",
			sql:             "    SELECT id\n\tFROM users",
			expectedMessage: "Inconsistent indentation: file uses both tabs and spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) == 0 {
				t.Fatal("Expected at least one violation")
			}

			if violations[0].Message != tt.expectedMessage {
				t.Errorf("Expected message '%s', got '%s'", tt.expectedMessage, violations[0].Message)
			}
		})
	}
}

func TestMixedIndentationRule_Check_LineNumbers(t *testing.T) {
	tests := []struct {
		name                string
		sql                 string
		expectedViolationAt []int
	}{
		{
			name:                "Violation on first line",
			sql:                 "\t SELECT id FROM users",
			expectedViolationAt: []int{1},
		},
		{
			name:                "Violation on second line",
			sql:                 "    SELECT id\n\tFROM users",
			expectedViolationAt: []int{2},
		},
		{
			name:                "Violations on multiple lines",
			sql:                 "\t SELECT id\n    FROM users\n\tWHERE active = true",
			expectedViolationAt: []int{1, 3},
		},
		{
			name:                "Violation on third line only",
			sql:                 "SELECT id\n    FROM users\n\tWHERE active = true",
			expectedViolationAt: []int{3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
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

func TestMixedIndentationRule_Fix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Convert all tabs to spaces (tabs at start of lines)",
			input:    "\tSELECT id\n\tFROM users\n\t\tWHERE active = true",
			expected: "    SELECT id\n    FROM users\n        WHERE active = true",
		},
		{
			name:     "Preserve already consistent spacing",
			input:    "    SELECT id\n    FROM users\n        WHERE active = true",
			expected: "    SELECT id\n    FROM users\n        WHERE active = true",
		},
		{
			name:     "Handle nested/multiple indent levels (tabs → spaces)",
			input:    "SELECT\n\tid,\n\tname,\n\t(\n\t\tSELECT COUNT(*)\n\t\tFROM orders\n\t) AS count\nFROM users",
			expected: "SELECT\n    id,\n    name,\n    (\n        SELECT COUNT(*)\n        FROM orders\n    ) AS count\nFROM users",
		},
		{
			name:     "Preserve non-leading tabs (tabs in content should not be converted)",
			input:    "\tSELECT\t'value'\tFROM users",
			expected: "    SELECT\t'value'\tFROM users",
		},
		{
			name:     "Mixed indentation file conversion",
			input:    "\tSELECT id\n    FROM users\n\t\tWHERE active = true",
			expected: "    SELECT id\n    FROM users\n        WHERE active = true",
		},
		{
			name:     "Empty file handling",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
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

func TestMixedIndentationRule_Fix_PreservesContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Preserve string literals with tabs",
			input: "\tSELECT 'data\twith\ttabs' FROM users",
		},
		{
			name:  "Preserve comments",
			input: "\t-- This is a comment\n\tSELECT id FROM users",
		},
		{
			name:  "Preserve empty lines",
			input: "\tSELECT id\n\n\tFROM users",
		},
		{
			name:  "Preserve line endings",
			input: "\tSELECT id\n\tFROM users\n\tWHERE active = true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
			ctx := linter.NewContext(tt.input, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error during check: %v", err)
			}

			fixed, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Unexpected error during fix: %v", err)
			}

			// Verify that fixing removes tabs from indentation
			// Count tabs in original vs fixed
			originalLeadingTabs := 0
			fixedLeadingTabs := 0

			for _, line := range ctx.Lines {
				for _, char := range line {
					if char == '\t' {
						originalLeadingTabs++
					} else if char != ' ' {
						break
					}
				}
			}

			fixedCtx := linter.NewContext(fixed, "test.sql")
			for _, line := range fixedCtx.Lines {
				for _, char := range line {
					if char == '\t' {
						fixedLeadingTabs++
					} else if char != ' ' {
						break
					}
				}
			}

			if originalLeadingTabs > 0 && fixedLeadingTabs >= originalLeadingTabs {
				t.Errorf("Expected leading tabs to be reduced, original: %d, fixed: %d", originalLeadingTabs, fixedLeadingTabs)
			}
		})
	}
}

func TestMixedIndentationRule_Fix_Idempotency(t *testing.T) {
	// Applying fix multiple times should yield the same result
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Single tab indentation",
			input: "\tSELECT id FROM users",
		},
		{
			name:  "Multiple tab levels",
			input: "\tSELECT id\n\t\tFROM users",
		},
		{
			name:  "Mixed indentation",
			input: "\t SELECT id\n    FROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
			ctx := linter.NewContext(tt.input, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error during check: %v", err)
			}

			fixed1, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Unexpected error during first fix: %v", err)
			}

			// Apply fix again
			ctx2 := linter.NewContext(fixed1, "test.sql")
			violations2, err := rule.Check(ctx2)
			if err != nil {
				t.Fatalf("Unexpected error during second check: %v", err)
			}

			fixed2, err := rule.Fix(fixed1, violations2)
			if err != nil {
				t.Fatalf("Unexpected error during second fix: %v", err)
			}

			if fixed1 != fixed2 {
				t.Errorf("Fix is not idempotent:\nFirst fix:  %q\nSecond fix: %q", fixed1, fixed2)
			}
		})
	}
}

func TestMixedIndentationRule_Metadata(t *testing.T) {
	rule := NewMixedIndentationRule()

	if rule.ID() != "L002" {
		t.Errorf("Expected ID 'L002', got '%s'", rule.ID())
	}

	if rule.Name() != "Mixed Indentation" {
		t.Errorf("Expected name 'Mixed Indentation', got '%s'", rule.Name())
	}

	if rule.Severity() != linter.SeverityError {
		t.Errorf("Expected severity 'error', got '%s'", rule.Severity())
	}

	if !rule.CanAutoFix() {
		t.Error("Expected CanAutoFix to be true")
	}

	if rule.Description() == "" {
		t.Error("Expected non-empty description")
	}
}

func TestMixedIndentationRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
		description        string
	}{
		{
			name:               "Only whitespace line with tabs",
			sql:                "\t\t\t",
			expectedViolations: 0,
			description:        "Whitespace-only lines should be ignored",
		},
		{
			name:               "Only whitespace line with spaces",
			sql:                "    ",
			expectedViolations: 0,
			description:        "Whitespace-only lines should be ignored",
		},
		{
			name:               "Empty string",
			sql:                "",
			expectedViolations: 0,
			description:        "Empty input should not cause errors",
		},
		{
			name:               "Single newline",
			sql:                "\n",
			expectedViolations: 0,
			description:        "Single newline should be handled",
		},
		{
			name:               "Multiple empty lines",
			sql:                "\n\n\n",
			expectedViolations: 0,
			description:        "Multiple empty lines should be ignored",
		},
		{
			name:               "Tab at end of line (not leading)",
			sql:                "SELECT id\tFROM users",
			expectedViolations: 0,
			description:        "Tabs in content (not leading) should not trigger violations",
		},
		{
			name:               "Space at end of line (not leading)",
			sql:                "SELECT id FROM users",
			expectedViolations: 0,
			description:        "Spaces in content should not trigger violations",
		},
		{
			name:               "Very deep nesting with tabs",
			sql:                "\t\t\t\t\t\tSELECT id FROM users",
			expectedViolations: 0,
			description:        "Deep nesting with consistent tabs is valid",
		},
		{
			name:               "Very deep nesting with spaces",
			sql:                "                        SELECT id FROM users",
			expectedViolations: 0,
			description:        "Deep nesting with consistent spaces is valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewMixedIndentationRule()
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
