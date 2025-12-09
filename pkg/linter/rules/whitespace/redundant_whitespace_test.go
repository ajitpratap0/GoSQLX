package whitespace

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestRedundantWhitespaceRule_Check(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "No redundant whitespace",
			sql:                "SELECT id, name FROM users WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Single redundant space",
			sql:                "SELECT id,  name FROM users",
			expectedViolations: 1,
		},
		{
			name:               "Multiple redundant spaces",
			sql:                "SELECT id,   name,    email FROM users",
			expectedViolations: 2,
		},
		{
			name:               "Redundant spaces in multiple locations",
			sql:                "SELECT id  FROM  users  WHERE  active = true",
			expectedViolations: 4,
		},
		{
			name:               "Leading indentation should be preserved",
			sql:                "    SELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Tab indentation should be preserved",
			sql:                "\tSELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Empty SQL",
			sql:                "",
			expectedViolations: 0,
		},
		{
			name:               "String literals should be ignored",
			sql:                "SELECT 'hello  world' FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Double quoted strings should be ignored",
			sql:                `SELECT "hello  world" FROM users`,
			expectedViolations: 0,
		},
		{
			name:               "Redundant spaces outside strings",
			sql:                "SELECT 'hello' FROM  users WHERE  name = 'test'",
			expectedViolations: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
				for i, v := range violations {
					t.Logf("Violation %d: %s at line %d, col %d", i+1, v.Message, v.Location.Line, v.Location.Column)
				}
			}

			// Verify violation details
			for _, v := range violations {
				if v.Rule != "L010" {
					t.Errorf("Expected rule ID 'L010', got '%s'", v.Rule)
				}
				if v.Severity != linter.SeverityInfo {
					t.Errorf("Expected severity 'info', got '%s'", v.Severity)
				}
				if !v.CanAutoFix {
					t.Error("Expected CanAutoFix to be true")
				}
			}
		})
	}
}

func TestRedundantWhitespaceRule_MultiLine(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Multi-line without redundant spaces",
			sql: `SELECT id, name
FROM users
WHERE active = true`,
			expectedViolations: 0,
		},
		{
			name: "Multi-line with redundant spaces",
			sql: `SELECT id,  name
FROM  users
WHERE  active = true`,
			expectedViolations: 3,
		},
		{
			name: "Multi-line with indentation",
			sql: `SELECT id, name
    FROM users
    WHERE active = true`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
			}
		})
	}
}

func TestRedundantWhitespaceRule_Fix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove single redundant space",
			input:    "SELECT id,  name FROM users",
			expected: "SELECT id, name FROM users",
		},
		{
			name:     "Remove multiple redundant spaces",
			input:    "SELECT id,   name,    email FROM users",
			expected: "SELECT id, name, email FROM users",
		},
		{
			name:     "Preserve single spaces",
			input:    "SELECT id, name FROM users",
			expected: "SELECT id, name FROM users",
		},
		{
			name:     "Preserve leading indentation",
			input:    "    SELECT id FROM users",
			expected: "    SELECT id FROM users",
		},
		{
			name:     "Preserve tab indentation",
			input:    "\tSELECT id FROM users",
			expected: "\tSELECT id FROM users",
		},
		{
			name:     "Preserve string literals",
			input:    "SELECT 'hello  world' FROM users",
			expected: "SELECT 'hello  world' FROM users",
		},
		{
			name:     "Remove spaces outside strings",
			input:    "SELECT 'hello' FROM  users WHERE  name = 'test  value'",
			expected: "SELECT 'hello' FROM users WHERE name = 'test  value'",
		},
		{
			name:     "Handle empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Multi-line fix",
			input:    "SELECT id,  name\nFROM  users\nWHERE  active = true",
			expected: "SELECT id, name\nFROM users\nWHERE active = true",
		},
		{
			name:     "Mixed indentation and redundant spaces",
			input:    "    SELECT id,  name FROM  users",
			expected: "    SELECT id, name FROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
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

func TestRedundantWhitespaceRule_Metadata(t *testing.T) {
	rule := NewRedundantWhitespaceRule()

	if rule.ID() != "L010" {
		t.Errorf("Expected ID 'L010', got '%s'", rule.ID())
	}

	if rule.Name() != "Redundant Whitespace" {
		t.Errorf("Expected name 'Redundant Whitespace', got '%s'", rule.Name())
	}

	if rule.Severity() != linter.SeverityInfo {
		t.Errorf("Expected severity 'info', got '%s'", rule.Severity())
	}

	if !rule.CanAutoFix() {
		t.Error("Expected CanAutoFix to be true")
	}

	if rule.Description() == "" {
		t.Error("Expected non-empty description")
	}
}

func TestRedundantWhitespaceRule_ComplexQueries(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "SELECT with JOIN",
			sql: `SELECT u.id,  u.name,  o.order_date
FROM users u
JOIN  orders o ON  u.id = o.user_id`,
			expectedViolations: 4,
		},
		{
			name: "CTE with redundant spaces",
			sql: `WITH cte AS (
    SELECT id,  name
    FROM  users
)
SELECT  * FROM  cte`,
			expectedViolations: 4,
		},
		{
			name: "Window function with redundant spaces",
			sql: `SELECT id,  name,
       ROW_NUMBER() OVER  (ORDER BY  created_at) as row_num
FROM users`,
			expectedViolations: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
				for i, v := range violations {
					t.Logf("Violation %d: %s at line %d, col %d", i+1, v.Message, v.Location.Line, v.Location.Column)
				}
			}
		})
	}
}

func TestRedundantWhitespaceRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Only spaces",
			sql:                "     ",
			expectedViolations: 0,
		},
		{
			name:               "Line with only indentation then content",
			sql:                "    SELECT id FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Multiple lines with different indentation",
			sql:                "    SELECT id\n        FROM users\n            WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Escaped quotes in strings",
			sql:                "SELECT 'it\\'s  fine' FROM users",
			expectedViolations: 1, // Current implementation doesn't handle escaped quotes
		},
		{
			name:               "Double quotes with spaces",
			sql:                `SELECT "column  name" FROM users`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
			}
		})
	}
}

func TestRedundantWhitespaceRule_Unicode(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Unicode identifiers without redundant spaces",
			sql:                "SELECT ユーザーID, 名前 FROM ユーザー",
			expectedViolations: 0,
		},
		{
			name:               "Unicode identifiers with redundant spaces",
			sql:                "SELECT ユーザーID,  名前 FROM  ユーザー",
			expectedViolations: 2,
		},
		{
			name:               "Unicode in string literals",
			sql:                "SELECT '日本語  テキスト' FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Unicode with redundant spaces outside strings",
			sql:                "SELECT '日本語' FROM  ユーザー WHERE  名前 = 'テスト'",
			expectedViolations: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(violations))
			}
		})
	}
}

func TestExtractNonStringParts(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectedParts int
	}{
		{
			name:          "No strings",
			line:          "SELECT id FROM users",
			expectedParts: 1,
		},
		{
			name:          "Single quoted string",
			line:          "SELECT 'hello' FROM users",
			expectedParts: 2, // "SELECT " and " FROM users"
		},
		{
			name:          "Double quoted string",
			line:          `SELECT "hello" FROM users`,
			expectedParts: 2,
		},
		{
			name:          "Multiple strings",
			line:          "SELECT 'hello', 'world' FROM users",
			expectedParts: 3, // "SELECT ", ", ", " FROM users"
		},
		{
			name:          "Empty line",
			line:          "",
			expectedParts: 0,
		},
		{
			name:          "Only string",
			line:          "'hello world'",
			expectedParts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := extractNonStringParts(tt.line)
			if len(parts) != tt.expectedParts {
				t.Errorf("Expected %d parts, got %d: %+v", tt.expectedParts, len(parts), parts)
			}
		})
	}
}
