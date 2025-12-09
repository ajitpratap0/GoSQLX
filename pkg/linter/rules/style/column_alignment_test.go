package style

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestColumnAlignmentRule_Check(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Single line SELECT - no violations",
			sql:                "SELECT id, name, email FROM users",
			expectedViolations: 0,
		},
		{
			name: "Properly aligned columns",
			sql: `SELECT id,
       name,
       email
FROM users`,
			expectedViolations: 0,
		},
		{
			name: "Misaligned columns",
			sql: `SELECT id,
       name,
    email
FROM users`,
			expectedViolations: 1, // email is misaligned
		},
		{
			name: "Multiple misaligned columns",
			sql: `SELECT id,
       name,
    email,
         address
FROM users`,
			expectedViolations: 2, // email and address misaligned
		},
		{
			name: "SELECT DISTINCT with aligned columns",
			sql: `SELECT DISTINCT id,
                name,
                email
FROM users`,
			expectedViolations: 0,
		},
		{
			name:               "Empty SQL",
			sql:                "",
			expectedViolations: 0,
		},
		{
			name: "SELECT with subquery",
			sql: `SELECT id,
       name,
       (SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewColumnAlignmentRule()
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
				if v.Rule != "L006" {
					t.Errorf("Expected rule ID 'L006', got '%s'", v.Rule)
				}
				if v.Severity != linter.SeverityInfo {
					t.Errorf("Expected severity 'info', got '%s'", v.Severity)
				}
				if v.CanAutoFix {
					t.Error("Expected CanAutoFix to be false")
				}
			}
		})
	}
}

func TestColumnAlignmentRule_ComplexQueries(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Multiple SELECT statements",
			sql: `SELECT id,
       name
FROM users
UNION
SELECT product_id,
       product_name
FROM products`,
			expectedViolations: 0,
		},
		{
			name: "SELECT with JOIN",
			sql: `SELECT u.id,
       u.name,
       o.order_date
FROM users u
JOIN orders o ON u.id = o.user_id`,
			expectedViolations: 0,
		},
		{
			name: "SELECT with window functions",
			sql: `SELECT id,
       name,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewColumnAlignmentRule()
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

func TestColumnAlignmentRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Only two columns - one per line",
			sql: `SELECT id,
       name
FROM users`,
			expectedViolations: 0,
		},
		{
			name:               "Columns with tabs",
			sql:                "SELECT id,\n\tname,\n\temail\nFROM users",
			expectedViolations: 0,
		},
		{
			name:               "SELECT without FROM",
			sql:                "SELECT 1, 2, 3",
			expectedViolations: 0,
		},
		{
			name: "Empty lines between columns",
			sql: `SELECT id,

       name
FROM users`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewColumnAlignmentRule()
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
		})
	}
}

func TestColumnAlignmentRule_Fix(t *testing.T) {
	// Fix should not modify content since auto-fix is not supported
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "Should not modify misaligned columns",
			input: `SELECT id,
       name,
    email
FROM users`,
		},
		{
			name:  "Should preserve properly aligned columns",
			input: "SELECT id,\n       name,\n       email\nFROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewColumnAlignmentRule()
			violations := []linter.Violation{}

			fixed, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if fixed != tt.input {
				t.Errorf("Fix should not modify content:\nExpected: %q\nGot:      %q", tt.input, fixed)
			}
		})
	}
}

func TestColumnAlignmentRule_Metadata(t *testing.T) {
	rule := NewColumnAlignmentRule()

	if rule.ID() != "L006" {
		t.Errorf("Expected ID 'L006', got '%s'", rule.ID())
	}

	if rule.Name() != "Column Alignment" {
		t.Errorf("Expected name 'Column Alignment', got '%s'", rule.Name())
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

func TestGetIndentSize(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		expectedIndent int
	}{
		{
			name:           "No indentation",
			line:           "SELECT id",
			expectedIndent: 0,
		},
		{
			name:           "Two spaces",
			line:           "  SELECT id",
			expectedIndent: 2,
		},
		{
			name:           "Four spaces",
			line:           "    SELECT id",
			expectedIndent: 4,
		},
		{
			name:           "One tab (counted as 4 spaces)",
			line:           "\tSELECT id",
			expectedIndent: 4,
		},
		{
			name:           "Two tabs (counted as 8 spaces)",
			line:           "\t\tSELECT id",
			expectedIndent: 8,
		},
		{
			name:           "Mixed spaces and tabs",
			line:           "  \t  SELECT id",
			expectedIndent: 8, // 2 spaces + 1 tab (4) + 2 spaces = 8
		},
		{
			name:           "Empty line",
			line:           "",
			expectedIndent: 0,
		},
		{
			name:           "Only whitespace",
			line:           "    ",
			expectedIndent: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indent := getIndentSize(tt.line)
			if indent != tt.expectedIndent {
				t.Errorf("Expected indent %d, got %d", tt.expectedIndent, indent)
			}
		})
	}
}

func TestColumnAlignmentRule_Unicode(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Unicode column names aligned",
			sql: `SELECT ユーザーID,
       名前,
       メール
FROM ユーザー`,
			expectedViolations: 0,
		},
		{
			name: "Unicode column names misaligned",
			sql: `SELECT ユーザーID,
       名前,
    メール
FROM ユーザー`,
			expectedViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewColumnAlignmentRule()
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
