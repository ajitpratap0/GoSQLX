package style

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestCommaPlacementRule_Check_TrailingStyle(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Single line - no violations",
			sql:                "SELECT id, name, email FROM users",
			expectedViolations: 0,
		},
		{
			name: "Trailing commas - no violations",
			sql: `SELECT id,
       name,
       email
FROM users`,
			expectedViolations: 0,
		},
		{
			name: "Leading commas - violations",
			sql: `SELECT id
       , name
       , email
FROM users`,
			expectedViolations: 2, // Two leading commas
		},
		{
			name: "Mixed trailing - no violations",
			sql: `SELECT id, name,
       email, address
FROM users`,
			expectedViolations: 0,
		},
		{
			name:               "Empty SQL",
			sql:                "",
			expectedViolations: 0,
		},
		{
			name: "Commas in VALUES clause",
			sql: `INSERT INTO users (id, name, email)
VALUES (1, 'John', 'john@example.com')`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(CommaTrailing)
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
				if v.Rule != "L008" {
					t.Errorf("Expected rule ID 'L008', got '%s'", v.Rule)
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

func TestCommaPlacementRule_Check_LeadingStyle(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Single line - no violations",
			sql:                "SELECT id, name, email FROM users",
			expectedViolations: 0,
		},
		{
			name: "Leading commas - no violations",
			sql: `SELECT id
       , name
       , email
FROM users`,
			expectedViolations: 0,
		},
		{
			name: "Trailing commas - violations",
			sql: `SELECT id,
       name,
       email
FROM users`,
			expectedViolations: 2, // Two trailing commas (last one before FROM doesn't count)
		},
		{
			name: "Mixed leading - no violations",
			sql: `SELECT id
       , name
       , email
FROM users`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(CommaLeading)
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

func TestCommaPlacementRule_DefaultStyle(t *testing.T) {
	// Test that default style is trailing
	rule := NewCommaPlacementRule("")
	ctx := linter.NewContext("SELECT id\n, name\nFROM users", "test.sql")

	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(violations) == 0 {
		t.Error("Expected violations for leading commas with default (trailing) style")
	}
}

func TestCommaPlacementRule_ComplexQueries(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		style              CommaStyle
		expectedViolations int
	}{
		{
			name: "SELECT with JOIN - trailing commas",
			sql: `SELECT u.id,
       u.name,
       o.order_date
FROM users u
JOIN orders o ON u.id = o.user_id`,
			style:              CommaTrailing,
			expectedViolations: 0,
		},
		{
			name: "SELECT with GROUP BY - trailing commas",
			sql: `SELECT region,
       product,
       SUM(sales)
FROM orders
GROUP BY region,
         product`,
			style:              CommaTrailing,
			expectedViolations: 0,
		},
		{
			name: "CTE with trailing commas",
			sql: `WITH cte AS (
    SELECT id,
           name,
           email
    FROM users
)
SELECT * FROM cte`,
			style:              CommaTrailing,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(tt.style)
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

func TestCommaPlacementRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		style              CommaStyle
		expectedViolations int
	}{
		{
			name:               "Line with only comma",
			sql:                "SELECT id\n,\nFROM users",
			style:              CommaTrailing,
			expectedViolations: 0, // Comma alone on line is skipped
		},
		{
			name:               "No commas",
			sql:                "SELECT id FROM users",
			style:              CommaTrailing,
			expectedViolations: 0,
		},
		{
			name:               "Comma at end of last line before keyword",
			sql:                "SELECT id, name,\nFROM users",
			style:              CommaTrailing,
			expectedViolations: 0,
		},
		{
			name:               "Multiple commas on one line",
			sql:                "SELECT id, name, email,\n       address\nFROM users",
			style:              CommaTrailing,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(tt.style)
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

func TestCommaPlacementRule_Fix(t *testing.T) {
	// Fix should not modify content since auto-fix is not supported
	tests := []struct {
		name  string
		input string
		style CommaStyle
	}{
		{
			name:  "Should not modify trailing commas",
			input: "SELECT id,\n       name,\n       email\nFROM users",
			style: CommaTrailing,
		},
		{
			name:  "Should not modify leading commas",
			input: "SELECT id\n       , name\n       , email\nFROM users",
			style: CommaLeading,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(tt.style)
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

func TestCommaPlacementRule_Metadata(t *testing.T) {
	rule := NewCommaPlacementRule(CommaTrailing)

	if rule.ID() != "L008" {
		t.Errorf("Expected ID 'L008', got '%s'", rule.ID())
	}

	if rule.Name() != "Comma Placement" {
		t.Errorf("Expected name 'Comma Placement', got '%s'", rule.Name())
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

func TestIsNewClause(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		isClause bool
	}{
		{
			name:     "SELECT clause",
			line:     "SELECT id",
			isClause: true,
		},
		{
			name:     "FROM clause",
			line:     "FROM users",
			isClause: true,
		},
		{
			name:     "WHERE clause",
			line:     "WHERE active = true",
			isClause: true,
		},
		{
			name:     "JOIN clause",
			line:     "JOIN orders ON users.id = orders.user_id",
			isClause: true,
		},
		{
			name:     "LEFT JOIN",
			line:     "LEFT JOIN orders",
			isClause: true,
		},
		{
			name:     "ORDER BY",
			line:     "ORDER BY id",
			isClause: true,
		},
		{
			name:     "GROUP BY",
			line:     "GROUP BY region",
			isClause: true,
		},
		{
			name:     "UNION",
			line:     "UNION",
			isClause: true,
		},
		{
			name:     "Not a clause - column name",
			line:     "id, name",
			isClause: false,
		},
		{
			name:     "Not a clause - identifier",
			line:     "users",
			isClause: false,
		},
		{
			name:     "Empty line",
			line:     "",
			isClause: false,
		},
		{
			name:     "Lowercase clause",
			line:     "select id",
			isClause: true,
		},
		{
			name:     "Mixed case clause",
			line:     "Select id",
			isClause: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNewClause(tt.line)
			if result != tt.isClause {
				t.Errorf("Expected isNewClause to return %v for '%s', got %v", tt.isClause, tt.line, result)
			}
		})
	}
}

func TestCommaPlacementRule_Unicode(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		style              CommaStyle
		expectedViolations int
	}{
		{
			name: "Unicode identifiers with trailing commas",
			sql: `SELECT ユーザーID,
       名前,
       メール
FROM ユーザー`,
			style:              CommaTrailing,
			expectedViolations: 0,
		},
		{
			name: "Unicode identifiers with leading commas",
			sql: `SELECT ユーザーID
       , 名前
       , メール
FROM ユーザー`,
			style:              CommaLeading,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewCommaPlacementRule(tt.style)
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
