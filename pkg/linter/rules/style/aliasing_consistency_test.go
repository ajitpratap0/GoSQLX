package style

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestAliasingConsistencyRule_Check_TextBased(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "No aliases - no violations",
			sql:                "SELECT id, name FROM users WHERE active = true",
			expectedViolations: 0,
		},
		{
			name:               "Consistent explicit AS aliases",
			sql:                "SELECT u.id, u.name FROM users AS u WHERE u.active = true",
			expectedViolations: 0,
		},
		{
			name:               "Consistent implicit aliases",
			sql:                "SELECT u.id, u.name FROM users u WHERE u.active = true",
			expectedViolations: 0,
		},
		{
			name:               "Multiple tables with aliases",
			sql:                "SELECT u.id, o.order_date FROM users u JOIN orders o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "Multiple tables with explicit AS",
			sql:                "SELECT u.id, o.order_date FROM users AS u JOIN orders AS o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "Empty SQL",
			sql:                "",
			expectedViolations: 0,
		},
		{
			name:               "Simple SELECT without FROM",
			sql:                "SELECT 1, 2, 3",
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(true)
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
				if v.Rule != "L009" {
					t.Errorf("Expected rule ID 'L009', got '%s'", v.Rule)
				}
				if v.Severity != linter.SeverityWarning {
					t.Errorf("Expected severity 'warning', got '%s'", v.Severity)
				}
				if v.CanAutoFix {
					t.Error("Expected CanAutoFix to be false")
				}
			}
		})
	}
}

func TestAliasingConsistencyRule_MultiLine(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Multi-line with aliases",
			sql: `SELECT u.id, u.name, o.order_date
FROM users AS u
JOIN orders AS o ON u.id = o.user_id
WHERE u.active = true`,
			expectedViolations: 0,
		},
		{
			name: "Multi-line implicit aliases",
			sql: `SELECT u.id, u.name, o.order_date
FROM users u
JOIN orders o ON u.id = o.user_id`,
			expectedViolations: 0,
		},
		{
			name: "Complex multi-line query",
			sql: `SELECT u.id, u.name, o.order_date, p.product_name
FROM users u
INNER JOIN orders o ON u.id = o.user_id
LEFT JOIN products p ON o.product_id = p.id
WHERE u.active = true
ORDER BY o.order_date DESC`,
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(true)
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

func TestAliasingConsistencyRule_JoinTypes(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "INNER JOIN with aliases",
			sql:                "SELECT u.id FROM users u INNER JOIN orders o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "LEFT JOIN with aliases",
			sql:                "SELECT u.id FROM users u LEFT JOIN orders o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "RIGHT JOIN with aliases",
			sql:                "SELECT u.id FROM users u RIGHT JOIN orders o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "FULL OUTER JOIN with aliases",
			sql:                "SELECT u.id FROM users u FULL OUTER JOIN orders o ON u.id = o.user_id",
			expectedViolations: 0,
		},
		{
			name:               "CROSS JOIN with aliases",
			sql:                "SELECT u.id FROM users u CROSS JOIN orders o",
			expectedViolations: 0,
		},
		{
			name:               "Multiple joins",
			sql:                "SELECT u.id FROM users u JOIN orders o ON u.id = o.user_id JOIN products p ON o.product_id = p.id",
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(true)
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

func TestAliasingConsistencyRule_Fix(t *testing.T) {
	// Fix should not modify content since auto-fix is not supported
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Should not modify content",
			input: "SELECT u.id FROM users u",
		},
		{
			name:  "Should preserve complex query",
			input: "SELECT u.id, o.order_date FROM users AS u JOIN orders AS o ON u.id = o.user_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(true)
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

func TestAliasingConsistencyRule_Metadata(t *testing.T) {
	rule := NewAliasingConsistencyRule(true)

	if rule.ID() != "L009" {
		t.Errorf("Expected ID 'L009', got '%s'", rule.ID())
	}

	if rule.Name() != "Aliasing Consistency" {
		t.Errorf("Expected name 'Aliasing Consistency', got '%s'", rule.Name())
	}

	if rule.Severity() != linter.SeverityWarning {
		t.Errorf("Expected severity 'warning', got '%s'", rule.Severity())
	}

	if rule.CanAutoFix() {
		t.Error("Expected CanAutoFix to be false")
	}

	if rule.Description() == "" {
		t.Error("Expected non-empty description")
	}
}

func TestAliasingConsistencyRule_Unicode(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Unicode table names with aliases",
			sql:                "SELECT u.ユーザー名 FROM ユーザーテーブル u WHERE u.アクティブ = true",
			expectedViolations: 0,
		},
		{
			name:               "Unicode identifiers in joins",
			sql:                "SELECT u.名前, o.日付 FROM ユーザー u JOIN 注文 o ON u.id = o.ユーザーID",
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(true)
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

func TestTokenizeForAliases(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectedWords []string
	}{
		{
			name:          "Simple FROM clause",
			line:          "FROM users u",
			expectedWords: []string{"FROM", "users", "u"},
		},
		{
			name:          "FROM with AS",
			line:          "FROM users AS u",
			expectedWords: []string{"FROM", "users", "AS", "u"},
		},
		{
			name:          "JOIN clause",
			line:          "JOIN orders o ON u.id = o.user_id",
			expectedWords: []string{"JOIN", "orders", "o", "ON", "u.id", "=", "o.user_id"},
		},
		{
			name:          "Query with string literal",
			line:          "FROM users WHERE name = 'John Doe'",
			expectedWords: []string{"FROM", "users", "WHERE", "name", "="},
		},
		{
			name:          "Empty line",
			line:          "",
			expectedWords: []string{},
		},
		{
			name:          "Line with commas",
			line:          "SELECT id, name, email",
			expectedWords: []string{"SELECT", "id", ",", "name", ",", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words := tokenizeForAliases(tt.line)
			if len(words) != len(tt.expectedWords) {
				t.Errorf("Expected %d words, got %d: %v", len(tt.expectedWords), len(words), words)
			}
			for i, word := range words {
				if i >= len(tt.expectedWords) {
					break
				}
				if word != tt.expectedWords[i] {
					t.Errorf("Word %d: expected '%s', got '%s'", i, tt.expectedWords[i], word)
				}
			}
		})
	}
}

func TestAliasingConsistencyRule_ExplicitVsImplicit(t *testing.T) {
	tests := []struct {
		name              string
		sql               string
		preferExplicitAS  bool
		expectsViolations bool
	}{
		{
			name:              "Explicit AS preferred, using explicit AS",
			sql:               "SELECT u.id FROM users AS u",
			preferExplicitAS:  true,
			expectsViolations: false,
		},
		{
			name:              "Implicit preferred, using implicit",
			sql:               "SELECT u.id FROM users u",
			preferExplicitAS:  false,
			expectsViolations: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewAliasingConsistencyRule(tt.preferExplicitAS)
			ctx := linter.NewContext(tt.sql, "test.sql")

			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			hasViolations := len(violations) > 0
			if hasViolations != tt.expectsViolations {
				t.Errorf("Expected violations: %v, got violations: %v (count: %d)",
					tt.expectsViolations, hasViolations, len(violations))
			}
		})
	}
}
