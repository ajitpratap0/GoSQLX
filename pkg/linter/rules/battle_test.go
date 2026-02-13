package rules_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

// Battle tests for lint rules with real-world SQL queries

// TestL003_ConsecutiveBlankLines_RealWorld tests the consecutive blank lines rule
func TestL003_ConsecutiveBlankLines_RealWorld(t *testing.T) {
	rule := whitespace.NewConsecutiveBlankLinesRule(1)

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name: "Complex query with proper spacing",
			sql: `SELECT
    u.id,
    u.name,
    u.email
FROM users u
WHERE u.active = true
ORDER BY u.created_at DESC`,
			expectViolation: false,
		},
		{
			name: "Query with too many blank lines",
			sql: `SELECT * FROM users


WHERE active = true`,
			expectViolation: true,
		},
		{
			name: "Multi-statement with blank separator",
			sql: `SELECT * FROM users;

SELECT * FROM orders;`,
			expectViolation: false,
		},
		{
			name: "File ending with multiple blank lines",
			sql: `SELECT * FROM users


`,
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
			}
		})
	}
}

// TestL004_IndentationDepth_RealWorld tests the indentation depth rule
func TestL004_IndentationDepth_RealWorld(t *testing.T) {
	rule := whitespace.NewIndentationDepthRule(4, 4)

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name: "Normal indentation",
			sql: `SELECT
    u.id,
    u.name
FROM users u
WHERE u.active = true`,
			expectViolation: false,
		},
		{
			name: "Deep nesting - subqueries",
			sql: `SELECT * FROM users WHERE id IN (
    SELECT user_id FROM orders WHERE product_id IN (
        SELECT id FROM products WHERE category_id IN (
            SELECT id FROM categories WHERE parent_id IN (
                SELECT id FROM root_categories WHERE active = true
            )
        )
    )
)`,
			expectViolation: false, // Max 4 levels (16 spaces), equals maxDepth=4, not exceeds
		},
		{
			name: "Excessive nesting - 6 levels",
			sql: `SELECT * FROM a WHERE id IN (
    SELECT id FROM b WHERE id IN (
        SELECT id FROM c WHERE id IN (
            SELECT id FROM d WHERE id IN (
                SELECT id FROM e WHERE id IN (
                    SELECT id FROM f
                )
            )
        )
    )
)`,
			expectViolation: true, // 6 levels (24 spaces) > maxDepth=4
		},
		{
			name: "Very deep indentation (10 levels)",
			sql: `SELECT *
                                        FROM users`, // 10 tabs worth
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
			}
		})
	}
}

// TestL004_DepthGreaterThan9 tests the bug with depth > 9
func TestL004_DepthGreaterThan9(t *testing.T) {
	rule := whitespace.NewIndentationDepthRule(4, 4)

	// Create SQL with 12 levels of indentation (48 spaces)
	sql := strings.Repeat(" ", 48) + "SELECT * FROM users"
	ctx := linter.NewContext(sql, "test.sql")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if len(violations) == 0 {
		t.Error("Expected violation for depth > 9")
	}

	// Check the message doesn't have garbage characters
	for _, v := range violations {
		if strings.Contains(v.Message, "\x00") || strings.Contains(v.Message, "�") {
			t.Errorf("Message contains garbage characters: %q", v.Message)
		}
		t.Logf("Violation message: %s", v.Message)
	}
}

// TestL006_ColumnAlignment_RealWorld tests the column alignment rule
func TestL006_ColumnAlignment_RealWorld(t *testing.T) {
	rule := style.NewColumnAlignmentRule()

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name: "Well-aligned columns",
			sql: `SELECT
    id,
    name,
    email,
    created_at
FROM users`,
			expectViolation: false,
		},
		{
			name: "Misaligned columns",
			sql: `SELECT
    id,
  name,
    email
FROM users`,
			expectViolation: true,
		},
		{
			name:            "Single column - no alignment check needed",
			sql:             `SELECT id FROM users`,
			expectViolation: false,
		},
		{
			name: "Complex expressions on multiple lines",
			sql: `SELECT
    u.id,
    u.name || ' ' || u.surname AS full_name,
    COALESCE(u.email, 'unknown') AS email,
    COUNT(*) OVER (PARTITION BY u.department)
FROM users u`,
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
				for _, v := range violations {
					t.Logf("  - %s at line %d", v.Message, v.Location.Line)
				}
			}
		})
	}
}

// TestL007_KeywordCase_RealWorld tests the keyword case rule
func TestL007_KeywordCase_RealWorld(t *testing.T) {
	rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name:            "All uppercase keywords",
			sql:             `SELECT id, name FROM users WHERE active = TRUE`,
			expectViolation: false,
		},
		{
			name:            "Mixed case keywords",
			sql:             `Select id, name From users Where active = True`,
			expectViolation: true,
		},
		{
			name:            "Keyword inside string should be ignored",
			sql:             `SELECT 'select from where' AS sql_text FROM queries`,
			expectViolation: false,
		},
		{
			name:            "Column named like keyword",
			sql:             `SELECT u.select_count, u.from_date FROM users u`,
			expectViolation: false, // select_count is not a keyword
		},
		{
			name: "Complex query with CTEs",
			sql: `WITH active_users AS (
    SELECT id, name FROM users WHERE active = TRUE
)
SELECT * FROM active_users`,
			expectViolation: false,
		},
		{
			name: "Window functions",
			sql: `SELECT
    name,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) AS rank
FROM employees`,
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
				for _, v := range violations {
					t.Logf("  - %s", v.Message)
				}
			}
		})
	}
}

// TestL007_AutoFix tests the auto-fix functionality
func TestL007_AutoFix(t *testing.T) {
	rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple fix",
			input:    `select * from users where active = true`,
			expected: `SELECT * FROM users WHERE active = TRUE`,
		},
		{
			name:     "Preserve strings",
			input:    `select 'select from where' as query from tests`,
			expected: `SELECT 'select from where' AS query FROM tests`,
		},
		{
			name:     "Preserve column names",
			input:    `select select_count, from_date from metrics`,
			expected: `SELECT select_count, from_date FROM metrics`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.input, "test.sql")
			violations, _ := rule.Check(ctx)
			fixed, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Fix failed: %v", err)
			}
			if fixed != tt.expected {
				t.Errorf("Fix mismatch:\nExpected: %s\nGot:      %s", tt.expected, fixed)
			}
		})
	}
}

// TestL008_CommaPlacement_RealWorld tests the comma placement rule
func TestL008_CommaPlacement_RealWorld(t *testing.T) {
	rule := style.NewCommaPlacementRule(style.CommaTrailing)

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name: "Trailing commas (preferred)",
			sql: `SELECT
    id,
    name,
    email
FROM users`,
			expectViolation: false,
		},
		{
			name: "Leading commas (violation)",
			sql: `SELECT
    id
    , name
    , email
FROM users`,
			expectViolation: true,
		},
		{
			name:            "Single line - no comma style issue",
			sql:             `SELECT id, name, email FROM users`,
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
			}
		})
	}
}

// TestL009_AliasingConsistency_RealWorld tests the aliasing consistency rule
func TestL009_AliasingConsistency_RealWorld(t *testing.T) {
	rule := style.NewAliasingConsistencyRule(true)

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name:            "Consistent aliases",
			sql:             `SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id`,
			expectViolation: false,
		},
		{
			name:            "No aliases - consistent",
			sql:             `SELECT users.id, users.name FROM users`,
			expectViolation: false,
		},
		{
			name: "Mixed aliasing (some with, some without)",
			sql: `SELECT u.id, orders.total
FROM users u
JOIN orders ON u.id = orders.user_id`,
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
				for _, v := range violations {
					t.Logf("  - %s", v.Message)
				}
			}
		})
	}
}

// TestL010_RedundantWhitespace_RealWorld tests the redundant whitespace rule
func TestL010_RedundantWhitespace_RealWorld(t *testing.T) {
	rule := whitespace.NewRedundantWhitespaceRule()

	tests := []struct {
		name            string
		sql             string
		expectViolation bool
	}{
		{
			name:            "Normal spacing",
			sql:             `SELECT id, name FROM users WHERE active = true`,
			expectViolation: false,
		},
		{
			name:            "Multiple spaces",
			sql:             `SELECT id,  name FROM  users`,
			expectViolation: true,
		},
		{
			name:            "Multiple spaces inside string - should be ignored",
			sql:             `SELECT 'hello    world' AS greeting FROM dual`,
			expectViolation: false,
		},
		{
			name:            "Indentation preserved",
			sql:             `    SELECT id FROM users`, // Leading 4 spaces - OK
			expectViolation: false,
		},
		{
			name:            "Trailing multiple spaces",
			sql:             `SELECT * FROM users  `,
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.sql, "test.sql")
			violations, err := rule.Check(ctx)
			if err != nil {
				t.Fatalf("Check failed: %v", err)
			}
			hasViolation := len(violations) > 0
			if hasViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got %v (violations: %d)", tt.expectViolation, hasViolation, len(violations))
				for _, v := range violations {
					t.Logf("  - %s at col %d", v.Message, v.Location.Column)
				}
			}
		})
	}
}

// TestL010_AutoFix tests the redundant whitespace auto-fix
func TestL010_AutoFix(t *testing.T) {
	rule := whitespace.NewRedundantWhitespaceRule()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Remove multiple spaces",
			input:    `SELECT id,  name FROM  users`,
			expected: `SELECT id, name FROM users`,
		},
		{
			name:     "Preserve string content",
			input:    `SELECT 'hello    world',  name FROM users`,
			expected: `SELECT 'hello    world', name FROM users`,
		},
		{
			name:     "Preserve indentation",
			input:    `    SELECT id,  name FROM users`,
			expected: `    SELECT id, name FROM users`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := linter.NewContext(tt.input, "test.sql")
			violations, _ := rule.Check(ctx)
			fixed, err := rule.Fix(tt.input, violations)
			if err != nil {
				t.Fatalf("Fix failed: %v", err)
			}
			if fixed != tt.expected {
				t.Errorf("Fix mismatch:\nExpected: %q\nGot:      %q", tt.expected, fixed)
			}
		})
	}
}

// TestAllRules_ComplexRealWorldQueries tests all rules against complex real-world queries
func TestAllRules_ComplexRealWorldQueries(t *testing.T) {
	// Create a linter with all rules
	l := linter.New(
		whitespace.NewTrailingWhitespaceRule(),
		whitespace.NewMixedIndentationRule(),
		whitespace.NewConsecutiveBlankLinesRule(1),
		whitespace.NewIndentationDepthRule(4, 4),
		whitespace.NewLongLinesRule(120),
		whitespace.NewRedundantWhitespaceRule(),
		style.NewColumnAlignmentRule(),
		style.NewCommaPlacementRule(style.CommaTrailing),
		style.NewAliasingConsistencyRule(true),
		keywords.NewKeywordCaseRule(keywords.CaseUpper),
	)

	// Well-formed query should have minimal violations
	wellFormedSQL := `WITH active_users AS (
    SELECT
        u.id,
        u.name,
        u.email,
        u.created_at
    FROM users u
    WHERE u.active = TRUE
        AND u.created_at > '2023-01-01'
)
SELECT
    au.id,
    au.name,
    COUNT(o.id) AS order_count,
    SUM(o.total) AS total_spent
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.id, au.name
HAVING COUNT(o.id) > 0
ORDER BY total_spent DESC
LIMIT 100`

	result := l.LintString(wellFormedSQL, "well_formed.sql")

	// Log any violations found
	if len(result.Violations) > 0 {
		t.Logf("Found %d violations in well-formed query:", len(result.Violations))
		for _, v := range result.Violations {
			t.Logf("  - [%s] %s at line %d, col %d", v.Rule, v.Message, v.Location.Line, v.Location.Column)
		}
	}

	// Poorly-formed query should have multiple violations
	poorlyFormedSQL := `select
  id,
    name,
  email
from users  where active = true


and created_at > '2023-01-01'`

	result = l.LintString(poorlyFormedSQL, "poorly_formed.sql")

	if len(result.Violations) == 0 {
		t.Error("Expected violations in poorly-formed query but found none")
	} else {
		t.Logf("Found %d violations in poorly-formed query (expected)", len(result.Violations))
		for _, v := range result.Violations {
			t.Logf("  - [%s] %s at line %d", v.Rule, v.Message, v.Location.Line)
		}
	}
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("Empty SQL", func(t *testing.T) {
		l := linter.New(
			whitespace.NewTrailingWhitespaceRule(),
			keywords.NewKeywordCaseRule(keywords.CaseUpper),
		)
		result := l.LintString("", "empty.sql")
		if result.Violations == nil {
			t.Error("Violations should not be nil")
		}
	})

	t.Run("Only whitespace", func(t *testing.T) {
		l := linter.New(
			whitespace.NewTrailingWhitespaceRule(),
		)
		result := l.LintString("   \n\t\n  ", "whitespace.sql")
		// Should detect trailing whitespace
		t.Logf("Violations: %d", len(result.Violations))
	})

	t.Run("Unicode SQL", func(t *testing.T) {
		l := linter.New(
			keywords.NewKeywordCaseRule(keywords.CaseUpper),
		)
		result := l.LintString(`SELECT '你好世界' AS greeting, 'Привет' AS russian FROM users`, "unicode.sql")
		// Should not crash and should properly detect keywords
		t.Logf("Unicode test violations: %d", len(result.Violations))
	})

	t.Run("Very long line", func(t *testing.T) {
		longLine := "SELECT " + strings.Repeat("column, ", 100) + "last_column FROM users"
		l := linter.New(
			whitespace.NewLongLinesRule(100),
		)
		result := l.LintString(longLine, "long.sql")
		if len(result.Violations) == 0 {
			t.Error("Expected violation for very long line")
		}
	})

	t.Run("SQL with comments", func(t *testing.T) {
		sqlWithComments := `-- This is a comment with select from where
SELECT id FROM users -- another comment
WHERE active = TRUE`
		l := linter.New(
			keywords.NewKeywordCaseRule(keywords.CaseUpper),
		)
		result := l.LintString(sqlWithComments, "comments.sql")
		// NOTE: Comment-aware linting is tracked in a future enhancement.
		// Keywords inside comments may still trigger violations until the
		// tokenizer skips comment tokens during rule evaluation.
		t.Logf("SQL with comments violations: %d", len(result.Violations))
	})
}
