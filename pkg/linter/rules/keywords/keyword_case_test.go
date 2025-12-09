package keywords

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestKeywordCaseRule_Check_UpperCase(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "All uppercase keywords - no violations",
			sql:                "SELECT id, name FROM users WHERE active = TRUE",
			expectedViolations: 0,
		},
		{
			name:               "All lowercase keywords",
			sql:                "select id, name from users where active = true",
			expectedViolations: 4, // select, from, where, true
		},
		{
			name:               "Mixed case keywords",
			sql:                "Select id, name From users Where active = True",
			expectedViolations: 4, // Select, From, Where, True
		},
		{
			name:               "Complex query with joins",
			sql:                "select u.id from users u inner join orders o on u.id = o.user_id",
			expectedViolations: 5, // select, from, inner, join, on
		},
		{
			name:               "Keywords in string literals should be ignored",
			sql:                "SELECT 'select from where' FROM users",
			expectedViolations: 0,
		},
		{
			name:               "Keywords in double quoted strings should be ignored",
			sql:                `SELECT "select from where" FROM users`,
			expectedViolations: 0,
		},
		{
			name:               "Window functions with uppercase",
			sql:                "SELECT ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary) FROM employees",
			expectedViolations: 0,
		},
		{
			name:               "Window functions with lowercase",
			sql:                "select row_number() over (partition by dept order by salary) from employees",
			expectedViolations: 7, // select, over, partition, by, order, by, from
		},
		{
			name:               "CTE with uppercase",
			sql:                "WITH cte AS (SELECT id FROM users) SELECT * FROM cte",
			expectedViolations: 0,
		},
		{
			name:               "CTE with lowercase",
			sql:                "with cte as (select id from users) select * from cte",
			expectedViolations: 6, // with, as, select, from, select, from
		},
		{
			name:               "Empty SQL",
			sql:                "",
			expectedViolations: 0,
		},
		{
			name:               "Only identifiers, no keywords",
			sql:                "id, name, email",
			expectedViolations: 0,
		},
		{
			name:               "MERGE statement with uppercase",
			sql:                "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET value = 1",
			expectedViolations: 0,
		},
		{
			name:               "GROUPING SETS with uppercase",
			sql:                "SELECT region, product FROM sales GROUP BY GROUPING SETS (region, product)",
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseUpper)
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
				if v.Rule != "L007" {
					t.Errorf("Expected rule ID 'L007', got '%s'", v.Rule)
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

func TestKeywordCaseRule_Check_LowerCase(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "All lowercase keywords - no violations",
			sql:                "select id, name from users where active = true",
			expectedViolations: 0,
		},
		{
			name:               "All uppercase keywords",
			sql:                "SELECT id, name FROM users WHERE active = TRUE",
			expectedViolations: 4, // SELECT, FROM, WHERE, TRUE
		},
		{
			name:               "Mixed case keywords",
			sql:                "Select id, name From users Where active = True",
			expectedViolations: 4, // Select, From, Where, True
		},
		{
			name:               "Complex query with joins",
			sql:                "SELECT u.id FROM users u INNER JOIN orders o ON u.id = o.user_id",
			expectedViolations: 5, // SELECT, FROM, INNER, JOIN, ON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseLower)
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

func TestKeywordCaseRule_Fix_UpperCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Convert lowercase to uppercase",
			input:    "select id, name from users where active = true",
			expected: "SELECT id, name FROM users WHERE active = TRUE",
		},
		{
			name:     "Fix mixed case keywords",
			input:    "Select id From users Where active = True",
			expected: "SELECT id FROM users WHERE active = TRUE",
		},
		{
			name:     "Preserve uppercase keywords",
			input:    "SELECT id FROM users",
			expected: "SELECT id FROM users",
		},
		{
			name:     "Preserve identifiers case",
			input:    "select UserId, UserName from Users",
			expected: "SELECT UserId, UserName FROM Users",
		},
		{
			name:     "Preserve strings",
			input:    "select 'select from where' from users",
			expected: "SELECT 'select from where' FROM users",
		},
		{
			name:     "Complex query with joins",
			input:    "select u.id from users u inner join orders o on u.id = o.user_id",
			expected: "SELECT u.id FROM users u INNER JOIN orders o ON u.id = o.user_id",
		},
		{
			name:     "Window functions",
			input:    "select row_number() over (partition by dept order by salary) from employees",
			expected: "SELECT row_number() OVER (PARTITION BY dept ORDER BY salary) FROM employees",
		},
		{
			name:     "Empty SQL",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseUpper)
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

func TestKeywordCaseRule_Fix_LowerCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Convert uppercase to lowercase",
			input:    "SELECT id, name FROM users WHERE active = TRUE",
			expected: "select id, name from users where active = true",
		},
		{
			name:     "Fix mixed case keywords",
			input:    "Select id From users Where active = True",
			expected: "select id from users where active = true",
		},
		{
			name:     "Preserve lowercase keywords",
			input:    "select id from users",
			expected: "select id from users",
		},
		{
			name:     "Preserve identifiers case",
			input:    "SELECT UserId, UserName FROM Users",
			expected: "select UserId, UserName from Users",
		},
		{
			name:     "Preserve strings",
			input:    "SELECT 'SELECT FROM WHERE' FROM users",
			expected: "select 'SELECT FROM WHERE' from users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseLower)
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

func TestKeywordCaseRule_DefaultStyle(t *testing.T) {
	// Test that default style is uppercase
	rule := NewKeywordCaseRule("")
	ctx := linter.NewContext("select id from users", "test.sql")

	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(violations) == 0 {
		t.Error("Expected violations for lowercase keywords with default (uppercase) style")
	}
}

func TestKeywordCaseRule_Metadata(t *testing.T) {
	rule := NewKeywordCaseRule(CaseUpper)

	if rule.ID() != "L007" {
		t.Errorf("Expected ID 'L007', got '%s'", rule.ID())
	}

	if rule.Name() != "Keyword Case Consistency" {
		t.Errorf("Expected name 'Keyword Case Consistency', got '%s'", rule.Name())
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

func TestKeywordCaseRule_Unicode(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name:               "Unicode identifiers with uppercase keywords",
			sql:                "SELECT ユーザー名, 年齢 FROM テーブル WHERE アクティブ = TRUE",
			expectedViolations: 0,
		},
		{
			name:               "Unicode identifiers with lowercase keywords",
			sql:                "select ユーザー名, 年齢 from テーブル where アクティブ = true",
			expectedViolations: 4, // select, from, where, true
		},
		{
			name:               "Unicode in string literals",
			sql:                "SELECT '日本語のテキスト' FROM users",
			expectedViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseUpper)
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

func TestKeywordCaseRule_MultiLine(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		expectedViolations int
	}{
		{
			name: "Multi-line query with uppercase",
			sql: `SELECT id, name
FROM users
WHERE active = TRUE
ORDER BY id`,
			expectedViolations: 0,
		},
		{
			name: "Multi-line query with lowercase",
			sql: `select id, name
from users
where active = true
order by id`,
			expectedViolations: 6, // select, from, where, true, order, by
		},
		{
			name: "Multi-line with mixed case",
			sql: `Select id, name
From users
Where active = True`,
			expectedViolations: 4, // Select, From, Where, True
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewKeywordCaseRule(CaseUpper)
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

func TestTokenizeLine(t *testing.T) {
	tests := []struct {
		name          string
		line          string
		expectedWords []string
	}{
		{
			name:          "Simple query",
			line:          "SELECT id FROM users",
			expectedWords: []string{"SELECT", "id", "FROM", "users"},
		},
		{
			name:          "Query with string literal",
			line:          "SELECT 'hello world' FROM users",
			expectedWords: []string{"SELECT", "FROM", "users"},
		},
		{
			name:          "Query with punctuation",
			line:          "SELECT id, name, email FROM users",
			expectedWords: []string{"SELECT", "id", "name", "email", "FROM", "users"},
		},
		{
			name:          "Empty line",
			line:          "",
			expectedWords: []string{},
		},
		{
			name:          "Identifiers with underscores",
			line:          "SELECT user_id, first_name FROM user_table",
			expectedWords: []string{"SELECT", "user_id", "first_name", "FROM", "user_table"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words := tokenizeLine(tt.line)
			if len(words) != len(tt.expectedWords) {
				t.Errorf("Expected %d words, got %d", len(tt.expectedWords), len(words))
			}
			for i, word := range words {
				if i >= len(tt.expectedWords) {
					break
				}
				if word.text != tt.expectedWords[i] {
					t.Errorf("Word %d: expected '%s', got '%s'", i, tt.expectedWords[i], word.text)
				}
			}
		})
	}
}
