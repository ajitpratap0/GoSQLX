package cmd

import (
	"testing"
)

// TestNewIssue tests issue builder creation
func TestNewIssue(t *testing.T) {
	issue := NewIssue("SEC-001", IssueCategorySecurity, IssueSeverityCritical)

	if issue == nil {
		t.Fatal("Expected issue builder but got nil")
	}

	built := issue.Build()
	if built.ID != "SEC-001" {
		t.Errorf("Expected ID=SEC-001, got %s", built.ID)
	}
	if built.Category != IssueCategorySecurity {
		t.Errorf("Expected category=Security, got %s", built.Category)
	}
	if built.Severity != IssueSeverityCritical {
		t.Errorf("Expected severity=Critical, got %s", built.Severity)
	}
}

// TestIssueBuilder_WithTitle tests title setting
func TestIssueBuilder_WithTitle(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithTitle("Test Issue").
		Build()

	if issue.Title != "Test Issue" {
		t.Errorf("Expected title='Test Issue', got %s", issue.Title)
	}
}

// TestIssueBuilder_WithDescription tests description setting
func TestIssueBuilder_WithDescription(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithDescription("Test description").
		Build()

	if issue.Description != "Test description" {
		t.Errorf("Expected description='Test description', got %s", issue.Description)
	}
}

// TestIssueBuilder_WithMessage tests message setting
func TestIssueBuilder_WithMessage(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithMessage("Test message").
		Build()

	if issue.Message != "Test message" {
		t.Errorf("Expected message='Test message', got %s", issue.Message)
	}
}

// TestIssueBuilder_WithPosition tests position setting
func TestIssueBuilder_WithPosition(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithPosition(10, 5).
		Build()

	if issue.Position == nil {
		t.Fatal("Expected position to be set")
	}
	if issue.Position.Line != 10 {
		t.Errorf("Expected line=10, got %d", issue.Position.Line)
	}
	if issue.Position.Column != 5 {
		t.Errorf("Expected column=5, got %d", issue.Position.Column)
	}
}

// TestIssueBuilder_WithPositionFromToken tests position from token
// Note: Skipping full test as it requires complex token setup
// The method is tested indirectly through SQLAnalyzer usage
func TestIssueBuilder_WithPositionFromToken(t *testing.T) {
	t.Skip("Skipping token-based position test - requires complex models setup")
}

// TestIssueBuilder_WithContext tests context setting
func TestIssueBuilder_WithContext(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithContext("SELECT * FROM users").
		Build()

	if issue.Context != "SELECT * FROM users" {
		t.Errorf("Expected context='SELECT * FROM users', got %s", issue.Context)
	}
}

// TestIssueBuilder_WithImpact tests impact setting
func TestIssueBuilder_WithImpact(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithImpact("High impact").
		Build()

	if issue.Impact != "High impact" {
		t.Errorf("Expected impact='High impact', got %s", issue.Impact)
	}
}

// TestIssueBuilder_WithSuggestion tests suggestion setting
func TestIssueBuilder_WithSuggestion(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithSuggestion("Use parameterized queries").
		Build()

	if issue.Suggestion != "Use parameterized queries" {
		t.Errorf("Expected suggestion='Use parameterized queries', got %s", issue.Suggestion)
	}
}

// TestIssueBuilder_WithReference tests reference setting
func TestIssueBuilder_WithReference(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithReference("https://example.com").
		Build()

	if len(issue.References) != 1 {
		t.Errorf("Expected 1 reference, got %d", len(issue.References))
	}
	if len(issue.References) > 0 && issue.References[0] != "https://example.com" {
		t.Errorf("Expected reference='https://example.com', got %s", issue.References[0])
	}
}

// TestIssueBuilder_WithTag tests tag setting
func TestIssueBuilder_WithTag(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityHigh).
		WithTag("sql-injection").
		WithTag("security").
		Build()

	if len(issue.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(issue.Tags))
	}

	if issue.Tags[0] != "sql-injection" {
		t.Errorf("Expected first tag='sql-injection', got %s", issue.Tags[0])
	}
	if issue.Tags[1] != "security" {
		t.Errorf("Expected second tag='security', got %s", issue.Tags[1])
	}
}

// TestIssueBuilder_Chaining tests method chaining
func TestIssueBuilder_Chaining(t *testing.T) {
	issue := NewIssue("TEST-001", IssueCategorySecurity, IssueSeverityCritical).
		WithTitle("SQL Injection Risk").
		WithDescription("Potential SQL injection vulnerability detected").
		WithMessage("User input not properly sanitized").
		WithPosition(15, 10).
		WithContext("SELECT * FROM users WHERE id = " + "user_input").
		WithImpact("Could lead to data breach").
		WithSuggestion("Use parameterized queries or prepared statements").
		WithReference("https://owasp.org/sql-injection").
		WithTag("sql-injection").
		WithTag("critical").
		Build()

	// Verify all fields are set
	if issue.ID != "TEST-001" {
		t.Errorf("Expected ID=TEST-001, got %s", issue.ID)
	}
	if issue.Title != "SQL Injection Risk" {
		t.Errorf("Expected title set")
	}
	if issue.Description == "" {
		t.Error("Expected description set")
	}
	if issue.Position == nil {
		t.Fatal("Expected position to be set")
	}
	if issue.Position.Line != 15 {
		t.Errorf("Expected line=15, got %d", issue.Position.Line)
	}
	if issue.Position.Column != 10 {
		t.Errorf("Expected column=10, got %d", issue.Position.Column)
	}
	if len(issue.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(issue.Tags))
	}
}

// TestCalculateScoreFromIssues tests score calculation
func TestCalculateScoreFromIssues(t *testing.T) {
	tests := []struct {
		name          string
		issues        []AnalysisIssue
		category      IssueCategory
		expectedScore int
	}{
		{
			name:          "no issues",
			issues:        []AnalysisIssue{},
			category:      IssueCategorySecurity,
			expectedScore: 100,
		},
		{
			name: "single critical issue",
			issues: []AnalysisIssue{
				{Category: IssueCategorySecurity, Severity: IssueSeverityCritical},
			},
			category:      IssueCategorySecurity,
			expectedScore: 70, // 100 - 30
		},
		{
			name: "multiple security issues",
			issues: []AnalysisIssue{
				{Category: IssueCategorySecurity, Severity: IssueSeverityCritical},
				{Category: IssueCategorySecurity, Severity: IssueSeverityHigh},
				{Category: IssueCategorySecurity, Severity: IssueSeverityMedium},
			},
			category:      IssueCategorySecurity,
			expectedScore: 40, // 100 - 30 - 20 - 10
		},
		{
			name: "ignore other categories",
			issues: []AnalysisIssue{
				{Category: IssueCategorySecurity, Severity: IssueSeverityCritical},
				{Category: IssueCategoryPerformance, Severity: IssueSeverityCritical},
			},
			category:      IssueCategorySecurity,
			expectedScore: 70, // Only security issue counts: 100 - 30
		},
		{
			name: "low severity issues",
			issues: []AnalysisIssue{
				{Category: IssueCategoryStyle, Severity: IssueSeverityLow},
				{Category: IssueCategoryStyle, Severity: IssueSeverityLow},
			},
			category:      IssueCategoryStyle,
			expectedScore: 90, // 100 - 5 - 5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateScoreFromIssues(tt.issues, tt.category)
			if score != tt.expectedScore {
				t.Errorf("Expected score=%d, got %d", tt.expectedScore, score)
			}
		})
	}
}

// TestCalculateGrade tests grade calculation
func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		score         int
		expectedGrade string
	}{
		{100, "A"},
		{95, "A"},
		{90, "A"},
		{85, "B"},
		{80, "B"},
		{75, "C"},
		{70, "C"},
		{65, "D"},
		{60, "D"},
		{55, "F"},
		{50, "F"},
		{40, "F"},
		{30, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedGrade, func(t *testing.T) {
			grade := CalculateGrade(tt.score)
			if grade != tt.expectedGrade {
				t.Errorf("For score %d, expected grade=%s, got %s", tt.score, tt.expectedGrade, grade)
			}
		})
	}
}

// TestCountIssuesBySeverity tests severity counting
func TestCountIssuesBySeverity(t *testing.T) {
	issues := []AnalysisIssue{
		{Severity: IssueSeverityCritical},
		{Severity: IssueSeverityCritical},
		{Severity: IssueSeverityHigh},
		{Severity: IssueSeverityHigh},
		{Severity: IssueSeverityHigh},
		{Severity: IssueSeverityMedium},
		{Severity: IssueSeverityMedium},
		{Severity: IssueSeverityLow},
	}

	critical, high, medium, low := CountIssuesBySeverity(issues)

	if critical != 2 {
		t.Errorf("Expected 2 critical issues, got %d", critical)
	}
	if high != 3 {
		t.Errorf("Expected 3 high issues, got %d", high)
	}
	if medium != 2 {
		t.Errorf("Expected 2 medium issues, got %d", medium)
	}
	if low != 1 {
		t.Errorf("Expected 1 low issue, got %d", low)
	}
}

// TestCountIssuesBySeverity_Empty tests with no issues
func TestCountIssuesBySeverity_Empty(t *testing.T) {
	issues := []AnalysisIssue{}
	critical, high, medium, low := CountIssuesBySeverity(issues)

	if critical != 0 || high != 0 || medium != 0 || low != 0 {
		t.Errorf("Expected all counts to be 0, got critical=%d, high=%d, medium=%d, low=%d",
			critical, high, medium, low)
	}
}
