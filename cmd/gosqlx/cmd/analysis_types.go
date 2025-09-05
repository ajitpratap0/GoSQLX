package cmd

import (
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// IssueCategory represents the category of analysis issue
type IssueCategory string

const (
	IssueCategorySecurity      IssueCategory = "security"
	IssueCategoryPerformance   IssueCategory = "performance"
	IssueCategoryComplexity    IssueCategory = "complexity"
	IssueCategoryStyle         IssueCategory = "style"
	IssueCategoryCompatibility IssueCategory = "compatibility"
)

// IssueSeverity represents the severity level of an issue
type IssueSeverity string

const (
	IssueSeverityCritical IssueSeverity = "critical"
	IssueSeverityHigh     IssueSeverity = "high"
	IssueSeverityMedium   IssueSeverity = "medium"
	IssueSeverityLow      IssueSeverity = "low"
	IssueSeverityInfo     IssueSeverity = "info"
)

// SourcePosition represents a position in the source code
type SourcePosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset,omitempty"`
	Length int `json:"length,omitempty"`
}

// AnalysisIssue represents a unified issue found during SQL analysis
type AnalysisIssue struct {
	ID          string          `json:"id"`                   // Unique identifier for the issue type
	Category    IssueCategory   `json:"category"`             // Category of the issue
	Severity    IssueSeverity   `json:"severity"`             // Severity level
	Title       string          `json:"title"`                // Short description
	Description string          `json:"description"`          // Detailed description
	Message     string          `json:"message,omitempty"`    // Context-specific message
	Position    *SourcePosition `json:"position,omitempty"`   // Source code position
	Context     string          `json:"context,omitempty"`    // Source code snippet
	Impact      string          `json:"impact,omitempty"`     // Impact description
	Suggestion  string          `json:"suggestion,omitempty"` // How to fix
	References  []string        `json:"references,omitempty"` // Documentation links
	Tags        []string        `json:"tags,omitempty"`       // Additional metadata tags
}

// ComplexityMetrics represents unified complexity measurements
type ComplexityMetrics struct {
	CyclomaticComplexity int     `json:"cyclomatic_complexity"` // Cyclomatic complexity
	NestingDepth         int     `json:"nesting_depth"`         // Maximum nesting depth
	JoinComplexity       int     `json:"join_complexity"`       // Number of JOINs
	SubqueryDepth        int     `json:"subquery_depth"`        // Maximum subquery nesting
	FunctionCount        int     `json:"function_count"`        // Number of function calls
	OverallComplexity    string  `json:"overall_complexity"`    // LOW, MEDIUM, HIGH, VERY_HIGH
	ComplexityScore      float64 `json:"complexity_score"`      // Numeric score
}

// AnalysisReport represents the complete unified analysis results
type AnalysisReport struct {
	// Metadata
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	QueryHash string    `json:"query_hash,omitempty"`

	// Query Information
	Query QueryInfo `json:"query"`

	// Analysis Results
	Issues            []AnalysisIssue   `json:"issues"`
	ComplexityMetrics ComplexityMetrics `json:"complexity_metrics"`

	// Scores (0-100)
	SecurityScore    int    `json:"security_score"`
	PerformanceScore int    `json:"performance_score"`
	OverallScore     int    `json:"overall_score"`
	Grade            string `json:"grade"` // A-F

	// Summary
	TotalIssues     int      `json:"total_issues"`
	CriticalIssues  int      `json:"critical_issues"`
	HighIssues      int      `json:"high_issues"`
	MediumIssues    int      `json:"medium_issues"`
	LowIssues       int      `json:"low_issues"`
	Recommendations []string `json:"recommendations"`
}

// QueryInfo represents information about the analyzed query
type QueryInfo struct {
	Size           int      `json:"size"`              // Query size in characters
	Lines          int      `json:"lines"`             // Number of lines
	StatementCount int      `json:"statement_count"`   // Number of SQL statements
	StatementTypes []string `json:"statement_types"`   // Types of statements
	Features       []string `json:"features"`          // SQL features used (CTEs, Window Functions, etc.)
	Dialect        string   `json:"dialect,omitempty"` // SQL dialect if detected
}

// IssueBuilder provides a fluent interface for creating analysis issues
type IssueBuilder struct {
	issue AnalysisIssue
}

// NewIssue creates a new issue builder
func NewIssue(id string, category IssueCategory, severity IssueSeverity) *IssueBuilder {
	return &IssueBuilder{
		issue: AnalysisIssue{
			ID:       id,
			Category: category,
			Severity: severity,
		},
	}
}

// WithTitle sets the issue title
func (b *IssueBuilder) WithTitle(title string) *IssueBuilder {
	b.issue.Title = title
	return b
}

// WithDescription sets the issue description
func (b *IssueBuilder) WithDescription(description string) *IssueBuilder {
	b.issue.Description = description
	return b
}

// WithMessage sets a context-specific message
func (b *IssueBuilder) WithMessage(message string) *IssueBuilder {
	b.issue.Message = message
	return b
}

// WithPosition sets the source position
func (b *IssueBuilder) WithPosition(line, column int) *IssueBuilder {
	b.issue.Position = &SourcePosition{
		Line:   line,
		Column: column,
	}
	return b
}

// WithPositionFromToken sets position from a token
func (b *IssueBuilder) WithPositionFromToken(token *models.TokenWithSpan) *IssueBuilder {
	if token != nil {
		b.issue.Position = &SourcePosition{
			Line:   token.Start.Line,
			Column: token.Start.Column,
			// Note: models.Location doesn't have Offset field yet
		}
	}
	return b
}

// WithContext sets the source code context
func (b *IssueBuilder) WithContext(context string) *IssueBuilder {
	b.issue.Context = context
	return b
}

// WithImpact sets the impact description
func (b *IssueBuilder) WithImpact(impact string) *IssueBuilder {
	b.issue.Impact = impact
	return b
}

// WithSuggestion sets the fix suggestion
func (b *IssueBuilder) WithSuggestion(suggestion string) *IssueBuilder {
	b.issue.Suggestion = suggestion
	return b
}

// WithReference adds a documentation reference
func (b *IssueBuilder) WithReference(ref string) *IssueBuilder {
	b.issue.References = append(b.issue.References, ref)
	return b
}

// WithTag adds a metadata tag
func (b *IssueBuilder) WithTag(tag string) *IssueBuilder {
	b.issue.Tags = append(b.issue.Tags, tag)
	return b
}

// Build creates the final AnalysisIssue
func (b *IssueBuilder) Build() AnalysisIssue {
	return b.issue
}

// Common issue templates for consistency
var (
	// Security issues
	SelectStarIssue = func() *IssueBuilder {
		return NewIssue("SELECT_STAR", IssueCategorySecurity, IssueSeverityMedium).
			WithTitle("SELECT * Usage").
			WithDescription("Using SELECT * can expose sensitive data and break when schema changes").
			WithImpact("Data exposure, maintenance issues").
			WithSuggestion("Specify explicit column names instead of SELECT *").
			WithReference("https://wiki.c2.com/?SelectStar")
	}

	UpdateWithoutWhereIssue = func() *IssueBuilder {
		return NewIssue("UPDATE_WITHOUT_WHERE", IssueCategorySecurity, IssueSeverityCritical).
			WithTitle("UPDATE Without WHERE Clause").
			WithDescription("UPDATE statement without WHERE clause will modify all rows in the table").
			WithImpact("Data corruption, unintended mass updates").
			WithSuggestion("Always include a WHERE clause in UPDATE statements").
			WithTag("data-safety")
	}

	DeleteWithoutWhereIssue = func() *IssueBuilder {
		return NewIssue("DELETE_WITHOUT_WHERE", IssueCategorySecurity, IssueSeverityCritical).
			WithTitle("DELETE Without WHERE Clause").
			WithDescription("DELETE statement without WHERE clause will remove all rows from the table").
			WithImpact("Data loss, catastrophic deletion").
			WithSuggestion("Always include a WHERE clause in DELETE statements").
			WithTag("data-safety")
	}

	// Performance issues
	MissingWhereIssue = func() *IssueBuilder {
		return NewIssue("MISSING_WHERE", IssueCategoryPerformance, IssueSeverityMedium).
			WithTitle("Missing WHERE Clause").
			WithDescription("SELECT without WHERE clause may scan the entire table").
			WithImpact("High I/O, slow query performance").
			WithSuggestion("Add WHERE clause to filter results and improve performance")
	}

	CartesianProductIssue = func() *IssueBuilder {
		return NewIssue("CARTESIAN_PRODUCT", IssueCategoryPerformance, IssueSeverityHigh).
			WithTitle("Potential Cartesian Product").
			WithDescription("Multiple tables without explicit JOIN conditions may create cartesian product").
			WithImpact("Exponential result set growth, severe performance degradation").
			WithSuggestion("Use explicit JOIN syntax with proper ON conditions")
	}

	FunctionInWhereIssue = func() *IssueBuilder {
		return NewIssue("FUNCTION_IN_WHERE", IssueCategoryPerformance, IssueSeverityMedium).
			WithTitle("Function Call in WHERE Clause").
			WithDescription("Function calls on indexed columns prevent index usage").
			WithImpact("Full table scans, reduced query performance").
			WithSuggestion("Avoid functions on indexed columns in WHERE clause")
	}
)

// Helper functions for score calculations
func CalculateScoreFromIssues(issues []AnalysisIssue, category IssueCategory) int {
	score := 100
	for _, issue := range issues {
		if issue.Category != category {
			continue
		}

		switch issue.Severity {
		case IssueSeverityCritical:
			score -= 30
		case IssueSeverityHigh:
			score -= 20
		case IssueSeverityMedium:
			score -= 10
		case IssueSeverityLow:
			score -= 5
		case IssueSeverityInfo:
			score -= 1
		}
	}

	if score < 0 {
		score = 0
	}
	return score
}

func CalculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func CountIssuesBySeverity(issues []AnalysisIssue) (critical, high, medium, low int) {
	for _, issue := range issues {
		switch issue.Severity {
		case IssueSeverityCritical:
			critical++
		case IssueSeverityHigh:
			high++
		case IssueSeverityMedium:
			medium++
		case IssueSeverityLow:
			low++
		}
	}
	return
}
