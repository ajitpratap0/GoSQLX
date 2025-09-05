package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SQLAnalyzer provides deep AST-based analysis of SQL queries
type SQLAnalyzer struct {
	// Unified analysis results
	Issues            []AnalysisIssue
	ComplexityMetrics ComplexityMetrics

	// Score tracking
	SecurityScore    int
	PerformanceScore int

	// AST traversal state
	currentDepth      int
	maxDepth          int
	joinCount         int
	subqueryCount     int
	functionCount     int
	hasCartesian      bool
	hasSelectStar     bool
	hasLiteralInWhere bool
}

// NewSQLAnalyzer creates a new AST-based SQL analyzer
func NewSQLAnalyzer() *SQLAnalyzer {
	return &SQLAnalyzer{
		Issues:           make([]AnalysisIssue, 0),
		SecurityScore:    100,
		PerformanceScore: 100,
	}
}

// Analyze performs comprehensive AST-based analysis
func (a *SQLAnalyzer) Analyze(astObj *ast.AST) (*AnalysisReport, error) {
	// Reset analyzer state
	a.reset()

	// Traverse AST using visitor pattern
	for _, stmt := range astObj.Statements {
		if err := ast.Walk(a, stmt); err != nil {
			return nil, fmt.Errorf("AST traversal failed: %w", err)
		}
	}

	// Calculate final metrics and scores
	a.calculateComplexityMetrics()
	a.calculateScores()

	// Generate recommendations
	recommendations := a.generateRecommendations()

	// Count issues by severity
	critical, high, medium, low := CountIssuesBySeverity(a.Issues)

	// Calculate final scores
	securityScore := a.calculateSecurityScore()
	overallScore := a.calculateOverallScore()

	return &AnalysisReport{
		Timestamp:         time.Now(),
		Version:           "2.0.0-unified",
		Issues:            a.Issues,
		ComplexityMetrics: a.ComplexityMetrics,
		SecurityScore:     securityScore,
		PerformanceScore:  a.PerformanceScore,
		OverallScore:      overallScore,
		Grade:             CalculateGrade(overallScore),
		TotalIssues:       len(a.Issues),
		CriticalIssues:    critical,
		HighIssues:        high,
		MediumIssues:      medium,
		LowIssues:         low,
		Recommendations:   recommendations,
	}, nil
}

// Visit implements ast.Visitor interface for AST traversal
func (a *SQLAnalyzer) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		// End of traversal for this branch
		a.currentDepth--
		return nil, nil
	}

	// Track nesting depth
	a.currentDepth++
	if a.currentDepth > a.maxDepth {
		a.maxDepth = a.currentDepth
	}

	// Analyze specific node types
	switch n := node.(type) {
	case *ast.SelectStatement:
		a.analyzeSelectStatement(n)
	case *ast.InsertStatement:
		a.analyzeInsertStatement(n)
	case *ast.UpdateStatement:
		a.analyzeUpdateStatement(n)
	case *ast.DeleteStatement:
		a.analyzeDeleteStatement(n)
	case *ast.JoinClause:
		a.analyzeJoinClause(n)
	case *ast.BinaryExpression:
		a.analyzeBinaryExpression(n)
	case *ast.FunctionCall:
		a.analyzeFunctionCall(n)
	case *ast.Identifier:
		a.analyzeIdentifier(n)
	case *ast.LiteralValue:
		a.analyzeLiteralValue(n)
	}

	// Continue traversal
	return a, nil
}

// analyzeSelectStatement analyzes SELECT statements for issues
func (a *SQLAnalyzer) analyzeSelectStatement(stmt *ast.SelectStatement) {
	// Check for SELECT *
	for _, col := range stmt.Columns {
		if id, ok := col.(*ast.Identifier); ok && id.Name == "*" {
			a.hasSelectStar = true
			a.addPerformanceIssue("SELECT_STAR", "MEDIUM",
				"SELECT * can be inefficient and may break if table schema changes",
				"performance", "Specify explicit column names instead of SELECT *")
		}
	}

	// Analyze FROM clause
	if len(stmt.From) > 1 {
		// Multiple tables in FROM without explicit JOIN
		a.hasCartesian = true
		a.addPerformanceIssue("CARTESIAN_PRODUCT", "HIGH",
			"Multiple tables in FROM clause may cause cartesian product",
			"performance", "Use explicit JOIN syntax instead of comma-separated tables")
	}

	// Check for missing WHERE clause on large table operations
	if stmt.Where == nil && len(stmt.From) > 0 {
		a.addPerformanceIssue("MISSING_WHERE", "MEDIUM",
			"SELECT without WHERE clause may scan entire table",
			"performance", "Add WHERE clause to limit result set")
	}

	// Analyze subqueries
	if len(stmt.From) > 0 {
		a.subqueryCount++
	}
}

// analyzeInsertStatement analyzes INSERT statements
func (a *SQLAnalyzer) analyzeInsertStatement(stmt *ast.InsertStatement) {
	// Check for INSERT without explicit columns
	if len(stmt.Columns) == 0 && len(stmt.Values) > 0 {
		a.addSecurityIssue("INSERT_WITHOUT_COLUMNS", "MEDIUM",
			"INSERT without explicit columns is brittle and error-prone",
			"Always specify column names in INSERT statements")
	}

	// Check for bulk operations without transaction
	if len(stmt.Values) > 100 {
		a.addPerformanceIssue("BULK_INSERT", "LOW",
			"Large INSERT operations should use batch processing",
			"performance", "Consider using batch INSERT or COPY operations")
	}
}

// analyzeUpdateStatement analyzes UPDATE statements
func (a *SQLAnalyzer) analyzeUpdateStatement(stmt *ast.UpdateStatement) {
	// Check for UPDATE without WHERE clause
	if stmt.Where == nil {
		a.addSecurityIssue("UPDATE_WITHOUT_WHERE", "CRITICAL",
			"UPDATE without WHERE clause will modify all rows in table",
			"Always include WHERE clause in UPDATE statements")
	}
}

// analyzeDeleteStatement analyzes DELETE statements
func (a *SQLAnalyzer) analyzeDeleteStatement(stmt *ast.DeleteStatement) {
	// Check for DELETE without WHERE clause
	if stmt.Where == nil {
		a.addSecurityIssue("DELETE_WITHOUT_WHERE", "CRITICAL",
			"DELETE without WHERE clause will remove all rows from table",
			"Always include WHERE clause in DELETE statements")
	}
}

// analyzeJoinClause analyzes JOIN operations
func (a *SQLAnalyzer) analyzeJoinClause(join *ast.JoinClause) {
	a.joinCount++

	// Check for JOIN without ON condition
	if join.Condition == nil {
		a.hasCartesian = true
		a.addPerformanceIssue("JOIN_WITHOUT_CONDITION", "HIGH",
			"JOIN without ON condition creates cartesian product",
			"performance", "Add explicit ON condition to JOIN clause")
	}

	// Analyze JOIN complexity
	if a.joinCount > 5 {
		a.addPerformanceIssue("COMPLEX_JOIN", "MEDIUM",
			fmt.Sprintf("Query has %d JOINs, which may impact performance", a.joinCount),
			"performance", "Consider denormalizing data or using materialized views")
	}
}

// analyzeBinaryExpression analyzes binary expressions (comparisons, etc.)
func (a *SQLAnalyzer) analyzeBinaryExpression(expr *ast.BinaryExpression) {
	// Check for literal values in WHERE clause (potential SQL injection)
	if lit, ok := expr.Right.(*ast.LiteralValue); ok {
		if lit.Type == "STRING" {
			a.hasLiteralInWhere = true
			a.addSecurityIssue("LITERAL_IN_WHERE", "MEDIUM",
				"Literal values in WHERE clause may indicate SQL injection vulnerability",
				"Use parameterized queries instead of string literals")
		}
	}

	// Check for function calls on left side of comparison
	if _, ok := expr.Left.(*ast.FunctionCall); ok {
		a.addPerformanceIssue("FUNCTION_IN_WHERE", "MEDIUM",
			"Function calls in WHERE clause prevent index usage",
			"performance", "Avoid functions on indexed columns in WHERE clause")
	}
}

// analyzeFunctionCall analyzes function calls
func (a *SQLAnalyzer) analyzeFunctionCall(fn *ast.FunctionCall) {
	a.functionCount++

	// Check for potentially expensive functions
	expensiveFunctions := map[string]bool{
		"SUBSTRING": true, "UPPER": true, "LOWER": true,
		"CONCAT": true, "REGEXP": true, "MD5": true,
	}

	if expensiveFunctions[strings.ToUpper(fn.Name)] {
		a.addPerformanceIssue("EXPENSIVE_FUNCTION", "LOW",
			fmt.Sprintf("Function %s may be expensive in large result sets", fn.Name),
			"performance", "Consider precalculating values or using indexes")
	}

	// Analyze window functions
	if fn.Over != nil {
		a.addPerformanceIssue("WINDOW_FUNCTION", "LOW",
			"Window functions can be resource intensive",
			"performance", "Ensure proper indexing for window function performance")
	}
}

// analyzeIdentifier analyzes identifiers
func (a *SQLAnalyzer) analyzeIdentifier(id *ast.Identifier) {
	// Check for unqualified column names in multi-table queries
	if id.Table == "" && a.joinCount > 0 {
		a.addPerformanceIssue("UNQUALIFIED_COLUMN", "LOW",
			"Unqualified column names in multi-table queries can be ambiguous",
			"performance", "Use table aliases to qualify column names")
	}
}

// analyzeLiteralValue analyzes literal values
func (a *SQLAnalyzer) analyzeLiteralValue(lit *ast.LiteralValue) {
	// Check for very large literals that might indicate hardcoded data
	if lit.Type == "STRING" {
		if str, ok := lit.Value.(string); ok && len(str) > 1000 {
			a.addPerformanceIssue("LARGE_LITERAL", "LOW",
				"Very large string literals may indicate hardcoded data",
				"performance", "Consider storing large data separately and referencing by ID")
		}
	}
}

// Helper methods for adding issues using the unified system
func (a *SQLAnalyzer) addSecurityIssue(issueType, severity, description, suggestion string) {
	var sev IssueSeverity
	switch strings.ToLower(severity) {
	case "critical":
		sev = IssueSeverityCritical
	case "high":
		sev = IssueSeverityHigh
	case "medium":
		sev = IssueSeverityMedium
	case "low":
		sev = IssueSeverityLow
	default:
		sev = IssueSeverityMedium
	}

	issue := NewIssue(issueType, IssueCategorySecurity, sev).
		WithDescription(description).
		WithSuggestion(suggestion).
		Build()

	a.Issues = append(a.Issues, issue)
	a.adjustSecurityScore(sev)
}

func (a *SQLAnalyzer) addPerformanceIssue(issueType, severity, description, impact, suggestion string) {
	var sev IssueSeverity
	switch strings.ToLower(severity) {
	case "critical":
		sev = IssueSeverityCritical
	case "high":
		sev = IssueSeverityHigh
	case "medium":
		sev = IssueSeverityMedium
	case "low":
		sev = IssueSeverityLow
	default:
		sev = IssueSeverityMedium
	}

	issue := NewIssue(issueType, IssueCategoryPerformance, sev).
		WithDescription(description).
		WithImpact(impact).
		WithSuggestion(suggestion).
		Build()

	a.Issues = append(a.Issues, issue)
	a.adjustPerformanceScore(sev)
}

func (a *SQLAnalyzer) adjustSecurityScore(severity IssueSeverity) {
	switch severity {
	case IssueSeverityCritical:
		a.SecurityScore -= 30
	case IssueSeverityHigh:
		a.SecurityScore -= 20
	case IssueSeverityMedium:
		a.SecurityScore -= 10
	case IssueSeverityLow:
		a.SecurityScore -= 5
	}
	if a.SecurityScore < 0 {
		a.SecurityScore = 0
	}
}

func (a *SQLAnalyzer) adjustPerformanceScore(severity IssueSeverity) {
	switch severity {
	case IssueSeverityCritical:
		a.PerformanceScore -= 25
	case IssueSeverityHigh:
		a.PerformanceScore -= 15
	case IssueSeverityMedium:
		a.PerformanceScore -= 10
	case IssueSeverityLow:
		a.PerformanceScore -= 5
	}

	if a.PerformanceScore < 0 {
		a.PerformanceScore = 0
	}
}

// calculateComplexityMetrics calculates complexity metrics
func (a *SQLAnalyzer) calculateComplexityMetrics() {
	// Cyclomatic complexity based on conditions and branches
	cyclomaticComplexity := 1 + len(a.Issues)

	// Overall complexity calculation
	complexityScore := float64(a.maxDepth)*2.0 +
		float64(a.joinCount)*1.5 +
		float64(a.subqueryCount)*3.0 +
		float64(a.functionCount)*0.5

	var complexityLevel string
	switch {
	case complexityScore < 5:
		complexityLevel = "LOW"
	case complexityScore < 15:
		complexityLevel = "MEDIUM"
	case complexityScore < 30:
		complexityLevel = "HIGH"
	default:
		complexityLevel = "VERY_HIGH"
	}

	a.ComplexityMetrics = ComplexityMetrics{
		CyclomaticComplexity: cyclomaticComplexity,
		NestingDepth:         a.maxDepth,
		JoinComplexity:       a.joinCount,
		SubqueryDepth:        a.subqueryCount,
		FunctionCount:        a.functionCount,
		OverallComplexity:    complexityLevel,
		ComplexityScore:      complexityScore,
	}
}

// calculateScores calculates final analysis scores
func (a *SQLAnalyzer) calculateScores() {
	// Performance score is already calculated during issue detection
}

// calculateSecurityScore calculates security score based on issues
func (a *SQLAnalyzer) calculateSecurityScore() int {
	return CalculateScoreFromIssues(a.Issues, IssueCategorySecurity)
}

// calculateOverallScore calculates overall analysis score
func (a *SQLAnalyzer) calculateOverallScore() int {
	securityScore := a.calculateSecurityScore()
	performanceScore := a.PerformanceScore

	// Weight: 40% security, 40% performance, 20% complexity
	complexityPenalty := int(a.ComplexityMetrics.ComplexityScore * 2)
	complexityScore := 100 - complexityPenalty
	if complexityScore < 0 {
		complexityScore = 0
	}

	return (securityScore*40 + performanceScore*40 + complexityScore*20) / 100
}

// generateRecommendations generates actionable recommendations
func (a *SQLAnalyzer) generateRecommendations() []string {
	var recommendations []string

	// Get security issues
	securityIssues := 0
	performanceIssues := 0
	for _, issue := range a.Issues {
		switch issue.Category {
		case IssueCategorySecurity:
			securityIssues++
		case IssueCategoryPerformance:
			performanceIssues++
		}
	}

	// Security recommendations
	if securityIssues > 0 {
		recommendations = append(recommendations, "Review and fix security vulnerabilities before production deployment")
	}

	// Performance recommendations
	if a.PerformanceScore < 70 {
		recommendations = append(recommendations, "Consider query optimization techniques to improve performance")
	}

	if a.hasSelectStar {
		recommendations = append(recommendations, "Replace SELECT * with explicit column lists")
	}

	if a.hasCartesian {
		recommendations = append(recommendations, "Review JOIN conditions to avoid cartesian products")
	}

	if a.joinCount > 3 {
		recommendations = append(recommendations, "Consider denormalization or materialized views for complex JOINs")
	}

	// Complexity recommendations
	if a.ComplexityMetrics.OverallComplexity == "HIGH" || a.ComplexityMetrics.OverallComplexity == "VERY_HIGH" {
		recommendations = append(recommendations, "Break down complex queries into simpler components")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Query follows good SQL practices")
	}

	return recommendations
}

// reset resets analyzer state for new analysis
func (a *SQLAnalyzer) reset() {
	a.Issues = a.Issues[:0]
	a.SecurityScore = 100
	a.PerformanceScore = 100
	a.currentDepth = 0
	a.maxDepth = 0
	a.joinCount = 0
	a.subqueryCount = 0
	a.functionCount = 0
	a.hasCartesian = false
	a.hasSelectStar = false
	a.hasLiteralInWhere = false
}
