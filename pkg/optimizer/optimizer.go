// Package optimizer provides SQL query optimization suggestions by analyzing parsed ASTs.
//
// The optimizer walks the Abstract Syntax Tree produced by the GoSQLX parser and
// applies configurable rules to detect common performance anti-patterns. Each rule
// produces zero or more Suggestions with severity levels, human-readable messages,
// and (where possible) suggested SQL rewrites.
//
// Quick Start:
//
//	opt := optimizer.New()
//	result, err := opt.AnalyzeSQL("SELECT * FROM users")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, s := range result.Suggestions {
//	    fmt.Printf("[%s] %s: %s\n", s.Severity, s.RuleID, s.Message)
//	}
//
// For fine-grained control, parse the SQL first and call Analyze directly:
//
//	astNode, _ := gosqlx.Parse(sql)
//	result := opt.Analyze(astNode)
package optimizer

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Severity levels for optimization suggestions.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Complexity levels for query classification.
const (
	ComplexitySimple   = "simple"
	ComplexityModerate = "moderate"
	ComplexityComplex  = "complex"
)

// Suggestion represents a single optimization recommendation produced by a Rule.
type Suggestion struct {
	RuleID       string // Unique rule identifier (e.g., "OPT-001")
	Severity     string // One of SeverityInfo, SeverityWarning, SeverityError
	Message      string // Short description of the issue
	Detail       string // Detailed explanation and rationale
	Line         int    // Source line (1-based, 0 if unknown)
	Column       int    // Source column (1-based, 0 if unknown)
	OriginalSQL  string // The problematic SQL fragment (if available)
	SuggestedSQL string // Suggested rewrite (if available)
}

// OptimizationResult contains the full output of an optimization analysis.
type OptimizationResult struct {
	Suggestions     []Suggestion // All suggestions from all rules
	QueryComplexity string       // One of ComplexitySimple, ComplexityModerate, ComplexityComplex
	Score           int          // 0-100 where 100 is optimal (no suggestions)
}

// Rule defines the interface that all optimization rules must implement.
//
// Each rule inspects a single AST statement and returns zero or more Suggestions.
// Rules should be stateless and safe for concurrent use.
type Rule interface {
	// ID returns the unique rule identifier (e.g., "OPT-001").
	ID() string

	// Name returns a short human-readable rule name.
	Name() string

	// Description returns a detailed description of what the rule checks.
	Description() string

	// Analyze inspects a single statement and returns suggestions.
	Analyze(stmt ast.Statement) []Suggestion
}

// Optimizer analyzes parsed SQL ASTs and produces optimization suggestions.
//
// An Optimizer is configured with a set of Rules. The default set includes
// all built-in rules (OPT-001 through OPT-008). The Optimizer is safe for
// concurrent use after creation.
type Optimizer struct {
	rules []Rule
}

// New creates a new Optimizer with all built-in optimization rules enabled.
func New() *Optimizer {
	return &Optimizer{
		rules: DefaultRules(),
	}
}

// NewWithRules creates a new Optimizer with the specified rules.
func NewWithRules(rules ...Rule) *Optimizer {
	return &Optimizer{
		rules: rules,
	}
}

// Rules returns the list of rules configured for this optimizer.
func (o *Optimizer) Rules() []Rule {
	return o.rules
}

// Analyze inspects all statements in the given AST and returns an OptimizationResult.
//
// Each configured rule is applied to every statement in the AST. The result
// includes all suggestions, a complexity classification, and an optimization score.
func (o *Optimizer) Analyze(tree *ast.AST) *OptimizationResult {
	if tree == nil {
		return &OptimizationResult{
			Suggestions:     []Suggestion{},
			QueryComplexity: ComplexitySimple,
			Score:           100,
		}
	}

	var suggestions []Suggestion

	for _, stmt := range tree.Statements {
		for _, rule := range o.rules {
			ruleSuggestions := rule.Analyze(stmt)
			suggestions = append(suggestions, ruleSuggestions...)
		}
	}

	complexity := classifyComplexity(tree)
	score := calculateScore(suggestions)

	return &OptimizationResult{
		Suggestions:     suggestions,
		QueryComplexity: complexity,
		Score:           score,
	}
}

// AnalyzeSQL is a convenience method that parses the SQL string and analyzes it.
//
// This method uses gosqlx.Parse internally for tokenization and parsing.
// If parsing fails, the error is returned and no analysis is performed.
func (o *Optimizer) AnalyzeSQL(sql string) (*OptimizationResult, error) {
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}

	return o.Analyze(tree), nil
}

// classifyComplexity determines query complexity based on AST characteristics.
func classifyComplexity(tree *ast.AST) string {
	if tree == nil || len(tree.Statements) == 0 {
		return ComplexitySimple
	}

	complexityScore := 0

	for _, stmt := range tree.Statements {
		complexityScore += statementComplexity(stmt)
	}

	switch {
	case complexityScore >= 5:
		return ComplexityComplex
	case complexityScore >= 2:
		return ComplexityModerate
	default:
		return ComplexitySimple
	}
}

// statementComplexity scores the complexity of a single statement.
func statementComplexity(stmt ast.Statement) int {
	score := 0

	switch s := stmt.(type) {
	case *ast.SelectStatement:
		// Base complexity
		score++

		// JOINs add complexity
		score += len(s.Joins)

		// Subqueries in FROM
		for _, from := range s.From {
			if from.Subquery != nil {
				score += 2
			}
		}

		// GROUP BY
		if len(s.GroupBy) > 0 {
			score++
		}

		// HAVING
		if s.Having != nil {
			score++
		}

		// Window functions
		if len(s.Windows) > 0 {
			score++
		}

		// CTE (WITH clause)
		if s.With != nil {
			score += len(s.With.CTEs)
		}

		// Subqueries in WHERE
		if s.Where != nil {
			score += countSubqueries(s.Where)
		}

	case *ast.SetOperation:
		score += statementComplexity(s.Left) + statementComplexity(s.Right) + 1

	default:
		score++
	}

	return score
}

// countSubqueries recursively counts subquery expressions in an expression tree.
func countSubqueries(expr ast.Expression) int {
	if expr == nil {
		return 0
	}

	count := 0

	switch e := expr.(type) {
	case *ast.SubqueryExpression:
		count++
	case *ast.InExpression:
		if e.Subquery != nil {
			count++
		}
	case *ast.ExistsExpression:
		count++
	case *ast.BinaryExpression:
		count += countSubqueries(e.Left)
		count += countSubqueries(e.Right)
	}

	return count
}

// calculateScore computes the optimization score (0-100).
// Each suggestion reduces the score based on its severity.
func calculateScore(suggestions []Suggestion) int {
	score := 100

	for _, s := range suggestions {
		switch s.Severity {
		case SeverityError:
			score -= 20
		case SeverityWarning:
			score -= 10
		case SeverityInfo:
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

// FormatResult produces a human-readable text report from an OptimizationResult.
func FormatResult(result *OptimizationResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Optimization Score: %d/100\n", result.Score))
	sb.WriteString(fmt.Sprintf("Query Complexity: %s\n", result.QueryComplexity))
	sb.WriteString(fmt.Sprintf("Suggestions: %d\n", len(result.Suggestions)))

	if len(result.Suggestions) == 0 {
		sb.WriteString("\nNo optimization suggestions - query looks good!\n")
		return sb.String()
	}

	sb.WriteString(strings.Repeat("=", 80) + "\n")

	for i, s := range result.Suggestions {
		sb.WriteString(fmt.Sprintf("\n[%s] %s (%s)\n", strings.ToUpper(s.Severity), s.RuleID, severityIcon(s.Severity)))
		sb.WriteString(fmt.Sprintf("  %s\n", s.Message))
		if s.Detail != "" {
			sb.WriteString(fmt.Sprintf("  Detail: %s\n", s.Detail))
		}
		if s.Line > 0 {
			sb.WriteString(fmt.Sprintf("  Location: line %d, column %d\n", s.Line, s.Column))
		}
		if s.SuggestedSQL != "" {
			sb.WriteString(fmt.Sprintf("  Suggested: %s\n", s.SuggestedSQL))
		}

		if i < len(result.Suggestions)-1 {
			sb.WriteString(strings.Repeat("-", 40) + "\n")
		}
	}

	return sb.String()
}

func severityIcon(severity string) string {
	switch severity {
	case SeverityError:
		return "critical"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return severity
	}
}
