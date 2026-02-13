package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// CLIAnalyzerOptions contains configuration for the SQL analyzer CLI
type CLIAnalyzerOptions struct {
	Security    bool
	Performance bool
	Complexity  bool
	All         bool
	Format      string // Output format: json, yaml, table
	Verbose     bool
}

// Analyzer provides SQL analysis functionality with injectable output
type Analyzer struct {
	Out  io.Writer
	Err  io.Writer
	Opts CLIAnalyzerOptions
}

// AnalyzerResult contains the result of analysis
type AnalyzerResult struct {
	Report *AnalysisReport
	Error  error
}

// NewAnalyzer creates a new Analyzer with the given options
func NewAnalyzer(out, err io.Writer, opts CLIAnalyzerOptions) *Analyzer {
	return &Analyzer{
		Out:  out,
		Err:  err,
		Opts: opts,
	}
}

// Analyze analyzes the given SQL input (file or direct SQL)
func (a *Analyzer) Analyze(input string) (*AnalyzerResult, error) {
	result := &AnalyzerResult{}

	// Use robust input detection with security checks
	inputResult, err := DetectAndReadInput(input)
	if err != nil {
		result.Error = fmt.Errorf("input processing failed: %w", err)
		return result, result.Error
	}

	// Use pooled tokenizer
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize(inputResult.Content)
	if err != nil {
		result.Error = fmt.Errorf("tokenization failed: %w", err)
		return result, result.Error
	}

	// Convert TokenWithSpan to Token using centralized converter
	//lint:ignore SA1019 intentional use during #215 migration
	convertedTokens, err := parser.ConvertTokensForParser(tokens) //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
	if err != nil {
		result.Error = fmt.Errorf("token conversion failed: %w", err)
		return result, result.Error
	}

	// Parse with proper error handling for memory management
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		// Parser failed, no AST to release
		result.Error = fmt.Errorf("parsing failed: %w", err)
		return result, result.Error
	}

	// CRITICAL: Always release AST, even on analysis errors
	defer func() {
		ast.ReleaseAST(astObj)
	}()

	// Use AST-based analyzer for deep analysis
	analyzer := NewSQLAnalyzer()
	report, err := analyzer.Analyze(astObj)
	if err != nil {
		// AST will be released by defer above
		result.Error = fmt.Errorf("analysis failed: %w", err)
		return result, result.Error
	}

	result.Report = report
	return result, nil
}

// DisplayReport displays the analysis report in the configured format
func (a *Analyzer) DisplayReport(report *AnalysisReport) error {
	switch strings.ToLower(a.Opts.Format) {
	case "json":
		encoder := json.NewEncoder(a.Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "yaml":
		encoder := yaml.NewEncoder(a.Out)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(a.Err, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(report)
	default:
		// Table format
		return a.displayTableFormat(report)
	}
}

// displayTableFormat displays the analysis report in table format
func (a *Analyzer) displayTableFormat(analysis *AnalysisReport) error {
	fmt.Fprintf(a.Out, "🔍 SQL Analysis Report\n")
	fmt.Fprintf(a.Out, "═══════════════════════\n\n")

	// Summary
	fmt.Fprintf(a.Out, "📊 Summary:\n")
	fmt.Fprintf(a.Out, "   Overall Score: %d/100 (Grade: %s)\n", analysis.OverallScore, analysis.Grade)
	fmt.Fprintf(a.Out, "   Issues: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		analysis.TotalIssues, analysis.CriticalIssues, analysis.HighIssues, analysis.MediumIssues, analysis.LowIssues)
	fmt.Fprintf(a.Out, "   Query Size: %d characters, %d statements, %d lines\n",
		analysis.Query.Size, analysis.Query.StatementCount, analysis.Query.Lines)
	if len(analysis.Query.Features) > 0 {
		fmt.Fprintf(a.Out, "   Features: %s\n", strings.Join(analysis.Query.Features, ", "))
	}
	fmt.Fprintf(a.Out, "\n")

	// Security
	securityIssues := filterIssuesByCategory(analysis.Issues, IssueCategorySecurity)
	fmt.Fprintf(a.Out, "🔒 Security Analysis:\n")
	fmt.Fprintf(a.Out, "   Score: %d/100\n", analysis.SecurityScore)
	if len(securityIssues) > 0 {
		fmt.Fprintf(a.Out, "   Issues found:\n")
		for _, issue := range securityIssues {
			fmt.Fprintf(a.Out, "   • [%s] %s\n", strings.ToUpper(string(issue.Severity)), issue.Title)
			if issue.Description != "" {
				fmt.Fprintf(a.Out, "     %s\n", issue.Description)
			}
			if issue.Suggestion != "" {
				fmt.Fprintf(a.Out, "     → %s\n", issue.Suggestion)
			}
		}
	} else {
		fmt.Fprintf(a.Out, "   ✅ No security issues detected\n")
	}
	fmt.Fprintf(a.Out, "\n")

	// Performance
	performanceIssues := filterIssuesByCategory(analysis.Issues, IssueCategoryPerformance)
	fmt.Fprintf(a.Out, "⚡ Performance Analysis:\n")
	fmt.Fprintf(a.Out, "   Score: %d/100\n", analysis.PerformanceScore)
	if len(performanceIssues) > 0 {
		fmt.Fprintf(a.Out, "   Issues found:\n")
		for _, issue := range performanceIssues {
			fmt.Fprintf(a.Out, "   • [%s] %s\n", strings.ToUpper(string(issue.Severity)), issue.Title)
			if issue.Description != "" {
				fmt.Fprintf(a.Out, "     %s\n", issue.Description)
			}
			if issue.Impact != "" {
				fmt.Fprintf(a.Out, "     Impact: %s\n", issue.Impact)
			}
			if issue.Suggestion != "" {
				fmt.Fprintf(a.Out, "     → %s\n", issue.Suggestion)
			}
		}
	} else {
		fmt.Fprintf(a.Out, "   ✅ No performance issues detected\n")
	}
	fmt.Fprintf(a.Out, "\n")

	// Complexity
	fmt.Fprintf(a.Out, "📈 Complexity Metrics:\n")
	fmt.Fprintf(a.Out, "   Overall: %s (Score: %.1f)\n", analysis.ComplexityMetrics.OverallComplexity, analysis.ComplexityMetrics.ComplexityScore)
	fmt.Fprintf(a.Out, "   JOINs: %d, Nesting: %d, Functions: %d\n",
		analysis.ComplexityMetrics.JoinComplexity, analysis.ComplexityMetrics.NestingDepth, analysis.ComplexityMetrics.FunctionCount)
	fmt.Fprintf(a.Out, "\n")

	// Recommendations
	if len(analysis.Recommendations) > 0 {
		fmt.Fprintf(a.Out, "💡 Recommendations:\n")
		for _, rec := range analysis.Recommendations {
			fmt.Fprintf(a.Out, "   • %s\n", rec)
		}
		fmt.Fprintf(a.Out, "\n")
	}

	fmt.Fprintf(a.Out, "Generated at: %s\n", analysis.Timestamp.Format("2006-01-02 15:04:05"))

	return nil
}

// filterIssuesByCategory filters issues by category for display
func filterIssuesByCategory(issues []AnalysisIssue, category IssueCategory) []AnalysisIssue {
	var filtered []AnalysisIssue
	for _, issue := range issues {
		if issue.Category == category {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// AnalyzerFlags represents CLI flags for analyzer command
type AnalyzerFlags struct {
	Security    bool
	Performance bool
	Complexity  bool
	All         bool
	Format      string
	Verbose     bool
}

// AnalyzerOptionsFromConfig creates CLIAnalyzerOptions from config and CLI flags
func AnalyzerOptionsFromConfig(cfg *config.Config, flagsChanged map[string]bool, flags AnalyzerFlags) CLIAnalyzerOptions {
	opts := CLIAnalyzerOptions{
		Security:    cfg.Analyze.Security,
		Performance: cfg.Analyze.Performance,
		Complexity:  cfg.Analyze.Complexity,
		All:         cfg.Analyze.All,
		Format:      cfg.Output.Format,
		Verbose:     cfg.Output.Verbose,
	}

	// Override with CLI flags if explicitly set
	if flagsChanged["security"] {
		opts.Security = flags.Security
	}
	if flagsChanged["performance"] {
		opts.Performance = flags.Performance
	}
	if flagsChanged["complexity"] {
		opts.Complexity = flags.Complexity
	}
	if flagsChanged["all"] {
		opts.All = flags.All
	}
	if flagsChanged["format"] {
		opts.Format = flags.Format
	}
	if flagsChanged["verbose"] {
		opts.Verbose = flags.Verbose
	}

	return opts
}
