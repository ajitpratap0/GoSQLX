package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

var (
	analyzeSecurity    bool
	analyzePerformance bool
	analyzeComplexity  bool
	analyzeAll         bool
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze [file|query]",
	Short: "Advanced SQL analysis capabilities",
	Long: `Analyze SQL queries for security vulnerabilities, performance issues, and complexity metrics.

Examples:
  gosqlx analyze query.sql                        # Basic analysis
  gosqlx analyze --security query.sql             # Security vulnerability scan
  gosqlx analyze --performance query.sql          # Performance optimization hints
  gosqlx analyze --complexity query.sql           # Complexity scoring
  gosqlx analyze --all query.sql                  # Comprehensive analysis
  gosqlx analyze "SELECT * FROM users"            # Analyze query directly

Analysis capabilities:
• SQL injection pattern detection
• Performance optimization suggestions
• Query complexity scoring  
• Best practices validation
• Multi-dialect compatibility checks

Note: Advanced analysis features are implemented in Phase 4 of the roadmap.
This is a basic implementation for CLI foundation.`,
	Args: cobra.ExactArgs(1),
	RunE: analyzeRun,
}

func analyzeRun(cmd *cobra.Command, args []string) error {
	// Load configuration with CLI flag overrides
	cfg, err := config.LoadDefault()
	if err != nil {
		// If config load fails, use defaults
		cfg = config.DefaultConfig()
	}

	// Override analyze flags if they were explicitly set
	if cmd.Flags().Changed("security") {
		cfg.Analyze.Security = analyzeSecurity
	} else {
		analyzeSecurity = cfg.Analyze.Security
	}
	if cmd.Flags().Changed("performance") {
		cfg.Analyze.Performance = analyzePerformance
	} else {
		analyzePerformance = cfg.Analyze.Performance
	}
	if cmd.Flags().Changed("complexity") {
		cfg.Analyze.Complexity = analyzeComplexity
	} else {
		analyzeComplexity = cfg.Analyze.Complexity
	}
	if cmd.Flags().Changed("all") {
		cfg.Analyze.All = analyzeAll
	} else {
		analyzeAll = cfg.Analyze.All
	}

	// Override format from global flags if set
	if cmd.Parent().PersistentFlags().Changed("format") {
		cfg.Output.Format = format
	} else {
		format = cfg.Output.Format
	}

	// Use verbose from global flags if set
	if cmd.Parent().PersistentFlags().Changed("verbose") {
		cfg.Output.Verbose = verbose
	} else {
		verbose = cfg.Output.Verbose
	}

	input := args[0]

	// Use robust input detection with security checks
	inputResult, err := DetectAndReadInput(input)
	if err != nil {
		return fmt.Errorf("input processing failed: %w", err)
	}

	// Use pooled tokenizer
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize(inputResult.Content)
	if err != nil {
		return fmt.Errorf("tokenization failed: %w", err)
	}

	// Convert TokenWithSpan to Token using centralized converter
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		return fmt.Errorf("token conversion failed: %w", err)
	}

	// Parse with proper error handling for memory management
	p := parser.NewParser()
	astObj, err := p.Parse(convertedTokens)
	if err != nil {
		// Parser failed, no AST to release
		return fmt.Errorf("parsing failed: %w", err)
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
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display modern analysis report directly
	return displayAnalysis(report)
}

// Legacy types removed - now using unified AnalysisReport from analysis_types.go

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

func displayAnalysis(analysis *AnalysisReport) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(analysis)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer func() {
			if err := encoder.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close YAML encoder: %v\n", err)
			}
		}()
		return encoder.Encode(analysis)
	default:
		// Table format
		fmt.Printf("🔍 SQL Analysis Report\n")
		fmt.Printf("═══════════════════════\n\n")

		// Summary
		fmt.Printf("📊 Summary:\n")
		fmt.Printf("   Overall Score: %d/100 (Grade: %s)\n", analysis.OverallScore, analysis.Grade)
		fmt.Printf("   Issues: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
			analysis.TotalIssues, analysis.CriticalIssues, analysis.HighIssues, analysis.MediumIssues, analysis.LowIssues)
		fmt.Printf("   Query Size: %d characters, %d statements, %d lines\n",
			analysis.Query.Size, analysis.Query.StatementCount, analysis.Query.Lines)
		if len(analysis.Query.Features) > 0 {
			fmt.Printf("   Features: %s\n", strings.Join(analysis.Query.Features, ", "))
		}
		fmt.Printf("\n")

		// Security
		securityIssues := filterIssuesByCategory(analysis.Issues, IssueCategorySecurity)
		fmt.Printf("🔒 Security Analysis:\n")
		fmt.Printf("   Score: %d/100\n", analysis.SecurityScore)
		if len(securityIssues) > 0 {
			fmt.Printf("   Issues found:\n")
			for _, issue := range securityIssues {
				fmt.Printf("   • [%s] %s\n", strings.ToUpper(string(issue.Severity)), issue.Title)
				if issue.Description != "" {
					fmt.Printf("     %s\n", issue.Description)
				}
				if issue.Suggestion != "" {
					fmt.Printf("     → %s\n", issue.Suggestion)
				}
			}
		} else {
			fmt.Printf("   ✅ No security issues detected\n")
		}
		fmt.Printf("\n")

		// Performance
		performanceIssues := filterIssuesByCategory(analysis.Issues, IssueCategoryPerformance)
		fmt.Printf("⚡ Performance Analysis:\n")
		fmt.Printf("   Score: %d/100\n", analysis.PerformanceScore)
		if len(performanceIssues) > 0 {
			fmt.Printf("   Issues found:\n")
			for _, issue := range performanceIssues {
				fmt.Printf("   • [%s] %s\n", strings.ToUpper(string(issue.Severity)), issue.Title)
				if issue.Description != "" {
					fmt.Printf("     %s\n", issue.Description)
				}
				if issue.Impact != "" {
					fmt.Printf("     Impact: %s\n", issue.Impact)
				}
				if issue.Suggestion != "" {
					fmt.Printf("     → %s\n", issue.Suggestion)
				}
			}
		} else {
			fmt.Printf("   ✅ No performance issues detected\n")
		}
		fmt.Printf("\n")

		// Complexity
		fmt.Printf("📈 Complexity Metrics:\n")
		fmt.Printf("   Overall: %s (Score: %.1f)\n", analysis.ComplexityMetrics.OverallComplexity, analysis.ComplexityMetrics.ComplexityScore)
		fmt.Printf("   JOINs: %d, Nesting: %d, Functions: %d\n",
			analysis.ComplexityMetrics.JoinComplexity, analysis.ComplexityMetrics.NestingDepth, analysis.ComplexityMetrics.FunctionCount)
		fmt.Printf("\n")

		// Recommendations
		if len(analysis.Recommendations) > 0 {
			fmt.Printf("💡 Recommendations:\n")
			for _, rec := range analysis.Recommendations {
				fmt.Printf("   • %s\n", rec)
			}
			fmt.Printf("\n")
		}

		fmt.Printf("Generated at: %s\n", analysis.Timestamp.Format("2006-01-02 15:04:05"))

		return nil
	}
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().BoolVar(&analyzeSecurity, "security", false, "focus on security vulnerability analysis (config: analyze.security)")
	analyzeCmd.Flags().BoolVar(&analyzePerformance, "performance", false, "focus on performance optimization analysis (config: analyze.performance)")
	analyzeCmd.Flags().BoolVar(&analyzeComplexity, "complexity", false, "focus on complexity metrics (config: analyze.complexity)")
	analyzeCmd.Flags().BoolVar(&analyzeAll, "all", false, "comprehensive analysis (config: analyze.all)")
}
