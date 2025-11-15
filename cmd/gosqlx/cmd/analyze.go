package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
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

	// Track which flags were explicitly set
	flagsChanged := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		flagsChanged[f.Name] = true
	})
	if cmd.Parent() != nil && cmd.Parent().PersistentFlags() != nil {
		cmd.Parent().PersistentFlags().Visit(func(f *pflag.Flag) {
			flagsChanged[f.Name] = true
		})
	}

	// Create analyzer options from config and flags
	opts := AnalyzerOptionsFromConfig(cfg, flagsChanged, AnalyzerFlags{
		Security:    analyzeSecurity,
		Performance: analyzePerformance,
		Complexity:  analyzeComplexity,
		All:         analyzeAll,
		Format:      format,
		Verbose:     verbose,
	})

	// Create analyzer with injectable output writers
	analyzer := NewAnalyzer(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)

	// Run analysis
	result, err := analyzer.Analyze(args[0])
	if err != nil {
		return err
	}

	// Display the report
	return analyzer.DisplayReport(result.Report)
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().BoolVar(&analyzeSecurity, "security", false, "focus on security vulnerability analysis (config: analyze.security)")
	analyzeCmd.Flags().BoolVar(&analyzePerformance, "performance", false, "focus on performance optimization analysis (config: analyze.performance)")
	analyzeCmd.Flags().BoolVar(&analyzeComplexity, "complexity", false, "focus on complexity metrics (config: analyze.complexity)")
	analyzeCmd.Flags().BoolVar(&analyzeAll, "all", false, "comprehensive analysis (config: analyze.all)")
}
